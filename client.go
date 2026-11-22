// Package vault is the Onshore client: token refresh, batching, retries, and
// detokenize that fails closed.
package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Error is an API error. It never holds a sensitive value.
type Error struct {
	Status                int
	Code, Message, Policy string
	// RequestID identifies the call in the audit log. Quote it to support.
	RequestID string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Client calls the data API.
type Client struct {
	BaseURL, ServiceAccountID, KeyID string
	PrivateKey                       ed25519.PrivateKey
	HTTP                             *http.Client
	MaxAttempts                      int

	mu     sync.Mutex
	token  string
	expiry time.Time
}

// New builds a client from the base64 seed printed by `rv sa-keygen`.
func New(baseURL, serviceAccountID, keyID, seedB64 string) (*Client, error) {
	seed, err := base64.StdEncoding.DecodeString(seedB64)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("the private key must be a base64 Ed25519 seed")
	}
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), ServiceAccountID: serviceAccountID, KeyID: keyID, PrivateKey: ed25519.NewKeyFromSeed(seed), HTTP: &http.Client{Timeout: 10 * time.Second}, MaxAttempts: 4}, nil
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (c *Client) assertion() (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	head, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": c.KeyID})
	body, _ := json.Marshal(map[string]any{"iss": c.ServiceAccountID, "sub": c.ServiceAccountID, "aud": "onshore", "jti": hex.EncodeToString(jti), "iat": time.Now().Unix(), "exp": time.Now().Add(2 * time.Minute).Unix()})
	s := b64u(head) + "." + b64u(body)
	return s + "." + b64u(ed25519.Sign(c.PrivateKey, []byte(s))), nil
}

func (c *Client) bearer(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.expiry.Add(-time.Minute)) {
		return c.token, nil
	}
	a, err := c.assertion()
	if err != nil {
		return "", err
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := c.do(ctx, "POST", "/v1/auth/token", "", nil, map[string]string{"assertion": a}, &out); err != nil {
		return "", err
	}
	c.token, c.expiry = out.AccessToken, time.Now().Add(time.Duration(out.ExpiresIn)*time.Second)
	return c.token, nil
}

func (c *Client) do(ctx context.Context, method, path, token string, headers map[string]string, body, out any) error {
	var b []byte
	if body != nil {
		var err error
		if b, err = json.Marshal(body); err != nil {
			return err
		}
	}
	var last error
	attempts := c.MaxAttempts
	if attempts < 1 {
		attempts = 1
	}
	for i := 0; i < attempts; i++ {
		if i > 0 {
			n, _ := rand.Int(rand.Reader, big.NewInt(100))
			wait := time.Duration(100<<i)*time.Millisecond/2 + time.Duration(n.Int64())*time.Millisecond
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		var reader io.Reader
		if b != nil {
			reader = bytes.NewReader(b)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader)
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			last = &Error{Code: "network_error", Message: "the vault cannot be reached"}
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if resp.StatusCode < 300 {
			if out == nil || len(data) == 0 {
				return nil
			}
			return json.Unmarshal(data, out)
		}
		var e struct {
			Error struct {
				Code, Message, Policy string
			} `json:"error"`
			RequestID string `json:"request_id"`
		}
		json.Unmarshal(data, &e)
		apiErr := &Error{resp.StatusCode, e.Error.Code, e.Error.Message, e.Error.Policy, e.RequestID}
		if resp.StatusCode == 401 && token != "" {
			c.mu.Lock()
			if c.token == token {
				c.token = ""
			}
			c.mu.Unlock()
			return apiErr
		}
		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			last = apiErr
			continue
		}
		return apiErr
	}
	return last
}

func (c *Client) call(ctx context.Context, path string, body, out any) error {
	return c.send(ctx, "POST", path, nil, body, out)
}

func (c *Client) send(ctx context.Context, method, path string, headers map[string]string, body, out any) error {
	t, err := c.bearer(ctx)
	if err != nil {
		return err
	}
	return c.do(ctx, method, path, t, headers, body, out)
}

// Item is one value to store.
type Item struct {
	Field      string `json:"field"`
	Value      string `json:"value"`
	SubjectRef string `json:"subject_ref,omitempty"`
}

// ItemError says why one item in a batch failed, with ContinueOnError.
type ItemError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Policy  string `json:"policy,omitempty"`
}

// TokenResult reports one stored value.
type TokenResult struct {
	Index    int        `json:"index"`
	Token    string     `json:"token"`
	Existing bool       `json:"existing"`
	Error    *ItemError `json:"error,omitempty"`
}

// TokenizeOptions changes how a batch behaves.
type TokenizeOptions struct {
	// ContinueOnError stores the good items and gives each bad one an Error,
	// instead of failing the whole batch.
	ContinueOnError bool
	// DryRun checks formats and access rules and stores nothing.
	DryRun bool
}

// Tokenize stores values, splitting into batches of 500. The first bad item fails its batch.
func (c *Client) Tokenize(ctx context.Context, vault string, items []Item) ([]TokenResult, error) {
	return c.TokenizeWith(ctx, vault, items, TokenizeOptions{})
}

// TokenizeWith is Tokenize with options.
func (c *Client) TokenizeWith(ctx context.Context, vault string, items []Item, opts TokenizeOptions) ([]TokenResult, error) {
	var out []TokenResult
	for i := 0; i < len(items); i += 500 {
		end := i + 500
		if end > len(items) {
			end = len(items)
		}
		var r struct {
			Results []TokenResult `json:"results"`
		}
		if err := c.call(ctx, "/v1/vaults/"+vault+"/tokenize", map[string]any{"items": items[i:end], "continue_on_error": opts.ContinueOnError, "dry_run": opts.DryRun}, &r); err != nil {
			return nil, err
		}
		for _, x := range r.Results {
			x.Index += i
			out = append(out, x)
		}
	}
	return out, nil
}

// Reveal reports one value, as far as policy allows.
type Reveal struct {
	Index    int        `json:"index"`
	Decision string     `json:"decision"`
	Value    string     `json:"value"`
	Policy   string     `json:"policy"`
	Error    *ItemError `json:"error,omitempty"`
}

// RevealItem is one token to reveal. Redaction ("masked" or "token_only") asks for
// less than the access rules allow; it can only narrow.
type RevealItem struct {
	Token     string `json:"token"`
	Redaction string `json:"redaction,omitempty"`
}

// Detokenize fails closed: when the vault cannot answer it returns an error, and it
// never returns a token as if it were the value.
func (c *Client) Detokenize(ctx context.Context, vault string, tokens []string, purpose string) ([]Reveal, error) {
	items := make([]RevealItem, len(tokens))
	for i, t := range tokens {
		items[i] = RevealItem{Token: t}
	}
	return c.DetokenizeWith(ctx, vault, items, purpose, false)
}

// DetokenizeWith reveals with per-item redaction. With continueOnError, a bad token
// gets an Error and the rest are answered.
func (c *Client) DetokenizeWith(ctx context.Context, vault string, tokens []RevealItem, purpose string, continueOnError bool) ([]Reveal, error) {
	var out []Reveal
	for i := 0; i < len(tokens); i += 500 {
		end := i + 500
		if end > len(tokens) {
			end = len(tokens)
		}
		var r struct {
			Results []Reveal `json:"results"`
		}
		if err := c.call(ctx, "/v1/vaults/"+vault+"/detokenize", map[string]any{"items": tokens[i:end], "purpose": purpose, "continue_on_error": continueOnError}, &r); err != nil {
			return nil, err
		}
		for _, x := range r.Results {
			x.Index += i
			out = append(out, x)
		}
	}
	return out, nil
}

// Lookup finds a token without revealing a value.
func (c *Client) Lookup(ctx context.Context, vault, field, value string) (string, error) {
	var r struct {
		Token string `json:"token"`
	}
	err := c.call(ctx, "/v1/vaults/"+vault+"/lookup", map[string]string{"field": field, "value": value}, &r)
	return r.Token, err
}

// ResidentCheck runs a check in the country and returns only true or false.
func (c *Client) ResidentCheck(ctx context.Context, vault, token, check, arg, purpose string) (bool, error) {
	var r struct {
		Result bool `json:"result"`
	}
	err := c.call(ctx, "/v1/vaults/"+vault+"/resident/check", map[string]string{"token": token, "check": check, "arg": arg, "purpose": purpose}, &r)
	return r.Result, err
}

func seg(s string) string { return url.PathEscape(s) }

// Record is a stored record and a token per field.
type Record struct {
	ID     string            `json:"id"`
	Tokens map[string]string `json:"tokens"`
}

// InsertRecord stores several fields for one person. All are stored or none.
func (c *Client) InsertRecord(ctx context.Context, vault string, fields map[string]string, subjectRef string) (Record, error) {
	var r Record
	err := c.call(ctx, "/v1/vaults/"+vault+"/records", map[string]any{"fields": fields, "subject_ref": subjectRef}, &r)
	return r, err
}

// GetRecord reads every field of a record, each as the access rules allow.
func (c *Client) GetRecord(ctx context.Context, vault, id, purpose string) (map[string]Reveal, error) {
	var r struct {
		Fields map[string]Reveal `json:"fields"`
	}
	err := c.send(ctx, "GET", "/v1/vaults/"+vault+"/records/"+seg(id), map[string]string{"X-RV-Purpose": purpose}, nil, &r)
	return r.Fields, err
}

// UpdateValue changes the value behind a new-token-each-time (cell) token.
func (c *Client) UpdateValue(ctx context.Context, vault, token, value string) error {
	return c.send(ctx, "PUT", "/v1/vaults/"+vault+"/tokens/"+seg(token), nil, map[string]string{"value": value}, nil)
}

// SubjectQuery filters SearchSubjects. Zero values are left out.
type SubjectQuery struct {
	Query         string `json:"query,omitempty"`
	FieldType     string `json:"field_type,omitempty"`
	HasReveals    bool   `json:"has_reveals,omitempty"`
	Flagged       bool   `json:"flagged,omitempty"`
	CreatedAfter  string `json:"created_after,omitempty"`
	CreatedBefore string `json:"created_before,omitempty"`
	Sort          string `json:"sort,omitempty"` // created_at, field_count, last_accessed
	Dir           string `json:"dir,omitempty"`  // asc, desc
	Limit         int    `json:"limit,omitempty"`
	Offset        int    `json:"offset,omitempty"`
}

// Subject is one person in a vault.
type Subject struct {
	ID           string     `json:"id"`
	Ref          string     `json:"ref"`
	FieldCount   int        `json:"field_count"`
	CreatedAt    time.Time  `json:"created_at"`
	LastAccessed *time.Time `json:"last_accessed"`
	Reveals30d   int        `json:"reveals_30d"`
	Restricted   bool       `json:"restricted"`
}

// SubjectField is one field held on a person, masked at most.
type SubjectField struct {
	Field    string `json:"field"`
	DataType string `json:"data_type"`
	Token    string `json:"token"`
	Masked   string `json:"masked,omitempty"`
	Decision string `json:"decision"`
	RecordID string `json:"record_id"`
}

// SubjectDetail is a person and their fields.
type SubjectDetail struct {
	Subject
	Fields []SubjectField `json:"fields"`
}

// ExportedField is one row of an access request export.
type ExportedField struct {
	Field    string `json:"field"`
	DataType string `json:"data_type"`
	Value    string `json:"value"`
	Token    string `json:"token"`
	Decision string `json:"decision"`
}

// SearchSubjects lists the people in a vault and the total matching.
func (c *Client) SearchSubjects(ctx context.Context, vault string, q SubjectQuery) ([]Subject, int, error) {
	var r struct {
		Subjects []Subject `json:"subjects"`
		Total    int       `json:"total"`
	}
	err := c.call(ctx, "/v1/vaults/"+vault+"/subjects/search", q, &r)
	return r.Subjects, r.Total, err
}

// GetSubject returns one person and their fields, masked at most.
func (c *Client) GetSubject(ctx context.Context, vault, subjectID string) (SubjectDetail, error) {
	var r SubjectDetail
	err := c.send(ctx, "GET", "/v1/vaults/"+vault+"/subjects/"+seg(subjectID), nil, nil, &r)
	return r, err
}

// ExportSubject exports a person's fields for an access request.
func (c *Client) ExportSubject(ctx context.Context, vault, subjectID, purpose string) ([]ExportedField, error) {
	var r struct {
		Fields []ExportedField `json:"fields"`
	}
	err := c.send(ctx, "GET", "/v1/vaults/"+vault+"/subjects/"+seg(subjectID)+"/export", map[string]string{"X-RV-Purpose": purpose}, nil, &r)
	return r.Fields, err
}

// RestrictSubject stops (or allows again) every reveal about a person.
func (c *Client) RestrictSubject(ctx context.Context, vault, subjectID string, restricted bool, purpose string) (bool, error) {
	var r struct {
		Restricted bool `json:"restricted"`
	}
	err := c.call(ctx, "/v1/vaults/"+vault+"/subjects/"+seg(subjectID)+"/restrict", map[string]any{"restricted": restricted, "purpose": purpose}, &r)
	return r.Restricted, err
}

// EraseSubject erases everything held on a person and returns how many records went.
func (c *Client) EraseSubject(ctx context.Context, vault, subjectID, purpose string) (int, error) {
	var r struct {
		Erased int `json:"erased_records"`
	}
	err := c.send(ctx, "DELETE", "/v1/vaults/"+vault+"/subjects/"+seg(subjectID), map[string]string{"X-RV-Purpose": purpose}, nil, &r)
	return r.Erased, err
}

// DetectOptions changes what Detect looks for.
type DetectOptions struct {
	Vault         string   `json:"vault,omitempty"`
	Tokenize      bool     `json:"tokenize"`
	Entities      []string `json:"entities,omitempty"`
	IncludeShadow bool     `json:"include_shadow,omitempty"`
}

// Entity is one identifier found. Start and End are byte offsets.
type Entity struct {
	Type          string  `json:"type"`
	Start         int     `json:"start"`
	End           int     `json:"end"`
	Score         float64 `json:"score"`
	Custom        bool    `json:"custom"`
	EntityVersion int     `json:"entity_version,omitempty"`
	Shadow        bool    `json:"shadow,omitempty"`
}

// Detection is what Detect found, and the text with tokens when tokenizing.
type Detection struct {
	Entities       []Entity `json:"entities"`
	Text           string   `json:"text,omitempty"`
	RulesetVersion int      `json:"ruleset_version"`
}

// Detect finds identifiers in text.
func (c *Client) Detect(ctx context.Context, text string, opts DetectOptions) (Detection, error) {
	var r Detection
	body := struct {
		Text string `json:"text"`
		DetectOptions
	}{text, opts}
	err := c.call(ctx, "/v1/detect", body, &r)
	return r, err
}

// FlowReport is what a flow check found in a sample.
type FlowReport struct {
	Identifiers int            `json:"identifiers"`
	Tokens      int            `json:"tokens"`
	Clean       bool           `json:"clean"`
	ByType      map[string]int `json:"by_type"`
}

// CheckFlow reports what a batch holds before a job sends it on. Only counts are kept.
func (c *Client) CheckFlow(ctx context.Context, vault, flow, text string) (FlowReport, error) {
	var r FlowReport
	err := c.call(ctx, "/v1/vaults/"+vault+"/flows/"+seg(flow)+"/check", map[string]string{"text": text}, &r)
	return r, err
}

// ClientTokenRequest mints a token for a secure component.
type ClientTokenRequest struct {
	Kind       string   `json:"kind"`   // collect or reveal
	Origin     string   `json:"origin"` // https://… or rvapp://<app id>
	Fields     []string `json:"fields,omitempty"`
	Tokens     []string `json:"tokens,omitempty"`
	Purpose    string   `json:"purpose,omitempty"`
	OnBehalfOf string   `json:"on_behalf_of,omitempty"`
	SubjectRef string   `json:"subject_ref,omitempty"`
	BindIP     string   `json:"bind_ip,omitempty"`
	TTLSeconds int      `json:"ttl_seconds,omitempty"`
}

// ClientToken is a single-use token for a browser or app.
type ClientToken struct {
	ClientToken string    `json:"client_token"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// CreateClientToken mints a single-use token for a collect or reveal component. Server only.
func (c *Client) CreateClientToken(ctx context.Context, vault string, req ClientTokenRequest) (ClientToken, error) {
	var r ClientToken
	err := c.call(ctx, "/v1/vaults/"+vault+"/client-tokens", req, &r)
	return r, err
}

// CloakRequest sets how text is cloaked. Send ProfileID or Options, not both.
type CloakRequest struct {
	ProfileID string            `json:"profile_id,omitempty"`
	Options   map[string]string `json:"options,omitempty"`
	KeepDays  int               `json:"keep_days,omitempty"`
}

// Cloaked is cloaked text, counts by type, and the digital twin's ID with KeepDays.
type Cloaked struct {
	Text    string         `json:"text"`
	Changed map[string]int `json:"changed"`
	ID      string         `json:"id,omitempty"`
}

// Cloak replaces identifiers in text before it goes to an AI model or outside service.
func (c *Client) Cloak(ctx context.Context, vault, text string, req CloakRequest) (Cloaked, error) {
	var r Cloaked
	body := struct {
		Text string `json:"text"`
		CloakRequest
	}{text, req}
	err := c.call(ctx, "/v1/vaults/"+vault+"/cloak", body, &r)
	return r, err
}

// Uncloaked is restored text and the decision per data type.
type Uncloaked struct {
	Text      string            `json:"text"`
	Decisions map[string]string `json:"decisions"`
}

// Uncloak restores placeholders in text as far as the access rules allow.
func (c *Client) Uncloak(ctx context.Context, vault, twinID, text, purpose string) (Uncloaked, error) {
	var r Uncloaked
	err := c.call(ctx, "/v1/vaults/"+vault+"/uncloak", map[string]string{"id": twinID, "text": text, "purpose": purpose}, &r)
	return r, err
}

// DeleteTwin deletes a digital twin before it expires.
func (c *Client) DeleteTwin(ctx context.Context, vault, twinID string) error {
	return c.send(ctx, "DELETE", "/v1/vaults/"+vault+"/twins/"+seg(twinID), nil, nil, nil)
}
