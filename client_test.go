package vault

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testClient(t *testing.T, h http.HandlerFunc) *Client {
	seed := make([]byte, 32)
	rand.Read(seed)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token" {
			fmt.Fprint(w, `{"access_token":"tok","expires_in":900}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("%s without bearer", r.URL.Path)
		}
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL+"/", "sa", "key", base64.StdEncoding.EncodeToString(seed))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func body(r *http.Request) map[string]any {
	var m map[string]any
	json.NewDecoder(r.Body).Decode(&m)
	return m
}

func TestBatchesAndOptions(t *testing.T) {
	var batches int32
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		b := body(r)
		if b["dry_run"] != true || b["continue_on_error"] != true {
			t.Errorf("options not sent: %v", b)
		}
		atomic.AddInt32(&batches, 1)
		n := len(b["items"].([]any))
		res := make([]string, n)
		for i := range res {
			res[i] = fmt.Sprintf(`{"index":%d,"token":"t%d"}`, i, i)
		}
		fmt.Fprintf(w, `{"results":[%s]}`, strings.Join(res, ","))
	})
	items := make([]Item, 1001)
	out, err := c.TokenizeWith(context.Background(), "v", items, TokenizeOptions{ContinueOnError: true, DryRun: true})
	if err != nil || len(out) != 1001 || out[1000].Index != 1000 || batches != 3 {
		t.Fatalf("got %d results, %d batches, %v", len(out), batches, err)
	}
}

func TestRedactionAndItemErrors(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		b := body(r)
		it := b["items"].([]any)[1].(map[string]any)
		if it["redaction"] != "masked" || b["continue_on_error"] != true {
			t.Errorf("bad body %v", b)
		}
		fmt.Fprint(w, `{"results":[{"index":0,"decision":"plaintext","value":"x"},{"index":1,"error":{"code":"token_not_found","message":"gone"}}]}`)
	})
	out, err := c.DetokenizeWith(context.Background(), "v", []RevealItem{{Token: "a"}, {Token: "b", Redaction: "masked"}}, "p", true)
	if err != nil || out[1].Error == nil || out[1].Error.Code != "token_not_found" {
		t.Fatalf("%v %+v", err, out)
	}
}

func TestGetWithPurposeHeaderAndNoBody(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.Header.Get("X-RV-Purpose") != "DSAR 4" || r.ContentLength > 0 {
			t.Errorf("method %s purpose %q len %d", r.Method, r.Header.Get("X-RV-Purpose"), r.ContentLength)
		}
		if r.URL.EscapedPath() != "/v1/vaults/v/subjects/a%2Fb/export" {
			t.Errorf("path %s", r.URL.EscapedPath())
		}
		fmt.Fprint(w, `{"subject_id":"a/b","fields":[{"field":"phone","value":"**12","decision":"masked"}]}`)
	})
	rows, err := c.ExportSubject(context.Background(), "v", "a/b", "DSAR 4")
	if err != nil || rows[0].Field != "phone" {
		t.Fatal(err, rows)
	}
}

func TestErrorsRetriesAndRequestID(t *testing.T) {
	var calls int32
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) < 3 {
			w.WriteHeader(503)
			fmt.Fprint(w, `{"error":{"code":"key_service_unavailable","message":"sealed"},"request_id":"r1"}`)
			return
		}
		w.WriteHeader(403)
		fmt.Fprint(w, `{"error":{"code":"policy_denied","message":"no","policy":"agents"},"request_id":"r2"}`)
	})
	_, err := c.Lookup(context.Background(), "v", "f", "x")
	e, ok := err.(*Error)
	if !ok || e.Status != 403 || e.Policy != "agents" || e.RequestID != "r2" || calls != 3 {
		t.Fatalf("%v after %d calls", err, calls)
	}
}

func TestUnauthorizedClearsToken(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		fmt.Fprint(w, `{"error":{"code":"unauthenticated","message":"revoked"}}`)
	})
	if _, err := c.ResidentCheck(context.Background(), "v", "t", "equals", "x", "p"); err == nil {
		t.Fatal("want error")
	}
	if c.token != "" {
		t.Fatal("token kept after 401")
	}
}

func TestEverythingElse(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "DELETE" && strings.Contains(r.URL.Path, "/subjects/"):
			fmt.Fprint(w, `{"erased_records":2}`)
		case r.Method == "DELETE":
			fmt.Fprint(w, `{}`)
		case r.Method == "PUT":
			if body(r)["value"] != "new" {
				t.Error("update body")
			}
			fmt.Fprint(w, `{"token":"t"}`)
		case strings.HasSuffix(r.URL.Path, "/records"):
			fmt.Fprint(w, `{"id":"rec","tokens":{"a":"t"}}`)
		case strings.HasSuffix(r.URL.Path, "/search"):
			fmt.Fprint(w, `{"subjects":[{"id":"s","created_at":"2026-11-01T00:00:00Z","last_accessed":null}],"total":1}`)
		case strings.HasSuffix(r.URL.Path, "/restrict"):
			fmt.Fprint(w, `{"restricted":true}`)
		case r.URL.Path == "/v1/detect":
			if b := body(r); b["text"] != "hi" || b["vault"] != "v" {
				t.Errorf("detect body %v", b)
			}
			fmt.Fprint(w, `{"entities":[{"type":"email","start":0,"end":2,"score":0.9}],"ruleset_version":3}`)
		case strings.HasSuffix(r.URL.Path, "/check"):
			fmt.Fprint(w, `{"identifiers":0,"tokens":2,"clean":true,"by_type":{}}`)
		case strings.HasSuffix(r.URL.Path, "/client-tokens"):
			fmt.Fprint(w, `{"client_token":"rvct","expires_at":"2026-11-22T10:00:00Z"}`)
		case strings.HasSuffix(r.URL.Path, "/cloak"):
			if b := body(r); b["text"] != "x" || b["keep_days"] != float64(1) {
				t.Errorf("cloak body %v", b)
			}
			fmt.Fprint(w, `{"text":"[NAME_1]","changed":{"person_name":1},"id":"tw"}`)
		case strings.HasSuffix(r.URL.Path, "/uncloak"):
			fmt.Fprint(w, `{"text":"Sam","decisions":{"person_name":"plaintext"}}`)
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/records/"):
			fmt.Fprint(w, `{"fields":{"a":{"decision":"masked","value":"**"}}}`)
		case r.Method == "GET":
			fmt.Fprint(w, `{"id":"s","fields":[{"field":"a","masked":"**"}]}`)
		}
	})
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	rec, err := c.InsertRecord(ctx, "v", map[string]string{"a": "1"}, "c")
	must(err)
	f, err := c.GetRecord(ctx, "v", rec.ID, "p")
	must(err)
	must(c.UpdateValue(ctx, "v", "t", "new"))
	subs, total, err := c.SearchSubjects(ctx, "v", SubjectQuery{Query: "c"})
	must(err)
	d, err := c.GetSubject(ctx, "v", "s")
	must(err)
	restricted, err := c.RestrictSubject(ctx, "v", "s", true, "p")
	must(err)
	n, err := c.EraseSubject(ctx, "v", "s", "p")
	must(err)
	det, err := c.Detect(ctx, "hi", DetectOptions{Vault: "v"})
	must(err)
	fr, err := c.CheckFlow(ctx, "v", "flow", "x")
	must(err)
	ct, err := c.CreateClientToken(ctx, "v", ClientTokenRequest{Kind: "collect", Origin: "https://a"})
	must(err)
	cl, err := c.Cloak(ctx, "v", "x", CloakRequest{KeepDays: 1})
	must(err)
	un, err := c.Uncloak(ctx, "v", cl.ID, "y", "p")
	must(err)
	must(c.DeleteTwin(ctx, "v", cl.ID))
	if f["a"].Value != "**" || total != 1 || subs[0].LastAccessed != nil || d.Fields[0].Masked != "**" || !restricted || n != 2 ||
		det.Entities[0].Type != "email" || !fr.Clean || ct.ClientToken != "rvct" || cl.ID != "tw" || un.Text != "Sam" {
		t.Fatal("unexpected results")
	}
}

func TestVerifyWebhook(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	raw := []byte(`{"type":"reveal.denied"}`)
	sign := func(secret string, at int64) string {
		m := hmac.New(sha256.New, []byte(secret))
		fmt.Fprintf(m, "%d.", at)
		m.Write(raw)
		return hex.EncodeToString(m.Sum(nil))
	}
	at := now.Unix()
	if !verifyAt("s", raw, fmt.Sprintf("t=%d,v1=%s", at, sign("s", at)), 0, now) {
		t.Fatal("good signature failed")
	}
	if !verifyAt("new", raw, fmt.Sprintf("t=%d,v1=%s,v1=%s", at, sign("old", at), sign("new", at)), 0, now) {
		t.Fatal("rotation failed")
	}
	if verifyAt("s", raw, fmt.Sprintf("t=%d,v1=%s", at-400, sign("s", at-400)), 0, now) {
		t.Fatal("stale accepted")
	}
	if verifyAt("s", []byte(`{}`), fmt.Sprintf("t=%d,v1=%s", at, sign("s", at)), 0, now) {
		t.Fatal("changed body accepted")
	}
}
