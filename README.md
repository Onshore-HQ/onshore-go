# Onshore SDK for Go

The Onshore server SDK for Go, using only the standard library. Context-aware, safe for concurrent use, and reveals fail closed.

## Install

```sh
go get github.com/Onshore-HQ/onshore-go@v0.1.0
```

```go
import vault "github.com/Onshore-HQ/onshore-go"

client, err := vault.New(os.Getenv("ONSHORE_URL"), os.Getenv("ONSHORE_SA_ID"), os.Getenv("ONSHORE_KEY_ID"), os.Getenv("ONSHORE_PRIVATE_KEY"))
```

## Documentation

Full reference, with every method, parameter, return value and error: https://docs.onshorevault.com/developers/sdks/go/

## Licence

Apache-2.0. Copyright 2026 Flowsplus Services. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Contributions need the [Contributor Licence Agreement](CLA.md).
