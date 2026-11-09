package payloads

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ethicalhackingplayground/bxss/v2/pkg/arguments"
)

func TestGeneratePayloadForContext_Query(t *testing.T) {
	// legal: query context passes the raw payload through untouched
	raw := `<script>alert(1)</script>"'\` + "\n"
	got, err := GeneratePayloadForContext(raw, arguments.ContextQuery, "")
	if err != nil {
		t.Fatalf("expected query context to accept raw payload, got error: %v", err)
	}
	if got != raw {
		t.Errorf("expected query context to pass payload through unchanged, got %q want %q", got, raw)
	}

	// illegal: header-name supplied while context is query is a dependency conflict
	_, err = GeneratePayloadForContext(raw, arguments.ContextQuery, "X-Foo")
	if err == nil {
		t.Fatal("expected error when header-name is supplied with context=query, got nil")
	}
	if !strings.Contains(err.Error(), "header-name dependency") {
		t.Errorf("error should be locatable to the header-name dependency step, got: %v", err)
	}
}

func TestGeneratePayloadForContext_JSON(t *testing.T) {
	// legal: json context escapes quotes/backslashes/newlines so the result
	// is safe to splice into a JSON string value
	raw := "<script>alert(\"xss\")</script>\\\n"
	got, err := GeneratePayloadForContext(raw, arguments.ContextJSON, "")
	if err != nil {
		t.Fatalf("expected json context to escape payload successfully, got error: %v", err)
	}
	wrapped := `"` + got + `"`
	var decoded string
	if err := json.Unmarshal([]byte(wrapped), &decoded); err != nil {
		t.Fatalf("escaped payload %q is not valid JSON when wrapped in quotes: %v", got, err)
	}
	if decoded != raw {
		t.Errorf("round-tripping escaped payload through JSON gave %q, want original %q", decoded, raw)
	}

	// illegal: header-name supplied while context is json is a dependency conflict
	_, err = GeneratePayloadForContext(raw, arguments.ContextJSON, "X-Foo")
	if err == nil {
		t.Fatal("expected error when header-name is supplied with context=json, got nil")
	}
	if !strings.Contains(err.Error(), "header-name dependency") {
		t.Errorf("error should be locatable to the header-name dependency step, got: %v", err)
	}
}

func TestGeneratePayloadForContext_Header(t *testing.T) {
	// legal: header context accepts a payload with no CR/LF, given a valid header name
	raw := `<script>alert(1)</script>`
	got, err := GeneratePayloadForContext(raw, arguments.ContextHeader, "X-Forwarded-For")
	if err != nil {
		t.Fatalf("expected header context to accept CRLF-free payload, got error: %v", err)
	}
	if got != raw {
		t.Errorf("expected header context to pass CRLF-free payload through unchanged, got %q want %q", got, raw)
	}

	// illegal: payload containing CRLF must be rejected outright, not escaped
	crlfPayload := "X-Injected: evil\r\nSet-Cookie: pwned=1"
	_, err = GeneratePayloadForContext(crlfPayload, arguments.ContextHeader, "X-Forwarded-For")
	if err == nil {
		t.Fatal("expected error for a header-context payload containing CR/LF, got nil")
	}
	if !strings.Contains(err.Error(), "placeholder substitution") || !strings.Contains(err.Error(), "CR or LF") {
		t.Errorf("error should be locatable to placeholder substitution and mention CR/LF, got: %v", err)
	}
}

func TestGeneratePayloadForContext_InvalidContext(t *testing.T) {
	_, err := GeneratePayloadForContext("payload", "xml", "")
	if err == nil {
		t.Fatal("expected error for an unrecognized context, got nil")
	}
	if !strings.Contains(err.Error(), "context validation") {
		t.Errorf("error should be locatable to the context validation step, got: %v", err)
	}
}

func TestGeneratePayloadForContext_HeaderNameDependency(t *testing.T) {
	// header context missing header-name entirely
	_, err := GeneratePayloadForContext("payload", arguments.ContextHeader, "")
	if err == nil {
		t.Fatal("expected error when context=header is used without a header-name, got nil")
	}
	if !strings.Contains(err.Error(), "header-name dependency") {
		t.Errorf("error should be locatable to the header-name dependency step, got: %v", err)
	}

	// header context with a syntactically invalid header-name
	_, err = GeneratePayloadForContext("payload", arguments.ContextHeader, "X-Foo: bar")
	if err == nil {
		t.Fatal("expected error for an invalid header-name, got nil")
	}
	if !strings.Contains(err.Error(), "header-name dependency") {
		t.Errorf("error should be locatable to the header-name dependency step, got: %v", err)
	}
}

// TestGeneratePayloadForContext_OverlongAfterEscaping covers the boundary
// where a payload is well within maxRenderedPayloadLen in its raw form, but
// JSON escaping (every `"` becomes `\"`, doubling those bytes) pushes the
// rendered result over the limit. This must fail loudly instead of sending a
// truncated, half-escaped payload.
func TestGeneratePayloadForContext_OverlongAfterEscaping(t *testing.T) {
	raw := strings.Repeat(`"`, maxRenderedPayloadLen) // doubles to 2x under JSON escaping
	if len(raw) > maxRenderedPayloadLen {
		t.Fatalf("test setup error: raw payload itself already exceeds the limit")
	}

	_, err := GeneratePayloadForContext(raw, arguments.ContextJSON, "")
	if err == nil {
		t.Fatal("expected error for a payload that exceeds the max length once JSON-escaped, got nil")
	}
	if !strings.Contains(err.Error(), "placeholder substitution") || !strings.Contains(err.Error(), "exceeds max") {
		t.Errorf("error should be locatable to placeholder substitution and mention the length limit, got: %v", err)
	}

	// Sanity check: the same raw payload is fine under query context, where
	// escaping doesn't expand length.
	if _, err := GeneratePayloadForContext(raw, arguments.ContextQuery, ""); err != nil {
		t.Errorf("expected the same raw payload to be accepted under query context (no expansion), got: %v", err)
	}
}
