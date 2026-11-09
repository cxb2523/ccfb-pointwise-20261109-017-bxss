package arguments

import (
	"strings"
	"testing"
)

func TestValidateContextArgs_Query(t *testing.T) {
	// legal: default context, no header-name
	a := &Arguments{Context: ContextQuery}
	if err := a.ValidateContextArgs(); err != nil {
		t.Fatalf("expected query context with no header-name to be valid, got: %v", err)
	}

	// illegal: header-name supplied but context is query, must be a conflict
	a = &Arguments{Context: ContextQuery, HeaderName: "X-Forwarded-For"}
	err := a.ValidateContextArgs()
	if err == nil {
		t.Fatal("expected error when -header-name is set with -context=query, got nil")
	}
	if !strings.Contains(err.Error(), "header-name dependency") && !strings.Contains(err.Error(), "only valid when") {
		t.Errorf("error should be locatable to the header-name dependency step, got: %v", err)
	}
}

func TestValidateContextArgs_JSON(t *testing.T) {
	// legal: json context, no header-name
	a := &Arguments{Context: ContextJSON}
	if err := a.ValidateContextArgs(); err != nil {
		t.Fatalf("expected json context with no header-name to be valid, got: %v", err)
	}

	// illegal: header-name supplied but context is json
	a = &Arguments{Context: ContextJSON, HeaderName: "X-Foo"}
	err := a.ValidateContextArgs()
	if err == nil {
		t.Fatal("expected error when -header-name is set with -context=json, got nil")
	}
	if !strings.Contains(err.Error(), "only valid when") {
		t.Errorf("error should explain the header-name/context conflict, got: %v", err)
	}
}

func TestValidateContextArgs_Header(t *testing.T) {
	// legal: header context with a valid header name
	a := &Arguments{Context: ContextHeader, HeaderName: "X-Forwarded-For"}
	if err := a.ValidateContextArgs(); err != nil {
		t.Fatalf("expected header context with valid header-name to be valid, got: %v", err)
	}

	// illegal: header context missing header-name entirely
	a = &Arguments{Context: ContextHeader}
	err := a.ValidateContextArgs()
	if err == nil {
		t.Fatal("expected error when -context=header is set without -header-name, got nil")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Errorf("error should state header-name is required, got: %v", err)
	}

	// illegal: header context with a syntactically invalid header name
	a = &Arguments{Context: ContextHeader, HeaderName: "X-Foo: bar\r\nEvil: 1"}
	err = a.ValidateContextArgs()
	if err == nil {
		t.Fatal("expected error for a header-name containing illegal characters, got nil")
	}
	if !strings.Contains(err.Error(), "header field name validation") {
		t.Errorf("error should be locatable to header field name validation, got: %v", err)
	}
}

func TestValidateContextArgs_InvalidContext(t *testing.T) {
	a := &Arguments{Context: "xml"}
	err := a.ValidateContextArgs()
	if err == nil {
		t.Fatal("expected error for an unrecognized -context value, got nil")
	}
	if !strings.Contains(err.Error(), "invalid -context") {
		t.Errorf("error should be locatable to the context validity step, got: %v", err)
	}
}

func TestValidHeaderName(t *testing.T) {
	validNames := []string{"X-Forwarded-For", "Authorization", "X-Custom_Header.v2", "A"}
	for _, name := range validNames {
		if err := ValidHeaderName(name); err != nil {
			t.Errorf("expected %q to be a valid header name, got error: %v", name, err)
		}
	}

	invalidNames := []string{"", "X-Foo: bar", "X-Foo\r\nEvil: 1", "Has Space", "Has\tTab"}
	for _, name := range invalidNames {
		if err := ValidHeaderName(name); err == nil {
			t.Errorf("expected %q to be rejected as an invalid header name, got nil error", name)
		}
	}
}
