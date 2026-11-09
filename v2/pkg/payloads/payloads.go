package payloads

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ethicalhackingplayground/bxss/v2/pkg/arguments"
	"github.com/ethicalhackingplayground/bxss/v2/pkg/colours"
	"github.com/ethicalhackingplayground/bxss/v2/pkg/scan"
	"golang.org/x/time/rate"
)

// payloadPlaceholder marks the slot that the context-escaped payload value is
// substituted into. Every context strategy below (query/json/header) routes
// through substitutePlaceholder - the single shared core - and only supplies
// a different escapeFunc; none of them re-implement substitution, and none
// of them are picked via a flat if/else chain (see contextEscapers).
const payloadPlaceholder = "{{PAYLOAD}}"

// maxRenderedPayloadLen bounds the length of a payload *after* it has been
// escaped for its context and substituted into the placeholder. This matters
// because escaping can expand length a lot: JSON-escaping turns every quote
// or backslash into a 2-byte sequence and every control character into a
// 6-byte \u00XX sequence, so a payload that looks reasonably sized in its raw
// form can still blow past what should go into a single request. 8192 bytes
// (8KiB) is comfortably under common single header-line/body-field limits
// (e.g. nginx's default 8k header buffer), so it's used as a hard ceiling:
// if a rendered payload would exceed it, GeneratePayloadForContext returns an
// explicit error instead of silently truncating and sending a broken
// half-payload.
const maxRenderedPayloadLen = 8192

// escapeFunc escapes a raw payload value for one injection context. It is
// the only thing that differs between contexts; everything else (validation
// order, placeholder substitution, length enforcement) is shared.
type escapeFunc func(raw string) (string, error)

// contextEscapers dispatches on context via a lookup table rather than a
// chain of if/else branches, and keeps the three escaping rules (query's
// passthrough, json's standard-library escaping, header's CRLF rejection)
// as small, independent, mutually exclusive functions instead of three
// copies of a generation function.
var contextEscapers = map[string]escapeFunc{
	arguments.ContextQuery:  escapeQuery,
	arguments.ContextJSON:   escapeJSON,
	arguments.ContextHeader: escapeHeader,
}

// escapeQuery passes the payload through untouched: query-string values are
// URL-encoded further downstream (via url.Values.Encode), so no escaping is
// needed - or wanted - at generation time.
func escapeQuery(raw string) (string, error) {
	return raw, nil
}

// escapeJSON escapes raw using the standard library's JSON string encoding,
// so quotes, backslashes, and newlines come out as valid JSON escape
// sequences instead of breaking the surrounding JSON structure.
func escapeJSON(raw string) (string, error) {
	encoded, err := json.Marshal(raw)
	if err != nil {
		return "", fmt.Errorf("json.Marshal failed: %w", err)
	}
	// json.Marshal wraps the value in double quotes; strip them since the
	// caller owns the surrounding JSON syntax and only wants the escaped
	// contents.
	return string(encoded[1 : len(encoded)-1]), nil
}

// escapeHeader rejects any payload containing CR or LF outright, rather than
// trying to escape them: a header value can't carry a literal CRLF without
// either splitting the request into extra header lines or being dropped by
// the HTTP layer, so there is no safe escaped form to fall back to here.
func escapeHeader(raw string) (string, error) {
	if strings.ContainsAny(raw, "\r\n") {
		return "", fmt.Errorf("payload contains CR or LF, which would split the request header")
	}
	return raw, nil
}

// substitutePlaceholder is the shared core every context strategy routes
// through. It never branches on context - only on whether the template
// contains the placeholder - which is what keeps the three escaping rules
// mutually exclusive without duplicating the generation logic itself.
func substitutePlaceholder(template, escaped string) string {
	if !strings.Contains(template, payloadPlaceholder) {
		return escaped
	}
	return strings.ReplaceAll(template, payloadPlaceholder, escaped)
}

// GeneratePayloadForContext renders rawPayload for the given injection
// context, returning the exact string that should be sent in the request.
// Validation runs in a fixed order, and each failure is prefixed with the
// step that produced it so the cause can be located from the error text
// alone instead of a generic "invalid arguments":
//
//  1. context validity - ctx must be one of query/json/header
//  2. header-name dependency - headerName is required and must be a legal
//     HTTP header field name when ctx is "header", and must be empty for
//     every other context
//  3. placeholder substitution - the payload is escaped for ctx and
//     substituted into the placeholder, then checked against
//     maxRenderedPayloadLen
func GeneratePayloadForContext(rawPayload string, ctx string, headerName string) (string, error) {
	// Step 1: context validity.
	escaper, ok := contextEscapers[ctx]
	if !ok {
		return "", fmt.Errorf("context validation: invalid context %q: must be one of %q, %q, %q", ctx, arguments.ContextQuery, arguments.ContextJSON, arguments.ContextHeader)
	}

	// Step 2: header-name dependency.
	if ctx == arguments.ContextHeader {
		if headerName == "" {
			return "", fmt.Errorf("header-name dependency: --header-name is required when --context=%s", arguments.ContextHeader)
		}
		if err := arguments.ValidHeaderName(headerName); err != nil {
			return "", fmt.Errorf("header-name dependency: %w", err)
		}
	} else if headerName != "" {
		return "", fmt.Errorf("header-name dependency: --header-name is only valid when --context=%s, got --context=%s", arguments.ContextHeader, ctx)
	}

	// Step 3: placeholder substitution.
	escaped, err := escaper(rawPayload)
	if err != nil {
		return "", fmt.Errorf("placeholder substitution: %w", err)
	}
	rendered := substitutePlaceholder(payloadPlaceholder, escaped)
	if len(rendered) > maxRenderedPayloadLen {
		return "", fmt.Errorf("placeholder substitution: rendered payload is %d bytes after %s escaping, exceeds max %d bytes", len(rendered), ctx, maxRenderedPayloadLen)
	}

	return rendered, nil
}

type PayloadParser struct {
	args *arguments.Arguments
}

func NewPayload(args *arguments.Arguments) *PayloadParser {
	return &PayloadParser{
		args: args,
	}
}

// GeneratePayload renders rawPayload for this parser's configured -context
// and -header-name. See GeneratePayloadForContext for the validation order
// and escaping rules.
func (p *PayloadParser) GeneratePayload(rawPayload string) (string, error) {
	return GeneratePayloadForContext(rawPayload, p.args.Context, p.args.HeaderName)
}

// readLinesFromFile reads a file line by line and returns the lines as a slice of strings.
//
// The lines are trimmed of whitespace. If there is an error reading the file,
// that error is returned. Otherwise, the function returns a slice of strings
// and a nil error.
func (p *PayloadParser) ReadLinesFromFile() ([]string, error) {
	file, err := os.Open(p.args.PayloadFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, strings.TrimSpace(scanner.Text()))
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

// processPayloadsAndHeaders reads lines from standard input, and for each line,
// sends a request with each payload to each header to the specified link.
//
// The function takes in a slice of payloads, a slice of headers, and booleans
// indicating whether to append the payload to the parameter, whether to test
// parameters, and whether to follow redirects. It also takes a client object
// with a timeout and a redirect policy.
//
// If there is an error reading the input, that error is printed to standard
// error. Otherwise, the function prints nothing and returns no value.
func (p *PayloadParser) ProcessPayloadsAndHeaders(limiter *rate.Limiter, link string, payloads []string, headers []string) {
	config := &scan.ScannerConfig{
		AppendMode:      p.args.AppendMode,
		IsParameters:    p.args.Parameters,
		RateLimit:       p.args.RateLimit,
		Method:          p.args.Method,
		FollowRedirects: p.args.FollowRedirects,
		Debug:           p.args.Debug,
		Trace:           p.args.Trace,
	}
	newScanner := scan.NewScanner(limiter, config)
	link = p.EnsureProtocol(link)
	fmt.Printf(colours.NoticeColor, "Checking URL Scheme: "+link)
	fmt.Println("")

	for _, payload := range payloads {
		// Generate the context-escaped payload up front. On failure (bad
		// context/header-name, CRLF in a header payload, or a payload that
		// is too long once escaped) this payload is skipped with an
		// explicit, locatable error instead of sending a truncated or
		// structurally broken request.
		generated, err := p.GeneratePayload(payload)
		if err != nil {
			fmt.Printf(colours.ErrorColor, "Skipping payload, generation failed: "+err.Error())
			fmt.Println("")
			continue
		}

		if len(headers) == 0 {
			newScanner.Scan(link, generated, "")
		} else {
			for _, header := range headers {
				newScanner.Scan(link, generated, header)
			}
		}
	}
}

// EnsureProtocol verifies that the provided link has a protocol prefix.
// If the link does not start with "http://" or "https://", it prepends "https://" to the link.
// The function trims any leading or trailing whitespace from the link before checking the protocol.
// It returns the modified or unmodified link with the appropriate protocol.
func (p *PayloadParser) EnsureProtocol(link string) string {
	link = strings.TrimSpace(link)
	if !strings.HasPrefix(link, "http://") && !strings.HasPrefix(link, "https://") {
		return "https://" + link
	}
	return link
}
