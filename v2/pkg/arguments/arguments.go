package arguments

import (
	"flag"
	"fmt"
	"os"

	"github.com/ethicalhackingplayground/bxss/v2/pkg/colours"
)

// Injection point types accepted by -context. These are shared with the
// payloads package (which imports arguments, not the other way around, to
// avoid an import cycle) so payload generation and CLI validation agree on
// the exact same set of valid values.
const (
	ContextQuery  = "query"
	ContextJSON   = "json"
	ContextHeader = "header"
)

type Arguments struct {
	Concurrency     int
	Header          string
	HeaderFile      string
	Payload         string
	PayloadFile     string
	Method          string
	AppendMode      bool
	Parameters      bool
	Debug           bool
	RateLimit       float64
	FollowRedirects bool
	Trace           bool
	Context         string
	HeaderName      string
}

// Flag variables
var (
	debug           bool
	concurrency     int
	payload         string
	payloadFile     string
	method          string
	header          string
	headerFile      string
	appendMode      bool
	parameters      bool
	rateLimit       float64
	followRedirects bool
	trace           bool
	context         string
	headerName      string
)

// isHeaderNameByte reports whether b is a valid RFC 7230 "tchar" byte, i.e.
// a byte that is legal inside an HTTP header field-name token.
func isHeaderNameByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z':
		return true
	case b >= 'A' && b <= 'Z':
		return true
	case b >= '0' && b <= '9':
		return true
	}
	switch b {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}

// ValidHeaderName reports whether name is a syntactically valid HTTP header
// field name (RFC 7230 token: 1*tchar). This is checked explicitly instead of
// trusting net/http's Header.Set with the raw value, because Header.Set does
// not reject an invalid field name itself - the Go HTTP transport silently
// drops header lines with illegal characters when the request is written to
// the wire, which would make a bad -header-name fail far away from here with
// no error at all. Validating up front turns that into an immediate,
// locatable error instead.
func ValidHeaderName(name string) error {
	if name == "" {
		return fmt.Errorf("header name must not be empty")
	}
	for i := 0; i < len(name); i++ {
		if !isHeaderNameByte(name[i]) {
			return fmt.Errorf("header name %q contains invalid character %q at position %d", name, name[i], i)
		}
	}
	return nil
}

// ValidateContextArgs checks that -context and -header-name are mutually
// consistent:
//   - -context must be one of query, json, header
//   - -header-name is required, and must be a syntactically valid HTTP
//     header field name, when -context=header
//   - -header-name must be omitted for every other context, since it would
//     otherwise silently have no effect
//
// It returns a descriptive error instead of exiting so that callers (and
// tests) can decide how to react; ValidateArgs is the only caller that turns
// a non-nil error here into a process exit.
func (a *Arguments) ValidateContextArgs() error {
	switch a.Context {
	case ContextQuery, ContextJSON, ContextHeader:
	default:
		return fmt.Errorf("invalid -context %q: must be one of %q, %q, %q", a.Context, ContextQuery, ContextJSON, ContextHeader)
	}

	if a.Context == ContextHeader {
		if a.HeaderName == "" {
			return fmt.Errorf("-header-name is required when -context=%s", ContextHeader)
		}
		if err := ValidHeaderName(a.HeaderName); err != nil {
			return fmt.Errorf("-header-name %q failed header field name validation: %w", a.HeaderName, err)
		}
	} else if a.HeaderName != "" {
		return fmt.Errorf("-header-name is only valid when -context=%s, got -context=%s", ContextHeader, a.Context)
	}

	return nil
}

// ValidateArgs validates the arguments passed to the program and prints the
func (a *Arguments) ValidateArgs() {
	// prints the default help and exits the program with status 1.

	// The banner
	fmt.Printf(colours.BannerColor, `
  ____                     
 | __ )  __  __  ___   ___ 
 |  _ \  \ \/ / / __| / __|
 | |_) |  >  <  \__ \ \__ \
 |____/  /_/\_\ |___/ |___/
                                        
	`, "")
	fmt.Printf(colours.TextColor, "", "v0.0.3")
	fmt.Printf("\n")

	// Check if at least one header and one payload option is provided
	if (a.Header == "" && a.HeaderFile == "") && (a.Payload == "" && a.PayloadFile == "") {
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Validate -context/-header-name separately from the header/payload
	// check above so a conflict here (e.g. -header-name without
	// -context=header) is reported with its own exit code and does not get
	// masked by flag.PrintDefaults() from the block above.
	if err := a.ValidateContextArgs(); err != nil {
		fmt.Printf(colours.ErrorColor, "Invalid arguments: "+err.Error())
		fmt.Printf("\n")
		flag.PrintDefaults()
		os.Exit(2)
	}
}

// NewArguments parses the command line flags and returns a pointer to an Arguments
// object. The Arguments object contains the parsed values of the flags, which can
// be used to configure the program. The function will panic if there is an error
// parsing the flags.
func NewArguments() *Arguments {

	// Define the flags
	flag.IntVar(&concurrency, "c", 30, "Set the concurrency level for the scanner")
	flag.StringVar(&header, "H", "", "Set a single custom header to test for blind XSS")
	flag.StringVar(&headerFile, "hf", "", "Path to file containing headers to test for blind XSS")
	flag.StringVar(&payload, "p", "", "The blind XSS payload to test")
	flag.StringVar(&payloadFile, "pf", "", "Path to file containing payloads to test for blind XSS")
	flag.BoolVar(&appendMode, "a", false, "Append the payload to the parameter value when testing")
	flag.BoolVar(&parameters, "t", false, "Test the parameters for blind XSS by appending the payload to the parameter value")
	flag.StringVar(&method, "X", "", "The HTTP method to use when testing (GET, POST, etc.)")
	flag.BoolVar(&debug, "v", false, "Enable debug mode to view full request details and debug information")
	flag.Float64Var(&rateLimit, "rl", 0, "Rate limit in requests per second (optional to prevent abuse)")
	flag.BoolVar(&followRedirects, "f", false, "Follow redirects when testing (optional)")
	flag.BoolVar(&trace, "l", false, "Enable trace mode to track which host is vulnerable to XSS, if your canary server support custom parameters, insert url={LINK}")
	flag.StringVar(&context, "context", ContextQuery, "The injection point the payload is generated for: 'query' (passed through as-is, URL-encoded later), 'json' (escaped with the standard JSON string encoder so quotes/backslashes/newlines can't break the request body), or 'header' (payload is rejected outright if it contains CR or LF, since that would split the request into extra header lines)")
	flag.StringVar(&headerName, "header-name", "", "The HTTP header the payload will be injected into; required when -context=header (and validated as a legal header field name), and must be omitted for every other -context value")

	// Parse the arguments
	flag.Parse()

	return &Arguments{
		Concurrency:     concurrency,
		Header:          header,
		HeaderFile:      headerFile,
		Payload:         payload,
		PayloadFile:     payloadFile,
		Method:          method,
		AppendMode:      appendMode,
		Parameters:      parameters,
		Debug:           debug,
		RateLimit:       rateLimit,
		FollowRedirects: followRedirects,
		Trace:           trace,
		Context:         context,
		HeaderName:      headerName,
	}
}
