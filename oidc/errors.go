package oidc

import (
	"errors"
	"fmt"
)

// ErrorKind categorizes the reason an ID Token or Logout Token failed
// verification. It lets callers decide whether a failure is terminal (the
// token or the verifier configuration must be fixed) or transient (the exact
// same token may be accepted on a later attempt), without having to match on
// human-readable error strings.
type ErrorKind int

const (
	// KindUnspecified is returned for failures that predate the error
	// taxonomy, or for which no more specific category applies.
	KindUnspecified ErrorKind = iota

	// KindMalformedToken means the token is not a well-formed, signed JWT in
	// an algorithm the verifier is configured to accept. The token can never
	// be accepted without changing it, so this is a terminal failure.
	KindMalformedToken

	// KindInvalidSignature means the token's signature did not match any key
	// available to the verifier. This is a terminal failure: the token must be
	// treated as forged or untrusted and rejected rather than retried.
	KindInvalidSignature

	// KindInvalidClaims means a validated token failed one of the OpenID
	// Connect claim checks (issuer, audience, "nbf", required Logout Token
	// fields, and so on). The token itself is well formed and correctly signed,
	// but it is not acceptable for this verifier, so this is a terminal
	// failure.
	KindInvalidClaims

	// KindExpired means the token's "exp" claim is in the past. An expired
	// token is not currently usable; the caller should re-authenticate rather
	// than retry the identical token. See TokenExpiredError.
	KindExpired

	// KindConfiguration means the Config used to build the verifier is
	// invalid (for example, neither a ClientID nor SkipClientIDCheck was set).
	// Retrying with the same configuration cannot succeed; the program has to
	// be fixed.
	KindConfiguration

	// KindRemoteKeySet means a transient failure occurred while fetching the
	// remote JSON Web Key Set (a network error, a non-200 HTTP response, or a
	// malformed key set document). The token itself was not rejected, so
	// retrying the same verification once the JWKs endpoint is reachable may
	// succeed. See RemoteKeySetError.
	KindRemoteKeySet

	// KindCanceled means the context passed to verification was canceled or
	// exceeded its deadline before verification finished. Retrying with a
	// fresh context is expected to be safe.
	KindCanceled
)

// String returns a stable, machine-readable name for the kind rather than a
// user-facing sentence.
func (k ErrorKind) String() string {
	switch k {
	case KindMalformedToken:
		return "malformed_token"
	case KindInvalidSignature:
		return "invalid_signature"
	case KindInvalidClaims:
		return "invalid_claims"
	case KindExpired:
		return "expired"
	case KindConfiguration:
		return "configuration"
	case KindRemoteKeySet:
		return "remote_keyset"
	case KindCanceled:
		return "canceled"
	default:
		return "unspecified"
	}
}

// VerificationError is the concrete error type returned by
// IDTokenVerifier.Verify and IDTokenVerifier.VerifyLogout for failures
// other than expiration. It wraps the underlying error while assigning it a
// stable ErrorKind.
//
// Use ErrorKindOf to classify an error and IsRetryable to decide whether
// the same request is worth retrying. Match on the exported sentinel errors
// (ErrInvalidSignature, ErrInvalidClaims, ErrMalformedToken,
// ErrInvalidConfiguration) with errors.Is to distinguish terminal categories.
type VerificationError struct {
	// Kind is the stable category of the failure.
	Kind ErrorKind

	// Err is the underlying error. It is preserved by errors.Is and
	// errors.Unwrap.
	Err error
}

func (e *VerificationError) Error() string {
	return e.Err.Error()
}

func (e *VerificationError) Unwrap() error {
	return e.Err
}

func newVerificationError(kind ErrorKind, format string, args ...any) error {
	return &VerificationError{
		Kind: kind,
		Err:  fmt.Errorf(format, args...),
	}
}

func wrapVerificationError(kind ErrorKind, sentinel error, cause error, format string, args ...any) error {
	inner := fmt.Errorf(format+": %w", append(args, sentinel)...)
	return &VerificationError{
		Kind: kind,
		Err:  fmt.Errorf("%w: %w", inner, cause),
	}
}

// wrapCause attaches a transient, non-sentinel cause (such as a context error)
// without implying one of the terminal sentinel categories.
func wrapCause(kind ErrorKind, cause error, format string, args ...any) error {
	return &VerificationError{
		Kind: kind,
		Err:  fmt.Errorf(format+": %w", append(args, cause)...),
	}
}

// Sentinel errors marking the terminal categories a caller can act on. They
// are wrapped by VerificationError, so inspect them with errors.Is.
var (
	// ErrMalformedToken indicates a token that could not be parsed as a
	// signed JWT using the configured signing algorithms.
	ErrMalformedToken = errors.New("oidc: malformed token")

	// ErrInvalidSignature indicates a token whose signature could not be
	// verified against any available key.
	ErrInvalidSignature = errors.New("oidc: token signature verification failed")

	// ErrInvalidClaims indicates a correctly signed token whose claims fail
	// validation (issuer, audience, "nbf", or required Logout Token claims).
	ErrInvalidClaims = errors.New("oidc: token claims validation failed")

	// ErrInvalidConfiguration indicates an unusable verifier Config.
	ErrInvalidConfiguration = errors.New("oidc: invalid verifier configuration")
)

// RemoteKeySetError wraps a failure to retrieve or decode the remote JSON Web
// Key Set. Unlike an invalid signature, this does not say anything about the
// token, and the same verification can be retried once the endpoint
// recovers.
//
// StatusCode holds the HTTP status returned by the JWKs endpoint, or zero
// when the failure happened before a response was received (for example, a
// network or context error).
type RemoteKeySetError struct {
	// StatusCode is the HTTP status code from the JWKs response, or zero if
	// no response was available.
	StatusCode int

	Err error
}

func (e *RemoteKeySetError) Error() string {
	return e.Err.Error()
}

func (e *RemoteKeySetError) Unwrap() error {
	return e.Err
}

// Kind implements the same classification interface as the other
// verification errors. A remote key set failure is always transient.
func (e *RemoteKeySetError) Kind() ErrorKind {
	return KindRemoteKeySet
}

// ErrorKindOf returns the ErrorKind of a verification error. It returns
// KindUnspecified for nil or errors this package did not produce.
func ErrorKindOf(err error) ErrorKind {
	if err == nil {
		return KindUnspecified
	}

	var verificationErr *VerificationError
	if errors.As(err, &verificationErr) {
		return verificationErr.Kind
	}

	var remoteErr *RemoteKeySetError
	if errors.As(err, &remoteErr) {
		return remoteErr.Kind()
	}

	var expired *TokenExpiredError
	if errors.As(err, &expired) {
		return expired.Kind()
	}

	return KindUnspecified
}

// IsRetryable reports whether the same verification request might succeed if
// it is attempted again. Only transient failures are retryable:
//
//   - A canceled or timed-out request (KindCanceled) is retryable with a
//     fresh, non-canceled context.
//   - A remote key set failure (KindRemoteKeySet) is retryable once the
//     JWKs endpoint is reachable.
//
// Malformed tokens, signature failures, claim failures, expired tokens, and
// configuration errors are terminal: retrying the identical token against the
// identical configuration cannot change the outcome.
func IsRetryable(err error) bool {
	switch ErrorKindOf(err) {
	case KindRemoteKeySet, KindCanceled:
		return true
	default:
		return false
	}
}
