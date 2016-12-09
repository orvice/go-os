package auth

import (
	"errors"
	"time"

	"github.com/micro/go-micro/client"
	"github.com/micro/go-micro/server"

	"golang.org/x/net/context"
)

// Auth handles client side validation of authentication
// The client does not actually handle authentication itself.
// This could be an oauth2 provider, openid, basic auth, etc.
type Auth interface {
	// Determine if a request with context is authorised
	// Should extract token from the context, check with
	// the authorizer and return an err if not authed.
	// Can be used for both client and server
	Authorized(ctx context.Context, req Request) (*Token, error)
	// Retrieve a token for this client, should handle refreshing
	Token() (*Token, error)
	// Lookup a token
	Introspect(ctx context.Context) (*Token, error)
	// Revoke a token
	Revoke(t *Token) error
	// Will retrieve token from the context
	FromContext(ctx context.Context) (*Token, bool)
	// Creates a context with the token which can be
	NewContext(ctx context.Context, t *Token) context.Context
	// Retrieves token from headers
	// We may get back a partial token here
	FromHeader(map[string]string) (*Token, bool)
	// Adds token to headers
	NewHeader(map[string]string, *Token) map[string]string
	// Name
	String() string
}

type Option func(*Options)

// Could be client or server request
type Request interface {
	Service() string
	Method() string
}

// Basically identical to oauth token
type Token struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresAt    time.Time
	Scopes       []string
	Metadata     map[string]string
}

var (
	ErrInvalidToken = errors.New("invalid token")
)

func ClientWrapper(a Auth) client.Wrapper {
	return func(c client.Client) client.Client {
		return &clientWrapper{c, a}
	}
}

func HandlerWrapper(a Auth) server.HandlerWrapper {
	return func(h server.HandlerFunc) server.HandlerFunc {
		return handlerWrapper(h, a)
	}
}

func NewAuth(opts ...Option) Auth {
	return newOS(opts...)
}
