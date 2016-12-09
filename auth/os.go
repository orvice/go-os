package auth

import (
	"strings"
	"sync"
	"time"

	"github.com/micro/go-micro/client"
	"github.com/micro/go-micro/metadata"

	oauth2 "github.com/micro/auth-srv/proto/oauth2"
	"golang.org/x/net/context"
)

type os struct {
	exit chan bool
	opts Options
	c    oauth2.Oauth2Client

	sync.Mutex
	t *Token
}

type tokenKey struct{}

func newOS(opts ...Option) Auth {
	var options Options
	for _, o := range opts {
		o(&options)
	}
	if options.Client == nil {
		options.Client = client.DefaultClient
	}

	return &os{
		exit: make(chan bool),
		opts: options,
		c:    oauth2.NewOauth2Client("go.micro.srv.auth", options.Client),
	}
}

func (o *os) Authorized(ctx context.Context, req Request) (*Token, error) {
	// There's no policies yet. Just check if the token is valid.
	t, err := o.Introspect(ctx)
	if err != nil {
		return nil, err
	}
	// and just for safe keeping
	if t.ExpiresAt.Before(time.Now()) {
		return nil, ErrInvalidToken
	}
	return t, nil
}

func (o *os) Token() (*Token, error) {
	o.Lock()
	defer o.Unlock()

	// we should have cached the token and if it hasn't expired we'll hand it back
	if o.t != nil && len(o.t.AccessToken) > 0 && !o.t.ExpiresAt.Before(time.Now()) {
		return o.t, nil
	}

	var grantType, refreshToken string

	// if its nil, ask for new token
	if o.t == nil {
		grantType = "client_credentials"
	} else {
		// ask for refresh token
		grantType = "refresh_token"
		refreshToken = o.t.RefreshToken
	}

	rsp, err := o.c.Token(context.TODO(), &oauth2.TokenRequest{
		GrantType:    grantType,
		ClientId:     o.opts.Id,
		ClientSecret: o.opts.Secret,
		RefreshToken: refreshToken,
	})

	// error? just return invalid token
	if err != nil {
		return nil, ErrInvalidToken
	}

	// save token for reuse
	o.t = &Token{
		AccessToken:  rsp.Token.AccessToken,
		RefreshToken: rsp.Token.RefreshToken,
		TokenType:    rsp.Token.TokenType,
		ExpiresAt:    time.Unix(rsp.Token.ExpiresAt, 0),
		Scopes:       rsp.Token.Scopes,
		Metadata:     rsp.Token.Metadata,
	}

	return o.t, nil
}

func (o *os) Introspect(ctx context.Context) (*Token, error) {
	t, ok := o.FromContext(ctx)
	if !ok {
		md, kk := metadata.FromContext(ctx)
		if !kk {
			return nil, ErrInvalidToken
		}
		t, ok = o.FromHeader(md)
		if !ok {
			return nil, ErrInvalidToken
		}
	}

	rsp, err := o.c.Introspect(context.TODO(), &oauth2.IntrospectRequest{
		AccessToken: t.AccessToken,
	})
	if err != nil {
		return nil, err
	}

	// if its not active just err?
	if !rsp.Active {
		return nil, ErrInvalidToken
	}

	return &Token{
		AccessToken:  rsp.Token.AccessToken,
		RefreshToken: rsp.Token.RefreshToken,
		TokenType:    rsp.Token.TokenType,
		ExpiresAt:    time.Unix(rsp.Token.ExpiresAt, 0),
		Scopes:       rsp.Token.Scopes,
		Metadata:     rsp.Token.Metadata,
	}, nil
}

func (o *os) Revoke(t *Token) error {
	_, err := o.c.Revoke(context.TODO(), &oauth2.RevokeRequest{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
	})
	return err
}

func (o *os) FromContext(ctx context.Context) (*Token, bool) {
	t, ok := ctx.Value(tokenKey{}).(*Token)
	return t, ok
}

func (o *os) NewContext(ctx context.Context, t *Token) context.Context {
	return context.WithValue(ctx, tokenKey{}, t)
}

func (o *os) FromHeader(hd map[string]string) (*Token, bool) {
	var t string
	var ok bool

	// range possible auth headers
	for _, key := range []string{"authorization", "Authorization"} {
		t, ok = hd[key]
		if ok {
			break
		}
	}

	// no token
	if !ok {
		return nil, false
	}

	parts := strings.Split(t, " ")
	if len(parts) != 2 {
		return nil, false
	}
	return &Token{
		AccessToken: parts[1],
		TokenType:   parts[0],
	}, true
}

func (o *os) NewHeader(hd map[string]string, t *Token) map[string]string {
	// we basically only store access token
	hd["authorization"] = t.TokenType + " " + t.AccessToken
	return hd
}

func (o *os) String() string {
	return "os"
}
