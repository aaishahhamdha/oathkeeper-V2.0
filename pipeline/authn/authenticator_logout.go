package authn

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/aaishahhamdha/oathkeeper/driver/configuration"
	"github.com/aaishahhamdha/oathkeeper/helper"
	"github.com/aaishahhamdha/oathkeeper/pipeline"
	"github.com/dgraph-io/ristretto"
	"github.com/ory/x/httpx"
	"github.com/ory/x/logrusx"
	"github.com/pkg/errors"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"
)

type AuthenticatorLogoutConfiguration struct {
	OidcLogoutUrl         string                                 `json:"oidc_logout_url"`
	PostLogoutRedirectUrl string                                 `json:"post_logout_redirect_url"`
	Retry                 *AuthenticatorLogoutRetryConfiguration `json:"retry"`
	Cache                 logoutCacheConfig                      `json:"cache"`
}

type AuthenticatorLogoutRetryConfiguration struct {
	Timeout string `json:"max_delay"`
	MaxWait string `json:"give_up_after"`
}

type logoutCacheConfig struct {
	Enabled bool   `json:"enabled"`
	TTL     string `json:"ttl"`
	MaxCost int    `json:"max_cost"`
}

type AuthenticatorLogout struct {
	c         configuration.Provider
	clientMap map[string]*http.Client

	mu         sync.RWMutex
	tokenCache *ristretto.Cache[string, []byte]
	cacheTTL   *time.Duration
	logger     *logrusx.Logger
	provider   trace.TracerProvider
}

// Authenticate implements Authenticator.
func (a *AuthenticatorLogout) Authenticate(r *http.Request, session *AuthenticationSession, config json.RawMessage, rule pipeline.Rule) (err error) {
	// Always fail with unauthorized error
	return errors.WithStack(helper.ErrUnauthorized)
}

func NewAuthenticatorLogout(c configuration.Provider, logger *logrusx.Logger, provider trace.TracerProvider) *AuthenticatorLogout {
	tokenCache, err := ristretto.NewCache(&ristretto.Config[string, []byte]{
		NumCounters: 1e7,
		MaxCost:     1 << 30,
		BufferItems: 64,
	})
	if err != nil {
		logger.Fatal("Failed to create token cache", err)
	}

	return &AuthenticatorLogout{
		c:          c,
		logger:     logger,
		provider:   provider,
		clientMap:  make(map[string]*http.Client),
		tokenCache: tokenCache,
	}
}

func (a *AuthenticatorLogout) GetID() string {
	return "logout"
}

func (a *AuthenticatorLogout) Validate(config json.RawMessage) error {
	if !a.c.AuthenticatorIsEnabled(a.GetID()) {
		return NewErrAuthenticatorNotEnabled(a)
	}

	_, _, err := a.Config(config)
	return err
}

func (a *AuthenticatorLogout) Config(config json.RawMessage) (*AuthenticatorLogoutConfiguration, *http.Client, error) {
	var c AuthenticatorLogoutConfiguration
	if err := a.c.AuthenticatorConfig(a.GetID(), config, &c); err != nil {
		return nil, nil, NewErrAuthenticatorMisconfigured(a, err)
	}

	rawKey, err := json.Marshal(&c)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	clientKey := fmt.Sprintf("%x", md5.Sum(rawKey))
	a.mu.RLock()
	client, ok := a.clientMap[clientKey]
	a.mu.RUnlock()

	if !ok || client == nil {
		a.logger.Debug("Initializing http client")
		var rt http.RoundTripper

		if c.Retry == nil {
			c.Retry = &AuthenticatorLogoutRetryConfiguration{Timeout: "500ms", MaxWait: "1s"}
		} else {
			if c.Retry.Timeout == "" {
				c.Retry.Timeout = "500ms"
			}
			if c.Retry.MaxWait == "" {
				c.Retry.MaxWait = "1s"
			}
		}
		duration, err := time.ParseDuration(c.Retry.Timeout)
		if err != nil {
			return nil, nil, errors.WithStack(err)
		}
		timeout := time.Millisecond * duration

		maxWait, err := time.ParseDuration(c.Retry.MaxWait)
		if err != nil {
			return nil, nil, errors.WithStack(err)
		}

		client = httpx.NewResilientClient(
			httpx.ResilientClientWithMaxRetryWait(maxWait),
			httpx.ResilientClientWithConnectionTimeout(timeout),
		).StandardClient()
		client.Transport = otelhttp.NewTransport(rt, otelhttp.WithTracerProvider(a.provider))
		a.mu.Lock()
		a.clientMap[clientKey] = client
		a.mu.Unlock()
	}

	if c.Cache.TTL != "" {
		cacheTTL, err := time.ParseDuration(c.Cache.TTL)
		if err != nil {
			return nil, nil, err
		}

		// clear cache if previous ttl was longer (or none)
		if a.tokenCache != nil {
			if a.cacheTTL == nil || (a.cacheTTL != nil && a.cacheTTL.Seconds() > cacheTTL.Seconds()) {
				a.tokenCache.Clear()
			}
		}

		a.cacheTTL = &cacheTTL
	}

	if a.tokenCache == nil {
		cost := int64(c.Cache.MaxCost)
		if cost == 0 {
			cost = 100000000
		}
		a.logger.Debugf("Creating cache with max cost: %d", c.Cache.MaxCost)
		cache, err := ristretto.NewCache(&ristretto.Config[string, []byte]{
			// This will hold about 1000 unique mutation responses.
			NumCounters: cost * 10,
			// Allocate a max
			MaxCost: cost,
			// This is a best-practice value.
			BufferItems: 64,
			Cost: func(value []byte) int64 {
				return 1
			},
			IgnoreInternalCost: true,
		})
		if err != nil {
			return nil, nil, err
		}

		a.tokenCache = cache
	}

	return &c, client, nil
}
