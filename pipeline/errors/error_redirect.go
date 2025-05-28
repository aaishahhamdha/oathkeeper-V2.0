// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package errors

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/aaishahhamdha/oathkeeper/driver/configuration"
	"github.com/aaishahhamdha/oathkeeper/pipeline"
	"github.com/aaishahhamdha/oathkeeper/pipeline/session_store"
	"github.com/aaishahhamdha/oathkeeper/x"
	"github.com/pkg/errors"
)

var _ Handler = new(ErrorRedirect)

const (
	xForwardedProto = "X-Forwarded-Proto"
	xForwardedHost  = "X-Forwarded-Host"
	xForwardedUri   = "X-Forwarded-Uri"
)

type (
	ErrorRedirectConfig struct {
		To                    string `json:"to"`
		Code                  int    `json:"code"`
		ReturnToQueryParam    string `json:"return_to_query_param"`
		Type                  string `json:"type"`
		OidcLogoutUrl         string `json:"oidc_logout_url"`
		PostLogoutRedirectUrl string `json:"post_logout_redirect_url"`
	}
	ErrorRedirect struct {
		c configuration.Provider
		d ErrorRedirectDependencies
	}
	ErrorRedirectDependencies interface {
		x.RegistryWriter
	}
)

func NewErrorRedirect(
	c configuration.Provider,
	d ErrorRedirectDependencies,
) *ErrorRedirect {
	return &ErrorRedirect{c: c, d: d}
}

// ContextKeySession is the key used to store the authentication session in the request context
var ContextKeySession = struct{}{}

func (a *ErrorRedirect) Handle(w http.ResponseWriter, r *http.Request, config json.RawMessage, rule pipeline.Rule, err error) error {
	c, err := a.Config(config)
	if err != nil {
		return err
	}

	r.URL.Scheme = x.OrDefaultString(r.Header.Get(xForwardedProto), r.URL.Scheme)
	r.URL.Host = x.OrDefaultString(r.Header.Get(xForwardedHost), r.URL.Host)
	r.URL.Path = x.OrDefaultString(r.Header.Get(xForwardedUri), r.URL.Path)

	if c.Type == "auth" {
		fmt.Println("Redirect type: auth")
		// Generate a random state for CSRF protection
		state, err := GenerateRandomString(32)
		if err != nil {
			return err
		}
		// Store the state in the session store with client info
		session_store.GlobalStore.AddStateEntry(state, r.RemoteAddr, r.UserAgent())
		// Add state to the redirect URL
		redirectURL := a.RedirectURL(r.URL, c) + "&state=" + state
		// Perform the redirect
		http.Redirect(w, r, redirectURL, c.Code)
		fmt.Printf("Redirecting to: %s with state: %s\n", redirectURL, state)
	} else if c.Type == "logout" {

		fmt.Println("Redirect type: logout")
		if c.OidcLogoutUrl == "" {
			return errors.New("oidc_logout_url is required")
		}
		if c.PostLogoutRedirectUrl == "" {
			return errors.New("post_logout_redirect_url is required")
		}

		// Get session ID from cookie
		sessionCookie, err := r.Cookie("wso2_session_id")
		var idTokenHint string
		if err == nil && sessionCookie != nil {
			fmt.Printf("Logout: Found session cookie with ID: %s\n", sessionCookie.Value)

			// Check if session exists before deletion
			if _, exists := session_store.GlobalStore.GetSession(sessionCookie.Value); exists {
				fmt.Println("Session exists in store, proceeding with logout")
			} else {
				fmt.Printf("Logout: Session %s not found in store", sessionCookie.Value)
			}

			// Get ID token for OIDC logout BEFORE deleting the session
			idTokenHint, _ = session_store.GlobalStore.GetField(sessionCookie.Value, "id_token")
			if idTokenHint != "" {
				fmt.Println("Logout: ID token hint found for OIDC logout")
			} else {
				fmt.Printf("Logout: No ID token found for session %s", sessionCookie.Value)
			}

			// Now remove session from session store
			session_store.GlobalStore.DeleteSession(sessionCookie.Value)
			fmt.Printf("Logout: Successfully deleted session %s from store", sessionCookie.Value)

			// Verify session was deleted
			deletedSession, exists := session_store.GlobalStore.GetSession(sessionCookie.Value)
			fmt.Printf("Logout verification: Session exists after deletion: %v, Session data: %+v\n", exists, deletedSession)
			session_store.GlobalStore.CleanExpired()
		} else {
			fmt.Println("Logout: No session cookie found in request")
		}

		state, err := GenerateRandomString(32)
		if err != nil {
			return errors.WithStack(err)
		}

		// Construct logout URL with proper URL encoding
		logoutURL, err := url.Parse(c.OidcLogoutUrl)
		if err != nil {
			return errors.WithStack(err)
		}
		params := url.Values{}
		params.Set("post_logout_redirect_uri", c.PostLogoutRedirectUrl)
		params.Set("state", state)
		params.Set("id_token_hint", idTokenHint)

		logoutURL.RawQuery = params.Encode()
		logoutURLString := logoutURL.String()

		fmt.Printf("Logout: Calling OIDC logout URL: %s\n", logoutURLString)
		http.Redirect(w, r, logoutURLString, c.Code)
		fmt.Printf("Redirecting to: %s\n", logoutURLString)
		fmt.Println("Logout: Successfully completed logout process")
	} else {
		fmt.Println("Redirect type: none")
		// Type is "none" or any other value - just do a simple redirect
		redirectURL := a.RedirectURL(r.URL, c)
		http.Redirect(w, r, redirectURL, c.Code)
		fmt.Printf("Redirecting to: %s\n", redirectURL)
	}

	return nil
}

func (a *ErrorRedirect) Validate(config json.RawMessage) error {
	if !a.c.ErrorHandlerIsEnabled(a.GetID()) {
		return NewErrErrorHandlerNotEnabled(a)
	}
	_, err := a.Config(config)
	return err
}

func (a *ErrorRedirect) Config(config json.RawMessage) (*ErrorRedirectConfig, error) {
	var c ErrorRedirectConfig
	if err := a.c.ErrorHandlerConfig(a.GetID(), config, &c); err != nil {
		return nil, NewErrErrorHandlerMisconfigured(a, err)
	}

	if c.Code < 301 || c.Code > 302 {
		c.Code = http.StatusFound
	}

	return &c, nil
}

func (a *ErrorRedirect) GetID() string {
	return "redirect"
}

func (a *ErrorRedirect) RedirectURL(uri *url.URL, c *ErrorRedirectConfig) string {
	if c.ReturnToQueryParam == "" {
		return c.To
	}

	u, err := url.Parse(c.To)
	if err != nil {
		return c.To
	}

	q := u.Query()
	q.Set(c.ReturnToQueryParam, uri.String())
	u.RawQuery = q.Encode()
	return u.String()
}

// GenerateRandomState creates a cryptographically secure random state string
func GenerateRandomString(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
