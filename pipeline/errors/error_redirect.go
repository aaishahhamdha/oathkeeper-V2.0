// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package errors

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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
		x.RegistryLogger
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
		a.d.Logger().Debug("Redirect type: auth")
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
		a.d.Logger().WithFields(map[string]interface{}{
			"redirect_url": redirectURL,
			"state":        state,
		}).Info("Redirecting to auth URL with state")
	} else if c.Type == "logout" {

		a.d.Logger().Debug("Redirect type: logout")
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
			a.d.Logger().WithField("session_id", sessionCookie.Value).Debug("Logout: Found session cookie")

			// Check if session exists before deletion
			if _, exists := session_store.GlobalStore.GetSession(sessionCookie.Value); exists {
				a.d.Logger().Debug("Session exists in store, proceeding with logout")
			} else {
				a.d.Logger().WithField("session_id", sessionCookie.Value).Warn("Logout: Session not found in store")
			}

			// Get ID token for OIDC logout BEFORE deleting the session
			idTokenHint, _ = session_store.GlobalStore.GetField(sessionCookie.Value, "id_token")
			if idTokenHint != "" {
				a.d.Logger().Debug("Logout: ID token hint found for OIDC logout")
			} else {
				a.d.Logger().WithField("session_id", sessionCookie.Value).Debug("Logout: No ID token found for session")
			}

			// Now remove session from session store
			session_store.GlobalStore.DeleteSession(sessionCookie.Value)
			a.d.Logger().WithField("session_id", sessionCookie.Value).Info("Logout: Successfully deleted session from store")

			// Verify session was deleted
			deletedSession, exists := session_store.GlobalStore.GetSession(sessionCookie.Value)
			a.d.Logger().WithFields(map[string]interface{}{
				"session_exists": exists,
				"session_data":   deletedSession,
			}).Debug("Logout verification: Session deletion status")
			session_store.GlobalStore.CleanExpired()

			// Remove the wso2_session_id cookie from the client's browser
			a.clearSessionCookie(w)
			a.d.Logger().Info("Logout: Cleared wso2_session_id cookie from client")
		} else {
			a.d.Logger().Info("Logout: No session cookie found in request")
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

		a.d.Logger().WithField("logout_url", logoutURLString).Info("Logout: Calling OIDC logout URL")
		http.Redirect(w, r, logoutURLString, c.Code)
		a.d.Logger().WithField("redirect_url", logoutURLString).Info("Redirecting to logout URL")
		a.d.Logger().Info("Logout: Successfully completed logout process")
	} else {
		a.d.Logger().Debug("Redirect type: none")
		// Type is "none" or any other value - just do a simple redirect
		redirectURL := a.RedirectURL(r.URL, c)
		http.Redirect(w, r, redirectURL, c.Code)
		a.d.Logger().WithField("redirect_url", redirectURL).Info("Redirecting to default URL")
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

// clearSessionCookie removes the wso2_session_id cookie from the client's browser
// by setting it with an expired date and empty value
func (a *ErrorRedirect) clearSessionCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     "wso2_session_id",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
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
