// Copyright Franklin "Snaipe" Mathieu.
//
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

package athens

import "net/url"

type ErrorType string

const (
	ErrInvalidRequest          ErrorType = "invalid_request"
	ErrUnauthorizedClient      ErrorType = "unauthorized_client"
	ErrAccessDenied            ErrorType = "access_denied"
	ErrUnsupportedResponseType ErrorType = "unsupported_response_type"
	ErrInvalidScope            ErrorType = "invalid_scope"
	ErrServerError             ErrorType = "server_error"
	ErrUnsupportedGrantType    ErrorType = "unsupported_grant_type"
	ErrInvalidGrant            ErrorType = "invalid_grant"
	ErrInvalidClient           ErrorType = "invalid_client"
	ErrAuthorizationPending    ErrorType = "authorization_pending"
	ErrSlowDown                ErrorType = "slow_down"
	ErrExpiredToken            ErrorType = "expired_token"
)


type ResponseMode string

const (
	ResponseQuery    ResponseMode = "query"
	ResponseFragment ResponseMode = "fragment"
)

// oauthError is the standard error response for token, introspection,
// revocation, and registration endpoints.
type oauthError struct {
	Status      int       `json:"-"`
	Code        ErrorType `json:"error"`
	Description string    `json:"error_description,omitempty"`
}

func (e *oauthError) Error() string {
	return string(e.Code)
}

type redirectError struct {
	Type        ErrorType
	Description string
	ErrorURI    string
	RedirectURI *url.URL
	Mode        ResponseMode
}

func (err *redirectError) Error() string {
	return string(err.Type)
}

func (err *redirectError) URI() string {
	newurl := *err.RedirectURI

	var field *string
	switch err.Mode {
	case ResponseFragment:
		field = &newurl.RawFragment
	default:
		field = &newurl.RawQuery
	}

	values, _ := url.ParseQuery(*field)
	values.Set("error", string(err.Type))
	if err.Description != "" {
		values.Set("error_description", err.Description)
	}
	if err.ErrorURI != "" {
		values.Set("error_uri", err.ErrorURI)
	}

	*field = values.Encode()
	return newurl.String()
}

func newRedirectError(base *url.URL, mode ResponseMode, typ ErrorType, msg string, uri string) error {
	return &redirectError{
		Type:        typ,
		Description: msg,
		ErrorURI:    uri,
		RedirectURI: base,
		Mode:        mode,
	}
}
