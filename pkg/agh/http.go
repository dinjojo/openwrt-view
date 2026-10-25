package agh

import (
	"fmt"
	"net/http"
	"net/http/cookiejar"
)

func cookieJar() (http.CookieJar, error) { return cookiejar.New(nil) }

// statusError marks a non-200 answer, keeping the code for auth retry
// decisions.
type statusError struct {
	path string
	code int
}

func (e statusError) Error() string { return fmt.Sprintf("agh: %s answered %d", e.path, e.code) }

func errStatus(path string, code int) error { return statusError{path: path, code: code} }

// isAuthErr reports expired/missing session cookies: AGH answers 403
// (cookie invalid) or 401.
func isAuthErr(err error) bool {
	se, ok := err.(statusError)
	return ok && (se.code == http.StatusUnauthorized || se.code == http.StatusForbidden)
}
