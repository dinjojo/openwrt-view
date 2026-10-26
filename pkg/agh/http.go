package agh

import (
	"fmt"
)

// statusError marks a non-200 answer, keeping the code for debugging.
type statusError struct {
	path string
	code int
}

func (e statusError) Error() string { return fmt.Sprintf("agh: %s answered %d", e.path, e.code) }

func errStatus(path string, code int) error { return statusError{path: path, code: code} }
