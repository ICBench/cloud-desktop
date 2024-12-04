package manager

import (
	"fmt"
	"strings"
)

type InvalidParamError interface {
	error
	Field() string
	SetContext(string)
}

type invalidParamError struct {
	context string
	field   string
	reason  string
}

func (e invalidParamError) Error() string {
	return fmt.Sprintf("%s, %s.", e.reason, e.Field())
}

func (e invalidParamError) Field() string {
	sb := &strings.Builder{}
	sb.WriteString(e.context)
	if sb.Len() > 0 {
		sb.WriteRune('.')
	}
	sb.WriteString(e.field)
	return sb.String()
}

func (e *invalidParamError) SetContext(ctx string) {
	e.context = ctx
}

func NewErrParamRequired(field string) InvalidParamError {
	return &invalidParamError{
		field:  field,
		reason: "missing required field",
	}
}

func NewErrParamNull(field string) InvalidParamError {
	return &invalidParamError{
		field:  field,
		reason: "null field",
	}
}
