package secretref

import (
	"errors"
	"regexp"
	"strings"
)

var (
	ErrInvalid   = errors.New("secret reference is invalid")
	aliasPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
)

func Alias(reference string) (string, error) {
	const prefix = "secret://"
	if !strings.HasPrefix(reference, prefix) {
		return "", ErrInvalid
	}
	alias := strings.TrimPrefix(reference, prefix)
	if !aliasPattern.MatchString(alias) {
		return "", ErrInvalid
	}
	return alias, nil
}
