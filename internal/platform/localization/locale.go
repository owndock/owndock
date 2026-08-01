package localization

import (
	"context"
	"strings"

	"golang.org/x/text/language"
)

type Locale string

const (
	EnglishUS         Locale = "en-US"
	SimplifiedChinese Locale = "zh-CN"
	DefaultLocale            = EnglishUS
)

var (
	supportedLocales = []Locale{EnglishUS, SimplifiedChinese}
	supportedTags    = []language.Tag{language.AmericanEnglish, language.SimplifiedChinese}
	localeMatcher    = language.NewMatcher(supportedTags)
)

type localeKey struct{}

// Supported returns a copy of the canonical locale identifiers supported by
// the current product release.
func Supported() []Locale {
	return append([]Locale(nil), supportedLocales...)
}

// Match resolves an HTTP Accept-Language value. Invalid, empty, and
// unsupported values safely fall back to en-US.
func Match(value string) Locale {
	value = strings.TrimSpace(value)
	if value == "" {
		return DefaultLocale
	}
	tags, _, err := language.ParseAcceptLanguage(value)
	if err != nil || len(tags) == 0 {
		return DefaultLocale
	}
	_, index, confidence := localeMatcher.Match(tags...)
	if confidence == language.No {
		return DefaultLocale
	}
	return supportedLocales[index]
}

// Parse resolves a locale-like value used by configuration and command-line
// clients. It accepts common POSIX forms such as zh_CN.UTF-8.
func Parse(value string) Locale {
	value = strings.TrimSpace(value)
	if value == "" || value == "C" || value == "POSIX" {
		return DefaultLocale
	}
	if index := strings.IndexByte(value, '.'); index >= 0 {
		value = value[:index]
	}
	if index := strings.IndexByte(value, '@'); index >= 0 {
		value = value[:index]
	}
	value = strings.ReplaceAll(value, "_", "-")
	return Match(value)
}

// CLILocale applies the customer CLI precedence contract. The caller parses
// --locale and passes it as explicit; lookupEnv normally is os.LookupEnv.
func CLILocale(explicit string, lookupEnv func(string) (string, bool)) Locale {
	if strings.TrimSpace(explicit) != "" {
		return Parse(explicit)
	}
	if lookupEnv == nil {
		return DefaultLocale
	}
	for _, name := range []string{"OWNDOCK_LOCALE", "LC_ALL", "LC_MESSAGES", "LANG"} {
		if value, ok := lookupEnv(name); ok && strings.TrimSpace(value) != "" {
			return Parse(value)
		}
	}
	return DefaultLocale
}

func WithLocale(ctx context.Context, locale Locale) context.Context {
	if !IsSupported(locale) {
		locale = DefaultLocale
	}
	return context.WithValue(ctx, localeKey{}, locale)
}

func FromContext(ctx context.Context) Locale {
	if ctx != nil {
		if locale, ok := ctx.Value(localeKey{}).(Locale); ok && IsSupported(locale) {
			return locale
		}
	}
	return DefaultLocale
}

func IsSupported(locale Locale) bool {
	return locale == EnglishUS || locale == SimplifiedChinese
}
