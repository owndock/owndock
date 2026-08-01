package localization

import (
	"context"
	"testing"
)

func TestMatchAcceptLanguage(t *testing.T) {
	tests := []struct {
		name   string
		value  string
		locale Locale
	}{
		{name: "default", locale: EnglishUS},
		{name: "simplified Chinese", value: "zh-CN", locale: SimplifiedChinese},
		{name: "Chinese script", value: "zh-Hans-CN,zh;q=0.9,en;q=0.8", locale: SimplifiedChinese},
		{name: "English region", value: "en-GB,en;q=0.9", locale: EnglishUS},
		{name: "quality preference", value: "en-US;q=0.5,zh-CN;q=0.9", locale: SimplifiedChinese},
		{name: "unsupported", value: "ja-JP", locale: EnglishUS},
		{name: "malformed", value: "zh-CN;q=wrong", locale: EnglishUS},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Match(test.value); got != test.locale {
				t.Fatalf("Match(%q) = %q, want %q", test.value, got, test.locale)
			}
		})
	}
}

func TestCLILocalePrecedence(t *testing.T) {
	values := map[string]string{
		"OWNDOCK_LOCALE": "zh_CN.UTF-8",
		"LC_ALL":         "en_US.UTF-8",
	}
	lookup := func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
	if got := CLILocale("en-US", lookup); got != EnglishUS {
		t.Fatalf("explicit locale = %q", got)
	}
	if got := CLILocale("", lookup); got != SimplifiedChinese {
		t.Fatalf("environment locale = %q", got)
	}
	delete(values, "OWNDOCK_LOCALE")
	if got := CLILocale("", lookup); got != EnglishUS {
		t.Fatalf("POSIX locale = %q", got)
	}
}

func TestLocaleContextRejectsUnsupportedValue(t *testing.T) {
	ctx := WithLocale(context.Background(), Locale("ja-JP"))
	if got := FromContext(ctx); got != DefaultLocale {
		t.Fatalf("locale = %q", got)
	}
}
