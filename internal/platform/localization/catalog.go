package localization

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
)

const fallbackErrorCode = "request_failed"

//go:embed locales/*.json
var localeFiles embed.FS

type localeDocument struct {
	APIErrors map[string]string `json:"api_errors"`
}

type Catalog struct {
	apiErrors map[Locale]map[string]string
}

var defaultCatalog = mustLoadCatalog()

// APIError returns the negotiated locale and safe message for a stable API
// error code. Unknown codes never expose implementation details.
func APIError(ctx context.Context, code string) (Locale, string) {
	locale := FromContext(ctx)
	return locale, defaultCatalog.apiError(locale, code)
}

func (catalog *Catalog) apiError(locale Locale, code string) string {
	messages, ok := catalog.apiErrors[locale]
	if !ok {
		messages = catalog.apiErrors[DefaultLocale]
	}
	if message := messages[code]; message != "" {
		return message
	}
	if message := messages[fallbackErrorCode]; message != "" {
		return message
	}
	return catalog.apiErrors[DefaultLocale][fallbackErrorCode]
}

func mustLoadCatalog() *Catalog {
	catalog := &Catalog{apiErrors: make(map[Locale]map[string]string, len(supportedLocales))}
	for _, locale := range supportedLocales {
		path := fmt.Sprintf("locales/%s.json", locale)
		data, err := localeFiles.ReadFile(path)
		if err != nil {
			panic(fmt.Sprintf("load localization catalog %s: %v", path, err))
		}
		var document localeDocument
		if err := json.Unmarshal(data, &document); err != nil {
			panic(fmt.Sprintf("decode localization catalog %s: %v", path, err))
		}
		messages := document.APIErrors
		if messages[fallbackErrorCode] == "" {
			panic(fmt.Sprintf("localization catalog %s has no %s message", path, fallbackErrorCode))
		}
		catalog.apiErrors[locale] = messages
	}
	validateEquivalentKeys(catalog.apiErrors[DefaultLocale], catalog.apiErrors[SimplifiedChinese])
	return catalog
}

func validateEquivalentKeys(reference, candidate map[string]string) {
	for key, value := range reference {
		if value == "" || candidate[key] == "" {
			panic(fmt.Sprintf("localization catalog key %q is missing or empty", key))
		}
	}
	for key, value := range candidate {
		if value == "" || reference[key] == "" {
			panic(fmt.Sprintf("localization catalog key %q is missing or empty", key))
		}
	}
}
