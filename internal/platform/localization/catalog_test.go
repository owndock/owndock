package localization

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestAPIErrorUsesNegotiatedCatalog(t *testing.T) {
	ctx := WithLocale(context.Background(), SimplifiedChinese)
	locale, message := APIError(ctx, "invalid_json")
	if locale != SimplifiedChinese {
		t.Fatalf("locale = %q", locale)
	}
	if message != "请求正文必须是有效的 JSON" {
		t.Fatalf("message = %q", message)
	}
}

func TestAPIErrorUnknownCodeUsesLocalizedSafeFallback(t *testing.T) {
	ctx := WithLocale(context.Background(), SimplifiedChinese)
	_, message := APIError(ctx, "unknown_internal_detail")
	if message != "请求失败" {
		t.Fatalf("message = %q", message)
	}
}

func TestCatalogsHaveEquivalentKeys(t *testing.T) {
	english := defaultCatalog.apiErrors[EnglishUS]
	chinese := defaultCatalog.apiErrors[SimplifiedChinese]
	if len(english) != len(chinese) {
		t.Fatalf("catalog sizes differ: en-US=%d zh-CN=%d", len(english), len(chinese))
	}
	for key, message := range english {
		if message == "" || chinese[key] == "" {
			t.Fatalf("catalog key %q is missing or empty", key)
		}
	}
}

func TestEveryStaticAPIErrorCodeHasTranslations(t *testing.T) {
	const internalRoot = "../.."
	used := make(map[string]string)
	err := fs.WalkDir(os.DirFS(internalRoot), ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), internalRoot+"/"+path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "ErrorRequest" {
				return true
			}
			literal, ok := call.Args[len(call.Args)-1].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			code, err := strconv.Unquote(literal.Value)
			if err == nil {
				used[code] = path
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for code, path := range used {
		for _, locale := range supportedLocales {
			if defaultCatalog.apiErrors[locale][code] == "" {
				t.Errorf("%s uses API error code %q with no %s translation", path, code, locale)
			}
		}
	}
}
