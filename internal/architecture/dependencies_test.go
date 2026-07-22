package architecture

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/owndock/owndock"

func TestDependencyBoundaries(t *testing.T) {
	root := repositoryRoot(t)
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		imports, err := fileImports(path)
		if err != nil {
			t.Errorf("parse %s: %v", relative, err)
			return nil
		}
		for _, imported := range imports {
			checkImport(t, filepath.ToSlash(relative), imported)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func checkImport(t *testing.T, file, imported string) {
	t.Helper()
	if strings.HasPrefix(file, "internal/platform/") && strings.Contains(imported, modulePath+"/internal/modules/") {
		t.Errorf("%s: platform packages must not import business modules: %s", file, imported)
	}

	domain, isBiz := bizDomain(file)
	if !isBiz {
		return
	}
	for _, forbidden := range []string{
		"github.com/go-kratos/kratos/",
		"go.mongodb.org/mongo-driver/",
		"github.com/docker/docker/",
	} {
		if strings.HasPrefix(imported, forbidden) {
			t.Errorf("%s: biz packages must not import infrastructure package %s", file, imported)
		}
	}
	const modulesPrefix = modulePath + "/internal/modules/"
	if strings.HasPrefix(imported, modulesPrefix) {
		importedDomain := strings.Split(strings.TrimPrefix(imported, modulesPrefix), "/")[0]
		if importedDomain != domain {
			t.Errorf("%s: biz package must not import domain %s directly: %s", file, importedDomain, imported)
		}
	}
}

func bizDomain(file string) (string, bool) {
	parts := strings.Split(file, "/")
	if len(parts) < 5 || parts[0] != "internal" || parts[1] != "modules" || parts[3] != "biz" {
		return "", false
	}
	return parts[2], true
}

func fileImports(path string) ([]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}
	imports := make([]string, 0, len(file.Imports))
	for _, spec := range file.Imports {
		value, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return nil, err
		}
		imports = append(imports, value)
	}
	return imports, nil
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test file")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
