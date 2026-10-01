package architecture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Docker images can declare anonymous volumes without the test asking for one.
// Removing only the container leaves those volumes behind, which is especially
// costly for the Docker-in-Docker fixture because /var/lib/docker is a volume.
func TestDockerContainerCleanupRemovesAnonymousVolumes(t *testing.T) {
	root := repositoryRoot(t)
	self := filepath.Join("internal", "architecture", "docker_cleanup_test.go")
	allowedExtensions := map[string]bool{
		".go": true, ".sh": true, ".yaml": true, ".yml": true,
	}
	shellCleanup := strings.Join([]string{"docker", " rm"}, "")
	directCleanup := strings.Join([]string{"\"docker\"", ", \"rm\""}, "")
	helperCleanup := strings.Join([]string{"dockerCommand(", "\"rm\""}, "")

	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "bin", "vendor":
				return filepath.SkipDir
			default:
				return nil
			}
		}
		if !allowedExtensions[filepath.Ext(path)] {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if filepath.Clean(relative) == self {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for number, line := range strings.Split(string(content), "\n") {
			isContainerCleanup := strings.Contains(line, shellCleanup) ||
				strings.Contains(line, directCleanup) || strings.Contains(line, helperCleanup)
			if isContainerCleanup && !strings.Contains(line, "--volumes") &&
				!strings.Contains(line, " -v ") {
				t.Errorf("%s:%d: Docker container cleanup must remove anonymous volumes", filepath.ToSlash(relative), number+1)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
