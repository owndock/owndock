// changedcoverage enforces statement coverage only for executable Go code
// added or modified relative to an immutable Git commit.
package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

const defaultThreshold = 80.0

var (
	hunkPattern = regexp.MustCompile(
		`^@@ -[0-9]+(?:,[0-9]+)? \+([0-9]+)(?:,([0-9]+))? @@`,
	)
	profilePattern = regexp.MustCompile(
		`^(.+):([0-9]+)\.([0-9]+),([0-9]+)\.([0-9]+) ([0-9]+) ([0-9]+)$`,
	)
)

type lineSet map[string]map[int]struct{}

type coverageBlock struct {
	path                   string
	startLine, startColumn int
	endLine, endColumn     int
	statements             int
	covered                bool
}

type fileReport struct {
	path                 string
	covered, statements  int
	uncoveredChangedLine []int
}

type report struct {
	covered, statements int
	files               []fileReport
}

type exclusion struct {
	path       string
	reviewDate time.Time
	reason     string
}

type stringList []string

func (values *stringList) String() string {
	return strings.Join(*values, ",")
}

func (values *stringList) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("profile path is empty")
	}
	*values = append(*values, value)
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "changed coverage:", err)
		os.Exit(1)
	}
}

func run(arguments []string, output *os.File) error {
	flags := flag.NewFlagSet("changedcoverage", flag.ContinueOnError)
	flags.SetOutput(output)
	var base, root, exclusionFile string
	var profiles stringList
	var threshold float64
	flags.StringVar(&base, "base", "", "immutable base Git revision")
	flags.Var(&profiles, "profile", "Go cover profile; repeat to merge profiles")
	flags.StringVar(&root, "root", ".", "repository root")
	flags.StringVar(
		&exclusionFile,
		"exclude-file",
		"",
		"tab-separated path, review date, and reason file",
	)
	flags.Float64Var(
		&threshold,
		"threshold",
		defaultThreshold,
		"minimum changed statement coverage percentage",
	)
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("arguments are invalid")
	}
	if strings.TrimSpace(base) == "" || len(profiles) == 0 ||
		threshold < 0 || threshold > 100 {
		return errors.New("base, profile, and a threshold from 0 to 100 are required")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve repository root: %w", err)
	}
	baseCommit, err := resolveBaseCommit(root, base)
	if err != nil {
		return err
	}
	changed, err := changedGoLines(root, baseCommit)
	if err != nil {
		return err
	}
	module, err := readModulePath(root)
	if err != nil {
		return err
	}
	var profileBlocks [][]coverageBlock
	for _, profile := range profiles {
		blocks, profileErr := readCoverageProfile(profile, root, module)
		if profileErr != nil {
			return profileErr
		}
		profileBlocks = append(profileBlocks, blocks)
	}
	blocks, err := mergeCoverageBlocks(profileBlocks...)
	if err != nil {
		return err
	}
	exclusions, err := readExclusions(exclusionFile, root, time.Now().UTC())
	if err != nil {
		return err
	}
	result, err := buildReport(root, changed, blocks, exclusions)
	if err != nil {
		return err
	}
	if result.statements == 0 {
		_, _ = fmt.Fprintln(
			output,
			"changed coverage: no changed executable Go statements",
		)
		return nil
	}
	percentage := 100 * float64(result.covered) / float64(result.statements)
	_, _ = fmt.Fprintf(
		output,
		"changed coverage: %.1f%% (%d/%d statements across %d files)\n",
		percentage,
		result.covered,
		result.statements,
		len(result.files),
	)
	for _, file := range result.files {
		_, _ = fmt.Fprintf(
			output,
			"  %s: %d/%d",
			file.path,
			file.covered,
			file.statements,
		)
		if len(file.uncoveredChangedLine) != 0 {
			_, _ = fmt.Fprintf(
				output,
				"; uncovered changed lines %s",
				joinLines(file.uncoveredChangedLine),
			)
		}
		_, _ = fmt.Fprintln(output)
	}
	if percentage+0.000001 < threshold {
		return fmt.Errorf(
			"%.1f%% is below the required %.1f%%",
			percentage,
			threshold,
		)
	}
	return nil
}

func mergeCoverageBlocks(groups ...[]coverageBlock) ([]coverageBlock, error) {
	blocks := make(map[string]coverageBlock)
	for _, group := range groups {
		for _, candidate := range group {
			key := fmt.Sprintf(
				"%s:%d.%d,%d.%d",
				candidate.path,
				candidate.startLine,
				candidate.startColumn,
				candidate.endLine,
				candidate.endColumn,
			)
			current := blocks[key]
			if current.path != "" && current.statements != candidate.statements {
				return nil, errors.New("coverage profiles contain conflicting blocks")
			}
			if current.path == "" {
				current = candidate
			}
			current.covered = current.covered || candidate.covered
			blocks[key] = current
		}
	}
	result := make([]coverageBlock, 0, len(blocks))
	for _, block := range blocks {
		result = append(result, block)
	}
	slices.SortFunc(result, func(left, right coverageBlock) int {
		if value := strings.Compare(left.path, right.path); value != 0 {
			return value
		}
		if left.startLine != right.startLine {
			return left.startLine - right.startLine
		}
		if left.startColumn != right.startColumn {
			return left.startColumn - right.startColumn
		}
		if left.endLine != right.endLine {
			return left.endLine - right.endLine
		}
		return left.endColumn - right.endColumn
	})
	return result, nil
}

func resolveBaseCommit(root, revision string) (string, error) {
	command := exec.Command(
		"git", "rev-parse", "--verify", strings.TrimSpace(revision)+"^{commit}",
	)
	command.Dir = root
	value, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("resolve coverage base commit: %w", err)
	}
	commit := strings.TrimSpace(string(value))
	if len(commit) != 40 && len(commit) != 64 {
		return "", errors.New("coverage base did not resolve to a full commit ID")
	}
	for _, character := range commit {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return "", errors.New("coverage base commit ID is invalid")
		}
	}
	return commit, nil
}

func changedGoLines(root, baseCommit string) (lineSet, error) {
	command := exec.Command(
		"git", "-c", "core.quotepath=false", "diff", "--unified=0",
		"--no-color", "--no-ext-diff", "--no-renames", "--diff-filter=ACMR",
		baseCommit, "--",
	)
	command.Dir = root
	diff, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("read changed lines: %w", err)
	}
	changed, err := parseUnifiedDiff(diff)
	if err != nil {
		return nil, err
	}
	command = exec.Command(
		"git", "ls-files", "--others", "--exclude-standard", "-z", "--",
	)
	command.Dir = root
	untracked, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("list untracked files: %w", err)
	}
	for _, encodedPath := range bytes.Split(untracked, []byte{0}) {
		path := filepath.ToSlash(string(encodedPath))
		if path == "" || !strings.HasSuffix(path, ".go") {
			continue
		}
		value, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if readErr != nil {
			return nil, fmt.Errorf("read untracked Go file %s: %w", path, readErr)
		}
		lineCount := bytes.Count(value, []byte{'\n'})
		if len(value) != 0 && value[len(value)-1] != '\n' {
			lineCount++
		}
		for line := 1; line <= lineCount; line++ {
			addChangedLine(changed, path, line)
		}
	}
	return changed, nil
}

func parseUnifiedDiff(value []byte) (lineSet, error) {
	changed := make(lineSet)
	var currentPath string
	scanner := bufio.NewScanner(bytes.NewReader(value))
	scanner.Buffer(make([]byte, 4096), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "+++ ") {
			path, err := decodeDiffPath(strings.TrimPrefix(line, "+++ "))
			if err != nil {
				return nil, err
			}
			currentPath = path
			continue
		}
		matches := hunkPattern.FindStringSubmatch(line)
		if matches == nil || currentPath == "" ||
			!strings.HasSuffix(currentPath, ".go") {
			continue
		}
		start, _ := strconv.Atoi(matches[1])
		count := 1
		if matches[2] != "" {
			count, _ = strconv.Atoi(matches[2])
		}
		for offset := 0; offset < count; offset++ {
			addChangedLine(changed, currentPath, start+offset)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse Git diff: %w", err)
	}
	return changed, nil
}

func decodeDiffPath(value string) (string, error) {
	if value == "/dev/null" {
		return "", nil
	}
	if strings.HasPrefix(value, "\"") {
		decoded, err := strconv.Unquote(value)
		if err != nil {
			return "", errors.New("Git diff contains an invalid quoted path")
		}
		value = decoded
	}
	value = strings.TrimPrefix(value, "b/")
	value = filepath.ToSlash(filepath.Clean(value))
	if value == "." || strings.HasPrefix(value, "../") || filepath.IsAbs(value) {
		return "", errors.New("Git diff contains an unsafe path")
	}
	return value, nil
}

func addChangedLine(changed lineSet, path string, line int) {
	if line < 1 || path == "" {
		return
	}
	if changed[path] == nil {
		changed[path] = make(map[int]struct{})
	}
	changed[path][line] = struct{}{}
}

func readModulePath(root string) (string, error) {
	value, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return "", fmt.Errorf("read go.mod: %w", err)
	}
	for _, line := range strings.Split(string(value), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "module" && fields[1] != "" {
			return fields[1], nil
		}
	}
	return "", errors.New("go.mod module path is missing")
}

func readCoverageProfile(
	path, root, module string,
) ([]coverageBlock, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open coverage profile: %w", err)
	}
	defer func() { _ = file.Close() }()
	blocks := make(map[string]coverageBlock)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 4*1024*1024)
	first := true
	for scanner.Scan() {
		line := scanner.Text()
		if first {
			first = false
			if !strings.HasPrefix(line, "mode: ") {
				return nil, errors.New("coverage profile header is invalid")
			}
			continue
		}
		matches := profilePattern.FindStringSubmatch(line)
		if matches == nil {
			return nil, errors.New("coverage profile entry is invalid")
		}
		startLine, _ := strconv.Atoi(matches[2])
		startColumn, _ := strconv.Atoi(matches[3])
		endLine, _ := strconv.Atoi(matches[4])
		endColumn, _ := strconv.Atoi(matches[5])
		statements, _ := strconv.Atoi(matches[6])
		count, _ := strconv.ParseUint(matches[7], 10, 64)
		profilePath := normalizeProfilePath(matches[1], root, module)
		if profilePath == "" || startLine < 1 || endLine < startLine ||
			statements < 0 {
			return nil, errors.New("coverage profile entry is invalid")
		}
		// The Go coverage writer can emit zero-statement regions for empty
		// generic/function boundaries. They are valid profile records but do
		// not represent executable code and must not affect the denominator.
		if statements == 0 {
			continue
		}
		key := fmt.Sprintf(
			"%s:%s.%s,%s.%s",
			profilePath, matches[2], matches[3], matches[4], matches[5],
		)
		block := blocks[key]
		if block.path != "" && block.statements != statements {
			return nil, errors.New("coverage profile contains conflicting blocks")
		}
		block.path = profilePath
		block.startLine = startLine
		block.startColumn = startColumn
		block.endLine = endLine
		block.endColumn = endColumn
		block.statements = statements
		block.covered = block.covered || count > 0
		blocks[key] = block
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read coverage profile: %w", err)
	}
	if first {
		return nil, errors.New("coverage profile is empty")
	}
	result := make([]coverageBlock, 0, len(blocks))
	for _, block := range blocks {
		result = append(result, block)
	}
	slices.SortFunc(result, func(left, right coverageBlock) int {
		if value := strings.Compare(left.path, right.path); value != 0 {
			return value
		}
		if left.startLine != right.startLine {
			return left.startLine - right.startLine
		}
		if left.startColumn != right.startColumn {
			return left.startColumn - right.startColumn
		}
		if left.endLine != right.endLine {
			return left.endLine - right.endLine
		}
		return left.endColumn - right.endColumn
	})
	return result, nil
}

func normalizeProfilePath(value, root, module string) string {
	value = filepath.ToSlash(value)
	root = filepath.ToSlash(root)
	switch {
	case strings.HasPrefix(value, module+"/"):
		value = strings.TrimPrefix(value, module+"/")
	case strings.HasPrefix(value, root+"/"):
		value = strings.TrimPrefix(value, root+"/")
	default:
		value = strings.TrimPrefix(value, "./")
	}
	value = filepath.ToSlash(filepath.Clean(value))
	if value == "." || strings.HasPrefix(value, "../") || filepath.IsAbs(value) {
		return ""
	}
	return value
}

func buildReport(
	root string,
	changed lineSet,
	blocks []coverageBlock,
	exclusions []exclusion,
) (report, error) {
	eligible := make(map[string]bool)
	lines := make(map[string][]int)
	for path, values := range changed {
		if excluded(path, exclusions) {
			continue
		}
		allowed, err := eligibleGoFile(root, path)
		if err != nil {
			return report{}, err
		}
		eligible[path] = allowed
		if !allowed {
			continue
		}
		for line := range values {
			lines[path] = append(lines[path], line)
		}
		slices.Sort(lines[path])
	}
	profileFiles := make(map[string]struct{})
	for _, block := range blocks {
		profileFiles[block.path] = struct{}{}
	}
	for path, allowed := range eligible {
		if !allowed {
			continue
		}
		if _, exists := profileFiles[path]; !exists {
			executable, err := hasExecutableStatements(root, path)
			if err != nil {
				return report{}, err
			}
			if !executable {
				continue
			}
			return report{}, fmt.Errorf(
				"changed Go file %s is absent from every coverage profile",
				path,
			)
		}
	}
	byFile := make(map[string]*fileReport)
	for _, block := range blocks {
		if !eligible[block.path] ||
			!intersectsChangedLine(
				lines[block.path], block.startLine, block.endLine,
			) {
			continue
		}
		file := byFile[block.path]
		if file == nil {
			file = &fileReport{path: block.path}
			byFile[block.path] = file
		}
		file.statements += block.statements
		if block.covered {
			file.covered += block.statements
		} else if line := firstChangedLine(
			lines[block.path], block.startLine, block.endLine,
		); line != 0 {
			file.uncoveredChangedLine = append(
				file.uncoveredChangedLine,
				line,
			)
		}
	}
	result := report{}
	for _, file := range byFile {
		slices.Sort(file.uncoveredChangedLine)
		file.uncoveredChangedLine = slices.Compact(file.uncoveredChangedLine)
		result.covered += file.covered
		result.statements += file.statements
		result.files = append(result.files, *file)
	}
	slices.SortFunc(result.files, func(left, right fileReport) int {
		return strings.Compare(left.path, right.path)
	})
	return result, nil
}

func hasExecutableStatements(root, path string) (bool, error) {
	parsed, err := parser.ParseFile(
		token.NewFileSet(),
		filepath.Join(root, filepath.FromSlash(path)),
		nil,
		parser.SkipObjectResolution,
	)
	if err != nil {
		return false, fmt.Errorf("parse changed Go file %s: %w", path, err)
	}
	executable := false
	ast.Inspect(parsed, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.FuncDecl:
			if value.Body != nil && len(value.Body.List) != 0 {
				executable = true
				return false
			}
		case *ast.FuncLit:
			if value.Body != nil && len(value.Body.List) != 0 {
				executable = true
				return false
			}
		}
		return !executable
	})
	return executable, nil
}

func readExclusions(path, root string, now time.Time) ([]exclusion, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open changed coverage exclusions: %w", err)
	}
	defer func() { _ = file.Close() }()
	var result []exclusion
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 3 {
			return nil, fmt.Errorf(
				"changed coverage exclusion line %d must contain path, review date, and reason",
				lineNumber,
			)
		}
		excludedPath := filepath.ToSlash(strings.TrimSpace(fields[0]))
		isPrefix := strings.HasSuffix(excludedPath, "/")
		excludedPath = filepath.ToSlash(filepath.Clean(excludedPath))
		if isPrefix {
			excludedPath += "/"
		}
		if excludedPath == "." || strings.HasPrefix(excludedPath, "../") ||
			filepath.IsAbs(excludedPath) {
			return nil, fmt.Errorf(
				"changed coverage exclusion line %d contains an unsafe path",
				lineNumber,
			)
		}
		if _, duplicate := seen[excludedPath]; duplicate {
			return nil, fmt.Errorf(
				"changed coverage exclusion line %d duplicates %s",
				lineNumber,
				excludedPath,
			)
		}
		reviewDate, parseErr := time.Parse(
			"2006-01-02",
			strings.TrimSpace(fields[1]),
		)
		reason := strings.TrimSpace(fields[2])
		if parseErr != nil || reason == "" || len(reason) > 240 {
			return nil, fmt.Errorf(
				"changed coverage exclusion line %d has an invalid review date or reason",
				lineNumber,
			)
		}
		if reviewDate.Before(midnightUTC(now)) {
			return nil, fmt.Errorf(
				"changed coverage exclusion %s expired on %s",
				excludedPath,
				reviewDate.Format("2006-01-02"),
			)
		}
		seen[excludedPath] = struct{}{}
		result = append(result, exclusion{
			path: excludedPath, reviewDate: reviewDate, reason: reason,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read changed coverage exclusions: %w", err)
	}
	return result, nil
}

func midnightUTC(value time.Time) time.Time {
	value = value.UTC()
	return time.Date(value.Year(), value.Month(), value.Day(), 0, 0, 0, 0, time.UTC)
}

func excluded(path string, exclusions []exclusion) bool {
	for _, value := range exclusions {
		if strings.HasSuffix(value.path, "/") {
			if strings.HasPrefix(path, value.path) {
				return true
			}
		} else if path == value.path {
			return true
		}
	}
	return false
}

func eligibleGoFile(root, path string) (bool, error) {
	if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
		return false, nil
	}
	value, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read changed Go file %s: %w", path, err)
	}
	for index, line := range strings.Split(string(value), "\n") {
		if index >= 10 {
			break
		}
		if strings.HasPrefix(line, "// Code generated ") &&
			strings.HasSuffix(line, " DO NOT EDIT.") {
			return false, nil
		}
	}
	return true, nil
}

func intersectsChangedLine(lines []int, start, end int) bool {
	return firstChangedLine(lines, start, end) != 0
}

func firstChangedLine(lines []int, start, end int) int {
	index, _ := slices.BinarySearch(lines, start)
	if index < len(lines) && lines[index] <= end {
		return lines[index]
	}
	return 0
}

func joinLines(lines []int) string {
	values := make([]string, len(lines))
	for index, line := range lines {
		values[index] = strconv.Itoa(line)
	}
	return strings.Join(values, ",")
}
