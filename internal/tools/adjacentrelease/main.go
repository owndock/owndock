package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"golang.org/x/mod/semver"
)

const maximumTagLength = 65

var (
	validReleaseTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
	errInvalidInput = errors.New("adjacent release input is invalid")
)

func main() {
	current := flag.String("current", "", "current v-prefixed SemVer release tag")
	requireNewest := flag.Bool("require-newest", false, "reject a current tag that is not newer than every published tag")
	flag.Parse()
	if flag.NArg() != 0 {
		_, _ = fmt.Fprintln(os.Stderr, errInvalidInput)
		os.Exit(1)
	}
	previous, err := selectPrevious(*current, os.Stdin, *requireNewest)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if previous != "" {
		_, _ = fmt.Fprintln(os.Stdout, previous)
	}
}

func selectPrevious(current string, input io.Reader, requireNewest bool) (string, error) {
	if !validTag(current) {
		return "", errInvalidInput
	}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 1024), 128*1024)
	previous := ""
	count := 0
	for scanner.Scan() {
		count++
		if count > 1000 {
			return "", errInvalidInput
		}
		candidate := strings.TrimSpace(scanner.Text())
		if !validTag(candidate) {
			continue
		}
		comparison := semver.Compare(candidate, current)
		if requireNewest && comparison >= 0 {
			return "", fmt.Errorf("%w: current tag must be newer than %s", errInvalidInput, candidate)
		}
		if comparison < 0 && (previous == "" || semver.Compare(candidate, previous) > 0) {
			previous = candidate
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("%w: read tags", errInvalidInput)
	}
	return previous, nil
}

func validTag(value string) bool {
	return len(value) <= maximumTagLength && validReleaseTag.MatchString(value) && semver.IsValid(value)
}
