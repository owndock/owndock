package data

import (
	"context"
	"encoding/base64"
	"regexp"
	"sort"
	"strings"
	"unicode"

	buildkitclient "github.com/moby/buildkit/client"
	"github.com/owndock/owndock/internal/modules/build/biz"
)

const maximumBufferedBuildLogLine = 64 * 1024

var (
	buildLogAuthorization = regexp.MustCompile(`(?i)(authorization\s*[:=]\s*)(?:bearer|basic)?\s*[^\s]+`)
	buildLogAssignment    = regexp.MustCompile(`(?i)((?:password|passwd|token|secret|api[_-]?key)\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s]+)`)
	buildLogQuerySecret   = regexp.MustCompile(`(?i)([?&](?:password|passwd|token|secret|api[_-]?key)=)[^&\s]+`)
	buildLogURLUserInfo   = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^/@\s]+@`)
)

type buildLogRedactor struct{ known []string }

func newBuildLogRedactor(username string, secret []byte) buildLogRedactor {
	known := make([]string, 0, 3)
	if value := string(secret); value != "" {
		known = append(known, value)
		if username != "" {
			known = append(known, username+":"+value,
				base64.StdEncoding.EncodeToString([]byte(username+":"+value)))
		}
	}
	sort.Slice(known, func(i, j int) bool { return len(known[i]) > len(known[j]) })
	return buildLogRedactor{known: known}
}

func (r buildLogRedactor) Redact(value string) string {
	value = strings.ToValidUTF8(value, "�")
	for _, secret := range r.known {
		value = strings.ReplaceAll(value, secret, "[REDACTED]")
	}
	value = buildLogURLUserInfo.ReplaceAllString(value, `${1}[REDACTED]@`)
	value = buildLogQuerySecret.ReplaceAllString(value, `${1}[REDACTED]`)
	value = buildLogAuthorization.ReplaceAllString(value, `${1}[REDACTED]`)
	value = buildLogAssignment.ReplaceAllString(value, `${1}[REDACTED]`)
	var builder strings.Builder
	builder.Grow(len(value))
	for _, character := range value {
		if character == '\t' || !unicode.IsControl(character) {
			builder.WriteRune(character)
		}
	}
	return strings.TrimSpace(builder.String())
}

type buildKitStatusLogger struct {
	sink          biz.BuildLogSink
	redactor      buildLogRedactor
	buffers       map[string][]byte
	discarding    map[string]bool
	stages        map[string]biz.BuildLogStage
	started       map[string]bool
	networkDenied bool
}

func newBuildKitStatusLogger(sink biz.BuildLogSink, username string, secret []byte) *buildKitStatusLogger {
	return &buildKitStatusLogger{
		sink: sink, redactor: newBuildLogRedactor(username, secret),
		buffers: make(map[string][]byte), discarding: make(map[string]bool),
		stages: make(map[string]biz.BuildLogStage), started: make(map[string]bool),
	}
}

func (l *buildKitStatusLogger) Consume(ctx context.Context, statuses <-chan *buildkitclient.SolveStatus) {
	for status := range statuses {
		if status == nil {
			continue
		}
		for _, vertex := range status.Vertexes {
			if vertex == nil {
				continue
			}
			key := vertex.Digest.String()
			stage := buildLogStageForVertex(vertex.Name)
			l.stages[key] = stage
			if vertex.Started != nil && !l.started[key] {
				l.started[key] = true
				l.emit(ctx, stage, vertex.Name)
			}
			if vertex.Error != "" {
				l.emit(ctx, stage, vertex.Error)
			}
		}
		for _, log := range status.Logs {
			if log != nil {
				l.consumeBytes(ctx, log.Vertex.String()+":"+string(rune(log.Stream)),
					l.stages[log.Vertex.String()], log.Data)
			}
		}
		for _, warning := range status.Warnings {
			if warning != nil {
				l.emit(ctx, l.stages[warning.Vertex.String()], string(warning.Short))
			}
		}
	}
	for key, buffer := range l.buffers {
		if len(buffer) > 0 && !l.discarding[key] {
			l.emit(ctx, biz.BuildLogStageBuild, string(buffer))
		}
	}
}

func (l *buildKitStatusLogger) consumeBytes(ctx context.Context, key string,
	stage biz.BuildLogStage, data []byte) {
	if !stage.Valid() {
		stage = biz.BuildLogStageBuild
	}
	for len(data) > 0 {
		newline := -1
		for index, value := range data {
			if value == '\n' {
				newline = index
				break
			}
		}
		if l.discarding[key] {
			if newline < 0 {
				return
			}
			l.discarding[key] = false
			data = data[newline+1:]
			continue
		}
		if newline >= 0 {
			l.buffers[key] = append(l.buffers[key], data[:newline]...)
			l.emit(ctx, stage, string(l.buffers[key]))
			l.buffers[key] = l.buffers[key][:0]
			data = data[newline+1:]
			continue
		}
		l.buffers[key] = append(l.buffers[key], data...)
		if len(l.buffers[key]) > maximumBufferedBuildLogLine {
			l.emit(ctx, stage, string(l.buffers[key][:maximumBufferedBuildLogLine])+" [line truncated]")
			l.buffers[key] = l.buffers[key][:0]
			l.discarding[key] = true
		}
		return
	}
}

func (l *buildKitStatusLogger) emit(ctx context.Context, stage biz.BuildLogStage, value string) {
	if strings.Contains(strings.ToLower(value), "451 unavailable for legal reasons") {
		l.networkDenied = true
	}
	if l.sink == nil {
		return
	}
	if !stage.Valid() {
		stage = biz.BuildLogStageBuild
	}
	if value = l.redactor.Redact(value); value != "" {
		l.sink(ctx, stage, value)
	}
}

func (l *buildKitStatusLogger) NetworkDenied() bool { return l.networkDenied }

func buildLogStageForVertex(name string) biz.BuildLogStage {
	lower := strings.ToLower(name)
	if strings.Contains(lower, "export") || strings.Contains(lower, "push") ||
		strings.Contains(lower, "manifest") {
		return biz.BuildLogStagePush
	}
	return biz.BuildLogStageBuild
}
