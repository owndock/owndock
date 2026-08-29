package data

import (
	"context"
	"strings"
	"testing"

	buildkitclient "github.com/moby/buildkit/client"
	"github.com/opencontainers/go-digest"
	"github.com/owndock/owndock/internal/modules/build/biz"
)

func TestBuildLogRedactorRemovesKnownAndStructuredSecrets(t *testing.T) {
	redactor := newBuildLogRedactor("builder", []byte("super-secret"))
	value := redactor.Redact("https://builder:super-secret@example.test/path?token=abc Authorization: Bearer xyz password=hunter2 API_KEY=\"quoted-value\"")
	for _, forbidden := range []string{"super-secret", "abc", "xyz", "hunter2", "quoted-value", "builder:super-secret"} {
		if strings.Contains(value, forbidden) {
			t.Fatalf("redacted value contains %q: %q", forbidden, value)
		}
	}
}

func TestBuildKitStatusLoggerRedactsSecretSplitAcrossFrames(t *testing.T) {
	var messages []string
	logger := newBuildKitStatusLogger(func(_ context.Context, stage biz.BuildLogStage, message string) {
		if stage != biz.BuildLogStageBuild {
			t.Fatalf("stage = %q", stage)
		}
		messages = append(messages, message)
	}, "builder", []byte("split-secret"))
	vertex := digest.FromString("step")
	statuses := make(chan *buildkitclient.SolveStatus, 2)
	statuses <- &buildkitclient.SolveStatus{Logs: []*buildkitclient.VertexLog{{
		Vertex: vertex, Stream: 1, Data: []byte("token=split-"),
	}}}
	statuses <- &buildkitclient.SolveStatus{Logs: []*buildkitclient.VertexLog{{
		Vertex: vertex, Stream: 1, Data: []byte("secret\n"),
	}}}
	close(statuses)
	logger.Consume(t.Context(), statuses)
	if len(messages) != 1 || strings.Contains(messages[0], "split-secret") ||
		!strings.Contains(messages[0], "[REDACTED]") {
		t.Fatalf("messages = %#v", messages)
	}
}

func TestBuildKitStatusLoggerDetectsEgressPolicyMarkerWithoutPublicLogSink(t *testing.T) {
	logger := newBuildKitStatusLogger(nil, "", nil)
	statuses := make(chan *buildkitclient.SolveStatus, 1)
	statuses <- &buildkitclient.SolveStatus{Logs: []*buildkitclient.VertexLog{{
		Stream: 2, Data: []byte("wget: server returned error: HTTP/1.1 451 Unavailable For Legal Reasons\n"),
	}}}
	close(statuses)
	logger.Consume(t.Context(), statuses)
	if !logger.NetworkDenied() {
		t.Fatal("Build egress policy marker was not detected")
	}
}

func TestSplitBuildLogMessagePreservesUTF8AndBounds(t *testing.T) {
	chunks := splitBuildLogMessage("开始构建镜像", 7)
	if len(chunks) < 2 || strings.Join(chunks, "") != "开始构建镜像" {
		t.Fatalf("chunks = %#v", chunks)
	}
	for _, chunk := range chunks {
		if len([]byte(chunk)) > 7 || strings.ContainsRune(chunk, '�') {
			t.Fatalf("invalid chunk = %q", chunk)
		}
	}
}
