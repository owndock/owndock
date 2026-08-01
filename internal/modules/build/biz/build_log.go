package biz

import (
	"context"
	"errors"
	"strings"
	"time"
)

const (
	DefaultBuildLogRetention  = 7 * 24 * time.Hour
	DefaultBuildLogMaxBytes   = int64(10 * 1024 * 1024)
	DefaultBuildLogChunkBytes = 16 * 1024
	DefaultBuildLogPageSize   = 100
	MaximumBuildLogPageSize   = 200
)

var (
	ErrInvalidBuildLog      = errors.New("build log is invalid")
	ErrInvalidBuildLogQuery = errors.New("build log query is invalid")
	ErrBuildLogsUnavailable = errors.New("build logs are unavailable")
)

type BuildLogStage string

const (
	BuildLogStageSystem   BuildLogStage = "system"
	BuildLogStageCheckout BuildLogStage = "checkout"
	BuildLogStageBuild    BuildLogStage = "build"
	BuildLogStagePush     BuildLogStage = "push"
	BuildLogStageRelease  BuildLogStage = "release"
)

func (s BuildLogStage) Valid() bool {
	return s == BuildLogStageSystem || s == BuildLogStageCheckout ||
		s == BuildLogStageBuild || s == BuildLogStagePush || s == BuildLogStageRelease
}

type BuildLogAppend struct {
	BuildID   string
	ProjectID string
	Stage     BuildLogStage
	Message   string
	CreatedAt time.Time
}

func (a BuildLogAppend) Validate() error {
	if !validIdentifier(strings.TrimSpace(a.BuildID)) ||
		!validIdentifier(strings.TrimSpace(a.ProjectID)) || !a.Stage.Valid() ||
		strings.TrimSpace(a.Message) == "" || a.CreatedAt.IsZero() {
		return ErrInvalidBuildLog
	}
	return nil
}

type BuildLogEntry struct {
	Sequence  uint64
	Stage     BuildLogStage
	Message   string
	CreatedAt time.Time
}

type BuildLogPage struct {
	Entries      []BuildLogEntry
	NextSequence uint64
	Truncated    bool
	Complete     bool
	ExpiresAt    time.Time
}

type BuildLogQuery struct {
	AfterSequence uint64
	Limit         int
}

func (q BuildLogQuery) Normalize() (BuildLogQuery, error) {
	if q.Limit == 0 {
		q.Limit = DefaultBuildLogPageSize
	}
	if q.Limit < 1 || q.Limit > MaximumBuildLogPageSize {
		return BuildLogQuery{}, ErrInvalidBuildLogQuery
	}
	return q, nil
}

type BuildLogSink func(context.Context, BuildLogStage, string)

type BuildLogWriter interface {
	AppendBuildLog(context.Context, BuildLogAppend) error
}

type BuildLogRepository interface {
	BuildLogWriter
	ReadBuildLogs(context.Context, string, string, BuildLogQuery) (BuildLogPage, error)
}
