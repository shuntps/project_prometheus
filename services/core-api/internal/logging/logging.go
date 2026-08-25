// Package logging builds the structured logger the service writes English
// operational records to. Records never carry credentials or personal data.
package logging

import (
	"io"
	"log/slog"
	"strings"
)

func New(out io.Writer, level string) *slog.Logger {
	handler := slog.NewJSONHandler(out, &slog.HandlerOptions{Level: parseLevel(level)})
	return slog.New(handler)
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
