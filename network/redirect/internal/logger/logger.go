package logger

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

const (
	levelEnv  = "LOG_LEVEL"
	formatEnv = "LOG_FORMAT"
)

// Options configures the structured logger.
type Options struct {
	Level  string
	Format string
}

// OptionsFromEnv reads Options from environment variables.
func OptionsFromEnv() Options {
	return Options{
		Level:  os.Getenv(levelEnv),
		Format: os.Getenv(formatEnv),
	}
}

// New creates a configured slog Logger based on the provided options.
func New(opts Options) (*slog.Logger, error) {
	var lvl slog.Level
	switch strings.ToLower(opts.Level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	case "info", "":
		lvl = slog.LevelInfo
	default:
		return nil, fmt.Errorf("unknown log level %q", opts.Level)
	}

	handlerOpts := &slog.HandlerOptions{Level: lvl}
	var handler slog.Handler
	if strings.ToLower(opts.Format) == "json" {
		handler = slog.NewJSONHandler(os.Stdout, handlerOpts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, handlerOpts)
	}
	return slog.New(handler), nil
}

type contextKey struct{}

var loggerKey contextKey

// ContextWithLogger returns a new context containing the provided logger.
func ContextWithLogger(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, l)
}

// FromContext extracts the logger from the context if it exists.
func FromContext(ctx context.Context) (*slog.Logger, bool) {
	l, ok := ctx.Value(loggerKey).(*slog.Logger)
	return l, ok
}
