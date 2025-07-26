package log

import "log/slog"

// Level is the level for logging.
type Level = slog.Level

// Field is a key/value pair for structured logging.
type Field struct {
	Key   string
	Value any
}

// Factory produces loggers.
type Factory interface {
	// New returns a new Logger with the given name.
	New(name string) Logger

	// NewWithFields returns a new Logger with the given name and initial fields.
	NewWithFields(name string, fields ...Field) Logger

	// Root returns the root Logger from this factory.
	Root() Logger
}

// Level aliases for convenience.
const (
	// DebugLevel logs debug messages.
	DebugLevel = LevelDebug

	// InfoLevel logs informational messages.
	InfoLevel = LevelInfo

	// WarnLevel logs warning messages.
	WarnLevel = LevelWarn

	// ErrorLevel logs error messages.
	ErrorLevel = LevelError

	// FatalLevel logs critical messages and exits.
	FatalLevel = LevelCrit
)
