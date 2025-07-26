package log

// Field is a key/value pair for structured logging.
type Field struct {
	Key   string
	Value any
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
