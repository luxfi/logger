package log

import (
	"testing"
)

// SetDefault should properly set the default logger when custom loggers are
// provided.
func TestSetDefaultCustomLogger(t *testing.T) {
	// Save original logger to restore after test
	originalLogger := Root()
	defer SetDefault(originalLogger)

	type customLogger struct {
		Logger // Implement the Logger interface
	}

	customLog := &customLogger{Logger: originalLogger}
	SetDefault(customLog)
	if Root() != customLog {
		t.Error("expected custom logger to be set as default")
	}
}
