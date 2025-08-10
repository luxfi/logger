package log

import (
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestCallerCore_UsesExternalFrame(t *testing.T) {
	// Build an observed core at debug level and wrap it with callerCore.
	obsCore, recorded := observer.New(zapcore.DebugLevel)
	core := callerCore{Core: obsCore}
	// Use zap.AddCaller() to enable caller tracking
	logger := zap.New(core, zap.AddCaller())

	// Log from THIS test file; the caller should be this file, not logger.go in this package.
	logger.Info("hello, world")

	entries := recorded.All()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	ent := entries[0]
	if !ent.Caller.Defined {
		t.Fatalf("expected caller to be defined")
	}
	file := ent.Caller.File

	if !strings.HasSuffix(file, "caller_test.go") {
		t.Fatalf("expected caller file to be caller_test.go; got %s", file)
	}
	if strings.Contains(strings.ToLower(file), "log@") {
		t.Fatalf("unexpected module version in caller file path: %s", file)
	}
}