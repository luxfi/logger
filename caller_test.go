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

	// Verify that runtime frames are properly skipped (Go 1.24+ compatibility)
	if strings.Contains(file, "runtime/asm_") || strings.Contains(file, "/runtime/") {
		t.Fatalf("callerCore failed to skip runtime frames; got %s", file)
	}

	if !strings.HasSuffix(file, "caller_test.go") {
		t.Fatalf("expected caller file to be caller_test.go; got %s", file)
	}
	if strings.Contains(strings.ToLower(file), "log@") {
		t.Fatalf("unexpected module version in caller file path: %s", file)
	}
}

func TestCallerCore_MultipleLogLevels(t *testing.T) {
	// Test that caller information is correct for different log levels
	obsCore, recorded := observer.New(zapcore.DebugLevel)
	core := callerCore{Core: obsCore}
	logger := zap.New(core, zap.AddCaller())

	// Log at different levels
	logger.Debug("debug message")
	logger.Info("info message")
	logger.Warn("warn message")
	logger.Error("error message")

	entries := recorded.All()
	if len(entries) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(entries))
	}

	// All entries should have the correct caller
	for i, ent := range entries {
		if !ent.Caller.Defined {
			t.Errorf("entry %d: expected caller to be defined", i)
			continue
		}

		file := ent.Caller.File
		if strings.Contains(file, "runtime/asm_") || strings.Contains(file, "/runtime/") {
			t.Errorf("entry %d: runtime frames not skipped; got %s", i, file)
		}

		if !strings.HasSuffix(file, "caller_test.go") {
			t.Errorf("entry %d: expected caller_test.go; got %s", i, file)
		}

		// Verify line numbers are different for each log call
		expectedLine := 52 + i // Starting line of logger.Debug call
		if ent.Caller.Line != expectedLine {
			t.Errorf("entry %d: expected line %d, got %d", i, expectedLine, ent.Caller.Line)
		}
	}
}

func TestCallerCore_NestedFunction(t *testing.T) {
	// Test that caller info works correctly when logging from nested functions
	obsCore, recorded := observer.New(zapcore.DebugLevel)
	core := callerCore{Core: obsCore}
	logger := zap.New(core, zap.AddCaller())

	// Helper function that logs
	logHelper := func(msg string) {
		logger.Info(msg)
	}

	// Another level of nesting
	doLogging := func() {
		logHelper("from nested function")
	}

	doLogging()

	entries := recorded.All()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	ent := entries[0]
	if !ent.Caller.Defined {
		t.Fatalf("expected caller to be defined")
	}

	file := ent.Caller.File
	// The caller should still be from this test file (the helper function)
	if !strings.HasSuffix(file, "caller_test.go") {
		t.Fatalf("expected caller_test.go; got %s", file)
	}

	// Should point to the line in logHelper where logger.Info is called
	if ent.Caller.Line != 94 {
		t.Errorf("expected line 94 (logHelper function), got %d", ent.Caller.Line)
	}
}

func TestCallerCore_WithFields(t *testing.T) {
	// Test that caller info is preserved when using With() to add fields
	obsCore, recorded := observer.New(zapcore.DebugLevel)
	core := callerCore{Core: obsCore}
	logger := zap.New(core, zap.AddCaller())

	// Create a logger with fields
	loggerWithFields := logger.With(zap.String("key", "value"))
	loggerWithFields.Info("message with fields")

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
		t.Fatalf("expected caller_test.go; got %s", file)
	}

	// Verify the field was included
	if len(ent.Context) != 1 {
		t.Fatalf("expected 1 field, got %d", len(ent.Context))
	}
	if ent.Context[0].Key != "key" || ent.Context[0].String != "value" {
		t.Errorf("unexpected field: %v", ent.Context[0])
	}
}

func TestCallerCore_RegisterInternalPackages(t *testing.T) {
	// Test that RegisterInternalPackages works correctly

	// First, add a test package to internal packages
	testPkg := "github.com/test/wrapper"
	RegisterInternalPackages(testPkg)

	// Verify it was added
	pkgs := getInternalPkgs()
	found := false
	for _, pkg := range pkgs {
		if pkg == testPkg {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("failed to register internal package %s", testPkg)
	}

	// Test that multiple packages can be registered at once
	RegisterInternalPackages("pkg1", "pkg2", "pkg3")
	pkgs = getInternalPkgs()

	expectedPkgs := []string{"pkg1", "pkg2", "pkg3"}
	for _, expected := range expectedPkgs {
		found := false
		for _, pkg := range pkgs {
			if pkg == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("failed to find registered package %s", expected)
		}
	}
}

func TestCallerCore_RuntimeFrameSkipping(t *testing.T) {
	// Specific test for Go 1.24+ runtime frame handling
	obsCore, recorded := observer.New(zapcore.DebugLevel)
	core := callerCore{Core: obsCore}
	logger := zap.New(core, zap.AddCaller())

	// Use a goroutine to ensure runtime frames are in the stack
	done := make(chan bool)
	go func() {
		logger.Info("from goroutine")
		done <- true
	}()
	<-done

	entries := recorded.All()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	ent := entries[0]
	if !ent.Caller.Defined {
		t.Fatalf("expected caller to be defined")
	}

	file := ent.Caller.File

	// Should never contain runtime paths
	if strings.Contains(file, "/runtime/") {
		t.Fatalf("runtime frame not properly skipped: %s", file)
	}
	if strings.Contains(file, "runtime/asm_") {
		t.Fatalf("runtime assembly frame not properly skipped: %s", file)
	}

	// Should be from this test file
	if !strings.HasSuffix(file, "caller_test.go") {
		t.Fatalf("expected caller_test.go; got %s", file)
	}
}
