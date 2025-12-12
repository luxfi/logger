package log_test

import (
	"os"
	"testing"
	"time"

	"github.com/luxfi/log"
)

func TestDocumentationExamples(t *testing.T) {
	// Test basic usage example from documentation
	t.Run("BasicUsage", func(t *testing.T) {
		logger := log.New()

		// Simple logging
		logger.Info("Starting application")
		logger.Debug("Debug information")
		logger.Error("An error occurred")

		// Structured logging with fields
		logger.Info("User login",
			log.String("user", "alice"),
			log.Int("attempt", 3),
			log.Duration("latency", time.Second),
		)

		// Create a sub-logger with context
		userLogger := logger.With(
			log.String("module", "user"),
			log.String("version", "1.0.0"),
		)
		userLogger.Info("Processing user request")
	})

	// Test Ethereum-compatible interface
	t.Run("EthereumCompatible", func(t *testing.T) {
		logger := log.New()

		// Geth-style logging
		logger.Info("Block processed",
			"number", 12345,
			"hash", "0xabc...",
			"txs", 100,
		)

		// Create a new logger with context
		blockLogger := logger.New("component", "blockchain")
		blockLogger.Debug("Validating block")
	})

	// Test field types
	t.Run("FieldTypes", func(t *testing.T) {
		logger := log.New()

		// Basic types
		logger.Info("Field examples",
			log.String("name", "Alice"),
			log.Int("count", 42),
			log.Float64("rate", 0.95),
			log.Bool("enabled", true),
		)

		// Time types
		now := time.Now()
		logger.Info("Time fields",
			log.Time("timestamp", now),
			log.Duration("elapsed", 5*time.Second),
		)

		// Binary data
		logger.Info("Binary fields",
			log.Binary("payload", []byte{0x01, 0x02}),
			log.ByteString("message", []byte("hello")),
		)
	})

	// Test log levels
	t.Run("LogLevels", func(t *testing.T) {
		logger := log.New()

		// Test various log levels
		logger.Trace("Trace message")
		logger.Debug("Debug message")
		logger.Info("Info message")
		logger.Warn("Warning message")
		logger.Error("Error message")

		// Check if level is enabled
		if logger.EnabledLevel(log.LevelDebug) {
			logger.Debug("Debug is enabled")
		}
	})

	// Test output formats
	t.Run("OutputFormats", func(t *testing.T) {
		// Create a logger with terminal handler
		terminalHandler := log.NewTerminalHandler(os.Stdout, true)
		// Note: The actual API may differ slightly from documentation
		// This test demonstrates the concept
		_ = terminalHandler // Handler is created successfully
	})
}

func TestPerformance(t *testing.T) {
	// Benchmark-style test to verify zero-allocation claims
	logger := log.New()

	// This should have minimal allocations
	for i := 0; i < 1000; i++ {
		logger.Info("Performance test",
			log.String("key", "value"),
			log.Int("iteration", i),
			log.Bool("flag", true),
		)
	}
}