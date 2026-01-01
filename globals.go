package log

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Note: zap import retained for init() which uses zapcore types

// Global logger instance used by the package-level functions
var globalLogger Logger

func init() {
	// Initialize with a default logger
	// Create a default zap logger
	config := zap.NewProductionConfig()
	config.DisableStacktrace = true
	config.Encoding = "console"
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	config.EncoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder

	logger, _ := config.Build(
		zap.AddCaller(),
		zap.WrapCore(func(c zapcore.Core) zapcore.Core {
			return callerCore{Core: c}
		}),
	)
	globalLogger = NewZapLogger(logger)
}

// SetGlobalLogger sets the global logger used by package-level functions
func SetGlobalLogger(l Logger) {
	globalLogger = l
}

// Package-level logging functions that match the geth-style API

// Trace logs a message at trace level with context
func Trace(msg string, ctx ...interface{}) {
	globalLogger.Trace(msg, ctx...)
}

// Debug logs a message at debug level with context
func Debug(msg string, ctx ...interface{}) {
	globalLogger.Debug(msg, ctx...)
}

// Info logs a message at info level with context
func Info(msg string, ctx ...interface{}) {
	globalLogger.Info(msg, ctx...)
}

// Warn logs a message at warn level with context
func Warn(msg string, ctx ...interface{}) {
	globalLogger.Warn(msg, ctx...)
}

// Error logs a message at error level with context
func Error(msg string, ctx ...interface{}) {
	globalLogger.Error(msg, ctx...)
}

// Crit logs a message at critical level with context
func Crit(msg string, ctx ...interface{}) {
	globalLogger.Crit(msg, ctx...)
}

// With creates a new logger with the given context
func With(ctx ...interface{}) Logger {
	return globalLogger.With(ctx...)
}

// New creates a new logger with the given context (alias for With)
func New(ctx ...interface{}) Logger {
	return globalLogger.With(ctx...)
}

