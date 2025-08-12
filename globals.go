package log

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

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

// Legacy V-level logging functions for geth compatibility

// Trace0 logs a message at trace level
func Trace0(msg string) {
	globalLogger.Trace(msg)
}

// Debug0 logs a message at debug level
func Debug0(msg string) {
	globalLogger.Debug(msg)
}

// Info0 logs a message at info level
func Info0(msg string) {
	globalLogger.Info(msg)
}

// Warn0 logs a message at warn level
func Warn0(msg string) {
	globalLogger.Warn(msg)
}

// Error0 logs a message at error level
func Error0(msg string) {
	globalLogger.Error(msg)
}

// Crit0 logs a message at critical level
func Crit0(msg string) {
	globalLogger.Crit(msg)
}

// Additional functions for zap field compatibility

// TraceF logs a message at trace level with zap fields
func TraceF(msg string, fields ...zap.Field) {
	if zl, ok := globalLogger.(*zapLogger); ok {
		zl.logger.Debug(msg, fields...) // Map trace to debug in zap
	}
}

// DebugF logs a message at debug level with zap fields
func DebugF(msg string, fields ...zap.Field) {
	if zl, ok := globalLogger.(*zapLogger); ok {
		zl.logger.Debug(msg, fields...)
	}
}

// InfoF logs a message at info level with zap fields
func InfoF(msg string, fields ...zap.Field) {
	if zl, ok := globalLogger.(*zapLogger); ok {
		zl.logger.Info(msg, fields...)
	}
}

// WarnF logs a message at warn level with zap fields
func WarnF(msg string, fields ...zap.Field) {
	if zl, ok := globalLogger.(*zapLogger); ok {
		zl.logger.Warn(msg, fields...)
	}
}

// ErrorF logs a message at error level with zap fields
func ErrorF(msg string, fields ...zap.Field) {
	if zl, ok := globalLogger.(*zapLogger); ok {
		zl.logger.Error(msg, fields...)
	}
}

// CritF logs a message at critical level with zap fields
func CritF(msg string, fields ...zap.Field) {
	if zl, ok := globalLogger.(*zapLogger); ok {
		zl.logger.Fatal(msg, fields...)
	}
}
