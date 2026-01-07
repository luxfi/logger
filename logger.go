package log

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/luxfi/log/level"
)

// Level constants aligned with zapcore.Level and level.Level for consistency
// There is one and exactly one way to represent each level across all systems
const (
	// LevelVerbo is the most verbose level (below debug)
	LevelVerbo slog.Level = -2
	// LevelTrace maps to debug (zap doesn't have trace)
	LevelTrace slog.Level = -1
	// LevelDebug matches slog.LevelDebug and zapcore.DebugLevel
	LevelDebug = slog.LevelDebug // -4 in slog, but we use -1 for zap compatibility
	// LevelInfo matches slog.LevelInfo and zapcore.InfoLevel
	LevelInfo = slog.LevelInfo // 0
	// LevelWarn matches slog.LevelWarn and zapcore.WarnLevel
	LevelWarn = slog.LevelWarn // 4
	// LevelError matches slog.LevelError and zapcore.ErrorLevel
	LevelError = slog.LevelError // 8
	// LevelCrit is for critical errors
	LevelCrit slog.Level = 12
	// LevelFatal matches zapcore.FatalLevel
	LevelFatal slog.Level = 5
)

// Logger interface that supports both the geth-style interface and zap fields
type Logger interface {
	// Original geth-style methods
	With(ctx ...interface{}) Logger
	New(ctx ...interface{}) Logger
	Log(level slog.Level, msg string, ctx ...interface{})
	Trace(msg string, ctx ...interface{})
	Debug(msg string, ctx ...interface{})
	Info(msg string, ctx ...interface{})
	Warn(msg string, ctx ...interface{})
	Error(msg string, ctx ...interface{})
	Crit(msg string, ctx ...interface{})
	WriteLog(level slog.Level, msg string, attrs ...any)
	Enabled(ctx context.Context, level slog.Level) bool
	Handler() slog.Handler

	// Additional methods for node compatibility
	Fatal(msg string, fields ...Field)
	Verbo(msg string, fields ...Field)
	WithFields(fields ...Field) Logger
	WithOptions(opts ...Option) Logger
	SetLevel(level slog.Level)
	GetLevel() slog.Level
	EnabledLevel(lvl slog.Level) bool
	StopOnPanic()
	RecoverAndPanic(f func())
	RecoverAndExit(f, exit func())
	Stop()

	// io.Writer
	io.Writer
}

// zapLogger wraps zap.Logger to implement our Logger interface
type zapLogger struct {
	logger  *zap.Logger
	sugar   *zap.SugaredLogger
	level   *zap.AtomicLevel
	handler slog.Handler // For compatibility
}

// LoggerWriter wraps a Logger to provide io.Writer interface
type LoggerWriter struct {
	logger Logger
	level  slog.Level
}

// Write implements io.Writer
func (w *LoggerWriter) Write(p []byte) (n int, err error) {
	w.logger.Log(w.level, string(p))
	return len(p), nil
}

// WriterAt returns an io.Writer that writes to the logger at the specified level
func WriterAt(logger Logger, level slog.Level) io.Writer {
	return &LoggerWriter{logger: logger, level: level}
}

// NewZapLogger creates a logger directly from a zap logger
func NewZapLogger(logger *zap.Logger) Logger {
	level := zap.NewAtomicLevelAt(zapcore.InfoLevel)
	return &zapLogger{
		logger:  logger,
		sugar:   logger.Sugar(),
		level:   &level,
		handler: nil,
	}
}

// Handler returns the slog handler (for compatibility)
func (l *zapLogger) Handler() slog.Handler {
	return l.handler
}

// With adds context fields (variadic key-value pairs)
func (l *zapLogger) With(ctx ...interface{}) Logger {
	if len(ctx) == 0 {
		return l
	}

	// Convert ctx to zap fields
	fields := make([]Field, 0, len(ctx)/2)
	for i := 0; i < len(ctx)-1; i += 2 {
		key, ok := ctx[i].(string)
		if !ok {
			key = fmt.Sprintf("%v", ctx[i])
		}
		fields = append(fields, zap.Any(key, ctx[i+1]))
	}

	return &zapLogger{
		logger:  l.logger.With(fields...),
		sugar:   l.logger.With(fields...).Sugar(),
		level:   l.level,
		handler: l.handler,
	}
}

// New is an alias for With
func (l *zapLogger) New(ctx ...interface{}) Logger {
	return l.With(ctx...)
}

// WithFields adds zap fields
func (l *zapLogger) WithFields(fields ...Field) Logger {
	return &zapLogger{
		logger:  l.logger.With(fields...),
		sugar:   l.logger.With(fields...).Sugar(),
		level:   l.level,
		handler: l.handler,
	}
}

// WithOptions applies zap options
func (l *zapLogger) WithOptions(opts ...Option) Logger {
	return &zapLogger{
		logger:  l.logger.WithOptions(opts...),
		sugar:   l.logger.WithOptions(opts...).Sugar(),
		level:   l.level,
		handler: l.handler,
	}
}

// SetLevel sets the logging level
func (l *zapLogger) SetLevel(level slog.Level) {
	l.level.SetLevel(slogToZapLevel(level))
}

// GetLevel returns the current logging level
func (l *zapLogger) GetLevel() slog.Level {
	return zapToSlogLevel(l.level.Level())
}

// Enabled checks if a level is enabled
func (l *zapLogger) Enabled(ctx context.Context, level slog.Level) bool {
	return l.logger.Core().Enabled(slogToZapLevel(level))
}

// EnabledLevel checks if a level is enabled (node compatibility)
func (l *zapLogger) EnabledLevel(lvl slog.Level) bool {
	return l.logger.Core().Enabled(slogToZapLevel(lvl))
}

// Log logs at the specified level
func (l *zapLogger) Log(level slog.Level, msg string, ctx ...interface{}) {
	zapLevel := slogToZapLevel(level)
	if ce := l.logger.Check(zapLevel, msg); ce != nil {
		fields := contextToFields(ctx)
		ce.Write(fields...)
	}
}

// WriteLog logs a message at the specified level (renamed to avoid conflict with io.Writer)
func (l *zapLogger) WriteLog(level slog.Level, msg string, attrs ...any) {
	l.Log(level, msg, attrs...)
}

// Trace logs at trace level
func (l *zapLogger) Trace(msg string, ctx ...interface{}) {
	l.logger.Debug(msg, contextToFields(ctx)...) // Map trace to debug in zap
}

// Debug logs at debug level
func (l *zapLogger) Debug(msg string, ctx ...interface{}) {
	l.logger.Debug(msg, contextToFields(ctx)...)
}

// Info logs at info level
func (l *zapLogger) Info(msg string, ctx ...interface{}) {
	l.logger.Info(msg, contextToFields(ctx)...)
}

// Warn logs at warn level
func (l *zapLogger) Warn(msg string, ctx ...interface{}) {
	l.logger.Warn(msg, contextToFields(ctx)...)
}

// Error logs at error level
func (l *zapLogger) Error(msg string, ctx ...interface{}) {
	l.logger.Error(msg, contextToFields(ctx)...)
}

// Crit logs at critical level and exits
func (l *zapLogger) Crit(msg string, ctx ...interface{}) {
	l.logger.Fatal(msg, contextToFields(ctx)...)
}

// Fatal logs at fatal level
func (l *zapLogger) Fatal(msg string, fields ...Field) {
	l.logger.Fatal(msg, fields...)
}

// Verbo logs at very verbose level
func (l *zapLogger) Verbo(msg string, fields ...Field) {
	// Map verbo to trace/debug with a special field
	l.logger.Debug(msg, append(fields, zap.String("level", "verbo"))...)
}

// StopOnPanic recovers from panic, logs, and re-panics
func (l *zapLogger) StopOnPanic() {
	if r := recover(); r != nil {
		l.logger.Fatal("panic recovered", zap.Any("panic", r))
		panic(r)
	}
}

// RecoverAndPanic runs a function and logs any panic
func (l *zapLogger) RecoverAndPanic(f func()) {
	defer l.StopOnPanic()
	f()
}

// RecoverAndExit runs a function and calls exit function on panic
func (l *zapLogger) RecoverAndExit(f, exit func()) {
	defer func() {
		if r := recover(); r != nil {
			l.logger.Error("panic recovered", zap.Any("panic", r))
			exit()
		}
	}()
	f()
}

// Stop syncs the logger
func (l *zapLogger) Stop() {
	_ = l.logger.Sync()
}

// Write implements io.Writer - logs pre-formatted messages at Info level
func (l *zapLogger) Write(p []byte) (n int, err error) {
	// Trim trailing newline if present
	msg := string(p)
	if len(msg) > 0 && msg[len(msg)-1] == '\n' {
		msg = msg[:len(msg)-1]
	}
	l.logger.Info(msg)
	return len(p), nil
}

// Helper functions

// contextToFields converts variadic key-value pairs to zap fields
func contextToFields(ctx []interface{}) []Field {
	fields := make([]Field, 0, len(ctx)/2)
	for i := 0; i < len(ctx)-1; i += 2 {
		key, ok := ctx[i].(string)
		if !ok {
			key = fmt.Sprintf("%v", ctx[i])
		}
		fields = append(fields, zap.Any(key, ctx[i+1]))
	}
	return fields
}

// slogToZapLevel converts slog level to zap level
func slogToZapLevel(level slog.Level) zapcore.Level {
	switch {
	case level <= LevelVerbo:
		return zapcore.DebugLevel
	case level <= LevelTrace:
		return zapcore.DebugLevel
	case level <= LevelDebug:
		return zapcore.DebugLevel
	case level <= LevelInfo:
		return zapcore.InfoLevel
	case level <= LevelWarn:
		return zapcore.WarnLevel
	case level <= LevelError:
		return zapcore.ErrorLevel
	default:
		return zapcore.FatalLevel
	}
}

// zapToSlogLevel converts zap level to slog level
func zapToSlogLevel(level zapcore.Level) slog.Level {
	switch level {
	case zapcore.DebugLevel:
		return LevelDebug
	case zapcore.InfoLevel:
		return LevelInfo
	case zapcore.WarnLevel:
		return LevelWarn
	case zapcore.ErrorLevel:
		return LevelError
	case zapcore.DPanicLevel, zapcore.PanicLevel, zapcore.FatalLevel:
		return LevelCrit
	default:
		return LevelInfo
	}
}

// Additional compatibility functions

// NewNoOpLogger creates a logger that discards all output
func NewNoOpLogger() Logger {
	nopCore := zapcore.NewNopCore()
	return NewZapLogger(zap.New(nopCore))
}

// NoLog is a no-op logger for testing
type NoLog struct{}

// Implement all Logger interface methods as no-ops
func (NoLog) With(ctx ...interface{}) Logger                       { return NoLog{} }
func (NoLog) New(ctx ...interface{}) Logger                        { return NoLog{} }
func (NoLog) Log(level slog.Level, msg string, ctx ...interface{}) {}
func (NoLog) Trace(msg string, ctx ...interface{})                 {}
func (NoLog) Debug(msg string, ctx ...interface{})                 {}
func (NoLog) Info(msg string, ctx ...interface{})                  {}
func (NoLog) Warn(msg string, ctx ...interface{})                  {}
func (NoLog) Error(msg string, ctx ...interface{})                 {}
func (NoLog) Crit(msg string, ctx ...interface{})                  {}
func (NoLog) WriteLog(level slog.Level, msg string, attrs ...any)  {}
func (NoLog) Enabled(ctx context.Context, level slog.Level) bool   { return false }
func (NoLog) Handler() slog.Handler                                { return nil }
func (NoLog) Fatal(msg string, fields ...Field)                    {}
func (NoLog) Verbo(msg string, fields ...Field)                    {}
func (NoLog) WithFields(fields ...Field) Logger                    { return NoLog{} }
func (NoLog) WithOptions(opts ...Option) Logger                    { return NoLog{} }
func (NoLog) SetLevel(level slog.Level)                            {}
func (NoLog) GetLevel() slog.Level                                 { return LevelInfo }
func (NoLog) EnabledLevel(lvl slog.Level) bool                     { return false }
func (NoLog) StopOnPanic()                                         {}
func (NoLog) RecoverAndPanic(f func())                             { f() }
func (NoLog) RecoverAndExit(f, exit func())                        { f() }
func (NoLog) Stop()                                                {}
func (NoLog) Write(p []byte) (n int, err error)                    { return len(p), nil }

// NewSimpleFactory creates a simple logger factory from zap config
// This is a convenience function for simple use cases
func NewSimpleFactory(config zap.Config) Factory {
	return NewFactoryWithConfig(Config{
		RotatingWriterConfig: RotatingWriterConfig{
			Directory: "./logs",
			MaxSize:   100,
			MaxFiles:  10,
			MaxAge:    30,
			Compress:  true,
		},
		DisplayLevel: level.Info,
		LogLevel:     level.Info,
		LogFormat:    Plain,
	})
}

// Factory and convenience functions

// Note: New function moved to globals.go

// Root returns the global logger
// This is an alias for the globalLogger defined in globals.go
func Root() Logger {
	return globalLogger
}

// SetDefault sets the default root logger
// This is an alias for SetGlobalLogger defined in globals.go
func SetDefault(l Logger) {
	SetGlobalLogger(l)
}

// Helper functions for formatting

// levelMaxVerbosity must be low enough to include slog.LevelDebug (-4)
// since some handlers like JSONHandler use slog's debug level
const levelMaxVerbosity slog.Level = -10

// Legacy level constants for compatibility
const (
	legacyLevelCrit = iota
	legacyLevelError
	legacyLevelWarn
	legacyLevelInfo
	legacyLevelDebug
	legacyLevelTrace
)

// FromLegacyLevel converts from old Geth verbosity level constants
// to levels defined by slog
func FromLegacyLevel(lvl int) slog.Level {
	switch lvl {
	case legacyLevelCrit:
		return LevelCrit
	case legacyLevelError:
		return slog.LevelError
	case legacyLevelWarn:
		return slog.LevelWarn
	case legacyLevelInfo:
		return slog.LevelInfo
	case legacyLevelDebug:
		return slog.LevelDebug
	case legacyLevelTrace:
		return LevelTrace
	default:
		// For higher verbosity levels, map to trace
		if lvl > legacyLevelTrace {
			return LevelTrace
		}
		// For negative levels, map to crit
		return LevelCrit
	}
}

// LevelString returns a string representation of the level
func LevelString(l slog.Level) string {
	switch l {
	case LevelTrace:
		return "trace"
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	case LevelCrit:
		return "crit"
	case LevelFatal:
		return "fatal"
	case LevelVerbo:
		return "verbo"
	default:
		return "unknown"
	}
}

// LevelAlignedString returns a 5-character aligned string for the level
// Handles both slog native levels and our custom level values
func LevelAlignedString(l slog.Level) string {
	switch {
	case l <= LevelVerbo: // -2 or lower
		return "verbo"
	case l <= LevelTrace: // -1 (Trace and Debug both map here)
		return "debug"
	case l <= LevelInfo: // 0
		return "info "
	case l <= LevelWarn, l == slog.LevelWarn: // 1 or 4 (slog.LevelWarn)
		return "warn "
	case l <= LevelError, l == slog.LevelError: // 2 or 8 (slog.LevelError)
		return "error"
	case l <= LevelFatal: // 5
		return "fatal"
	case l <= LevelCrit: // 12
		return "CRIT "
	default:
		return "OFF  "
	}
}
