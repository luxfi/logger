package log

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Re-export slog levels for compatibility
const (
	LevelTrace slog.Level = -8
	LevelDebug           = slog.LevelDebug
	LevelInfo            = slog.LevelInfo
	LevelWarn            = slog.LevelWarn
	LevelError           = slog.LevelError
	LevelCrit  slog.Level = 12
	LevelFatal slog.Level = 16 // Added for Fatal
	LevelVerbo slog.Level = -10 // Added for Verbo (most verbose)
)

// Level is the type for log levels
type Level = slog.Level

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
	Fatal(msg string, fields ...zap.Field)
	Verbo(msg string, fields ...zap.Field)
	WithFields(fields ...zap.Field) Logger
	WithOptions(opts ...zap.Option) Logger
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
	logger *zap.Logger
	sugar  *zap.SugaredLogger
	level  *zap.AtomicLevel
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

// NewLogger creates a new zap-backed logger
func NewLogger(h slog.Handler) Logger {
	// For compatibility, we accept an slog.Handler but create a zap logger
	config := zap.NewProductionConfig()
	config.DisableStacktrace = true
	config.Encoding = "console"
	config.EncoderConfig.TimeKey = "time"
	config.EncoderConfig.LevelKey = "level"
	config.EncoderConfig.MessageKey = "msg"
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	config.EncoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	
	logger, _ := config.Build()
	return &zapLogger{
		logger: logger,
		sugar:  logger.Sugar(),
		level:  &config.Level,
		handler: h,
	}
}

// NewZapLogger creates a logger directly from a zap logger
func NewZapLogger(logger *zap.Logger) Logger {
	level := zap.NewAtomicLevelAt(zapcore.InfoLevel)
	return &zapLogger{
		logger: logger,
		sugar:  logger.Sugar(),
		level:  &level,
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
	fields := make([]zap.Field, 0, len(ctx)/2)
	for i := 0; i < len(ctx)-1; i += 2 {
		key, ok := ctx[i].(string)
		if !ok {
			key = fmt.Sprintf("%v", ctx[i])
		}
		fields = append(fields, zap.Any(key, ctx[i+1]))
	}
	
	return &zapLogger{
		logger: l.logger.With(fields...),
		sugar:  l.logger.With(fields...).Sugar(),
		level:  l.level,
		handler: l.handler,
	}
}

// New is an alias for With
func (l *zapLogger) New(ctx ...interface{}) Logger {
	return l.With(ctx...)
}

// WithFields adds zap fields
func (l *zapLogger) WithFields(fields ...zap.Field) Logger {
	return &zapLogger{
		logger: l.logger.With(fields...),
		sugar:  l.logger.With(fields...).Sugar(),
		level:  l.level,
		handler: l.handler,
	}
}

// WithOptions applies zap options
func (l *zapLogger) WithOptions(opts ...zap.Option) Logger {
	return &zapLogger{
		logger: l.logger.WithOptions(opts...),
		sugar:  l.logger.WithOptions(opts...).Sugar(),
		level:  l.level,
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
func (l *zapLogger) Fatal(msg string, fields ...zap.Field) {
	l.logger.Fatal(msg, fields...)
}

// Verbo logs at very verbose level
func (l *zapLogger) Verbo(msg string, fields ...zap.Field) {
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
func contextToFields(ctx []interface{}) []zap.Field {
	fields := make([]zap.Field, 0, len(ctx)/2)
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

// Factory interface for creating loggers
type Factory interface {
	New(name string) Logger
	NewWithFields(name string, fields ...zap.Field) Logger
}

// zapFactory implements Factory
type zapFactory struct {
	config zap.Config
}

// NewFactory creates a new logger factory
func NewFactory(config zap.Config) Factory {
	return &zapFactory{config: config}
}

func (f *zapFactory) New(name string) Logger {
	logger, _ := f.config.Build()
	return NewZapLogger(logger.Named(name))
}

func (f *zapFactory) NewWithFields(name string, fields ...zap.Field) Logger {
	logger, _ := f.config.Build()
	return NewZapLogger(logger.Named(name).With(fields...))
}

// Factory and convenience functions

// New creates a new logger with the given context
func New(ctx ...interface{}) Logger {
	return Root().With(ctx...)
}

var (
	root Logger
)

func init() {
	// Initialize with a default zap logger
	config := zap.NewProductionConfig()
	config.DisableStacktrace = true
	config.Encoding = "console"
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	config.EncoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	
	logger, _ := config.Build()
	root = NewZapLogger(logger)
}

// Root returns the root logger
func Root() Logger {
	return root
}

// SetDefault sets the default root logger
func SetDefault(l Logger) {
	root = l
}

// Global convenience functions that use the root logger
func Trace(msg string, ctx ...interface{}) { root.Trace(msg, ctx...) }
func Debug(msg string, ctx ...interface{}) { root.Debug(msg, ctx...) }
func Info(msg string, ctx ...interface{})  { root.Info(msg, ctx...) }
func Warn(msg string, ctx ...interface{})  { root.Warn(msg, ctx...) }
func Error(msg string, ctx ...interface{}) { root.Error(msg, ctx...) }
func Crit(msg string, ctx ...interface{})  { root.Crit(msg, ctx...) }

// Helper functions for formatting

const levelMaxVerbosity = LevelVerbo

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
func LevelAlignedString(l slog.Level) string {
	switch l {
	case LevelTrace:
		return "TRACE"
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO "
	case LevelWarn:
		return "WARN "
	case LevelError:
		return "ERROR"
	case LevelCrit:
		return "CRIT "
	case LevelFatal:
		return "FATAL"
	case LevelVerbo:
		return "VERBO"
	default:
		return "UNKWN"
	}
}