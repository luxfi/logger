// Copyright (C) 2019-2025, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

// Package log provides a structured logging interface compatible with the Lux ecosystem.
//
// Usage:
//
//	import "github.com/luxfi/logger/log"
//
//	// Simple global logging
//	log.Info("starting server")
//	log.Debug("processing request")
//
//	// With key-value pairs
//	log.Info("user logged in", "user", "alice", "age", 30)
//
//	// With field constructors
//	log.Info("user logged in", log.String("user", "alice"), log.Int("age", 30))
//
//	// Instance logging
//	logger := log.NewLogger()
//	logger.Info("message", log.String("key", "value"))
package log

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/luxfi/logger"
)

// Logger is the interface for structured logging with variadic fields.
type Logger interface {
	Trace(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Fatal(msg string, args ...interface{})
	Panic(msg string, args ...interface{})
	Verbo(msg string, args ...interface{}) // Alias for Trace

	// With returns a new logger with the given fields added to context.
	With(args ...interface{}) Logger

	// New creates a new child logger with the given context fields (geth compatibility).
	New(ctx ...interface{}) Logger

	// Enabled returns true if the given level is enabled.
	Enabled(ctx context.Context, level Level) bool
}

// Level represents log level (slog.Level for geth/coreth compatibility).
type Level = slog.Level

// Log levels as slog.Level for geth/coreth compatibility.
const (
	LevelTrace Level = logger.SlogLevelTrace
	LevelDebug Level = slog.LevelDebug
	LevelInfo  Level = slog.LevelInfo
	LevelWarn  Level = slog.LevelWarn
	LevelError Level = slog.LevelError
	LevelCrit  Level = logger.SlogLevelCrit
	LevelFatal Level = logger.SlogLevelCrit // Alias for LevelCrit
	LevelPanic Level = logger.SlogLevelCrit // Alias for LevelCrit
)

// baseLogger is the underlying zerolog logger.
var baseLogger = logger.NewWriter(os.Stderr).With().Timestamp().Logger()

// L is the global logger instance implementing Logger interface.
var L Logger = &zeroLogWrapper{l: baseLogger}

// Nop is a disabled logger instance for which all operations are no-op.
var Nop Logger = &NoLog{}

// Field is a function that adds a field to a log event.
type Field func(*logger.Event)

// zeroLogWrapper wraps logger.Logger to implement Logger interface.
type zeroLogWrapper struct {
	l      logger.Logger
	fields []Field
}

// String returns a field for a string value.
func String(key, val string) Field {
	return func(e *logger.Event) {
		e.Str(key, val)
	}
}

// UserString returns a field for a user-provided string value (same as String).
func UserString(key, val string) Field {
	return func(e *logger.Event) {
		e.Str(key, val)
	}
}

// Stringer returns a field for a fmt.Stringer value.
func Stringer(key string, val fmt.Stringer) Field {
	return func(e *logger.Event) {
		if val != nil {
			e.Stringer(key, val)
		}
	}
}

// Int returns a field for an int value.
func Int(key string, val int) Field {
	return func(e *logger.Event) {
		e.Int(key, val)
	}
}

// Int32 returns a field for an int32 value.
func Int32(key string, val int32) Field {
	return func(e *logger.Event) {
		e.Int32(key, val)
	}
}

// Int64 returns a field for an int64 value.
func Int64(key string, val int64) Field {
	return func(e *logger.Event) {
		e.Int64(key, val)
	}
}

// Uint returns a field for a uint value.
func Uint(key string, val uint) Field {
	return func(e *logger.Event) {
		e.Uint(key, val)
	}
}

// Uint8 returns a field for a uint8 value.
func Uint8(key string, val uint8) Field {
	return func(e *logger.Event) {
		e.Uint8(key, val)
	}
}

// Uint16 returns a field for a uint16 value.
func Uint16(key string, val uint16) Field {
	return func(e *logger.Event) {
		e.Uint16(key, val)
	}
}

// Uint32 returns a field for a uint32 value.
func Uint32(key string, val uint32) Field {
	return func(e *logger.Event) {
		e.Uint32(key, val)
	}
}

// Uint64 returns a field for a uint64 value.
func Uint64(key string, val uint64) Field {
	return func(e *logger.Event) {
		e.Uint64(key, val)
	}
}

// Float64 returns a field for a float64 value.
func Float64(key string, val float64) Field {
	return func(e *logger.Event) {
		e.Float64(key, val)
	}
}

// Bool returns a field for a bool value.
func Bool(key string, val bool) Field {
	return func(e *logger.Event) {
		e.Bool(key, val)
	}
}

// Err returns a field for an error value.
func Err(err error) Field {
	return func(e *logger.Event) {
		e.Err(err)
	}
}

// Reflect returns a field for any value using reflection.
func Reflect(key string, val interface{}) Field {
	return func(e *logger.Event) {
		e.Interface(key, val)
	}
}

// Binary returns a field for binary data (hex encoded).
func Binary(key string, val []byte) Field {
	return func(e *logger.Event) {
		e.Hex(key, val)
	}
}

// Duration returns a field for a time.Duration value.
func Duration(key string, val interface{}) Field {
	return func(e *logger.Event) {
		e.Interface(key, val)
	}
}

// Time returns a field for a time.Time value.
func Time(key string, val interface{}) Field {
	return func(e *logger.Event) {
		e.Interface(key, val)
	}
}

// Strings returns a field for a string slice value.
func Strings(key string, val []string) Field {
	return func(e *logger.Event) {
		e.Strs(key, val)
	}
}

// Ints returns a field for an int slice value.
func Ints(key string, val []int) Field {
	return func(e *logger.Event) {
		e.Ints(key, val)
	}
}

// Any returns a field for any value (alias for Reflect).
func Any(key string, val interface{}) Field {
	return Reflect(key, val)
}

// Factory is a function type that creates new Logger instances.
type Factory func() Logger

// DefaultFactory returns a factory that creates new loggers with default settings.
func DefaultFactory() Factory {
	return NewLogger
}

// applyArgs applies fields or key-value pairs to an event.
// Supports both Field functions and alternating key-value pairs.
func applyArgs(e *logger.Event, args []interface{}) {
	for i := 0; i < len(args); {
		arg := args[i]

		// Check if it's a Field function
		if field, ok := arg.(Field); ok {
			field(e)
			i++
			continue
		}

		// Check if it's a func(*logger.Event) (handle untyped function literals)
		if field, ok := arg.(func(*logger.Event)); ok {
			field(e)
			i++
			continue
		}

		// Otherwise, treat as key-value pair
		if i+1 < len(args) {
			key, keyOk := arg.(string)
			if keyOk {
				val := args[i+1]
				addFieldToEvent(e, key, val)
				i += 2
				continue
			}
		}

		// If we get here, it's an unpaired value - log it with "arg" key
		e.Interface("arg", arg)
		i++
	}
}

// addFieldToEvent adds a key-value pair to the event.
func addFieldToEvent(e *logger.Event, key string, val interface{}) {
	switch v := val.(type) {
	case string:
		e.Str(key, v)
	case int:
		e.Int(key, v)
	case int32:
		e.Int32(key, v)
	case int64:
		e.Int64(key, v)
	case uint:
		e.Uint(key, v)
	case uint32:
		e.Uint32(key, v)
	case uint64:
		e.Uint64(key, v)
	case float32:
		e.Float32(key, float32(v))
	case float64:
		e.Float64(key, v)
	case bool:
		e.Bool(key, v)
	case error:
		if v != nil {
			e.Str(key, v.Error())
		}
	case []byte:
		e.Hex(key, v)
	case fmt.Stringer:
		if v != nil {
			e.Stringer(key, v)
		}
	default:
		e.Interface(key, v)
	}
}

// NewLogger creates a new Logger instance.
func NewLogger() Logger {
	return &zeroLogWrapper{l: logger.NewWriter(os.Stderr).With().Timestamp().Logger()}
}

// NewLoggerWithOutput creates a new Logger with a custom output.
func NewLoggerWithOutput(w io.Writer) Logger {
	return &zeroLogWrapper{l: logger.NewWriter(w).With().Timestamp().Logger()}
}

// zeroLogWrapper methods

func (z *zeroLogWrapper) log(level logger.Level, msg string, args []interface{}) {
	e := z.l.WithLevel(level)
	for _, f := range z.fields {
		f(e)
	}
	applyArgs(e, args)
	e.Msg(msg)
}

func (z *zeroLogWrapper) Trace(msg string, args ...interface{}) {
	z.log(logger.TraceLevel, msg, args)
}

func (z *zeroLogWrapper) Debug(msg string, args ...interface{}) {
	z.log(logger.DebugLevel, msg, args)
}

func (z *zeroLogWrapper) Info(msg string, args ...interface{}) {
	z.log(logger.InfoLevel, msg, args)
}

func (z *zeroLogWrapper) Warn(msg string, args ...interface{}) {
	z.log(logger.WarnLevel, msg, args)
}

func (z *zeroLogWrapper) Error(msg string, args ...interface{}) {
	z.log(logger.ErrorLevel, msg, args)
}

func (z *zeroLogWrapper) Fatal(msg string, args ...interface{}) {
	z.log(logger.FatalLevel, msg, args)
}

func (z *zeroLogWrapper) Panic(msg string, args ...interface{}) {
	z.log(logger.PanicLevel, msg, args)
}

func (z *zeroLogWrapper) Verbo(msg string, args ...interface{}) {
	z.Trace(msg, args...)
}

func (z *zeroLogWrapper) With(args ...interface{}) Logger {
	// Convert args to fields
	newFields := make([]Field, 0, len(z.fields))
	newFields = append(newFields, z.fields...)

	// Process args into fields
	for i := 0; i < len(args); {
		arg := args[i]
		if field, ok := arg.(Field); ok {
			newFields = append(newFields, field)
			i++
			continue
		}
		if i+1 < len(args) {
			if key, ok := arg.(string); ok {
				val := args[i+1]
				newFields = append(newFields, func(e *logger.Event) {
					addFieldToEvent(e, key, val)
				})
				i += 2
				continue
			}
		}
		i++
	}

	return &zeroLogWrapper{
		l:      z.l,
		fields: newFields,
	}
}

func (z *zeroLogWrapper) New(ctx ...interface{}) Logger {
	// New is an alias for With (geth compatibility)
	return z.With(ctx...)
}

func (z *zeroLogWrapper) Enabled(ctx context.Context, level Level) bool {
	return z.l.Enabled(ctx, level)
}

// NoLog is a no-op logger implementation.
type NoLog struct{}

func (n NoLog) Trace(msg string, args ...interface{}) {}
func (n NoLog) Debug(msg string, args ...interface{}) {}
func (n NoLog) Info(msg string, args ...interface{})  {}
func (n NoLog) Warn(msg string, args ...interface{})  {}
func (n NoLog) Error(msg string, args ...interface{}) {}
func (n NoLog) Fatal(msg string, args ...interface{}) {}
func (n NoLog) Panic(msg string, args ...interface{}) {}
func (n NoLog) Verbo(msg string, args ...interface{}) {}
func (n NoLog) With(args ...interface{}) Logger       { return n }
func (n NoLog) New(ctx ...interface{}) Logger         { return n }
func (n NoLog) Enabled(ctx context.Context, level Level) bool { return false }

// Global logging functions

// Trace logs a trace-level message with optional fields.
func Trace(msg string, args ...interface{}) {
	L.Trace(msg, args...)
}

// Debug logs a debug-level message with optional fields.
func Debug(msg string, args ...interface{}) {
	L.Debug(msg, args...)
}

// Info logs an info-level message with optional fields.
func Info(msg string, args ...interface{}) {
	L.Info(msg, args...)
}

// Warn logs a warning-level message with optional fields.
func Warn(msg string, args ...interface{}) {
	L.Warn(msg, args...)
}

// Error logs an error-level message with optional fields.
func Error(msg string, args ...interface{}) {
	L.Error(msg, args...)
}

// Fatal logs a fatal-level message with optional fields and exits.
func Fatal(msg string, args ...interface{}) {
	L.Fatal(msg, args...)
}

// Panic logs a panic-level message with optional fields and panics.
func Panic(msg string, args ...interface{}) {
	L.Panic(msg, args...)
}

// Verbo logs a verbose/trace-level message.
func Verbo(msg string, args ...interface{}) {
	L.Verbo(msg, args...)
}

// Output duplicates the global logger and sets w as its output.
func Output(w io.Writer) logger.Logger {
	return baseLogger.Output(w)
}

// With creates a child logger with the field added to its context.
func With() logger.Context {
	return baseLogger.With()
}

// SetGlobalLevel sets the global log level.
func SetGlobalLevel(level Level) {
	// Convert slog.Level to logger.Level
	var internalLevel logger.Level
	switch {
	case level <= logger.SlogLevelTrace:
		internalLevel = logger.TraceLevel
	case level <= slog.LevelDebug:
		internalLevel = logger.DebugLevel
	case level <= slog.LevelInfo:
		internalLevel = logger.InfoLevel
	case level <= slog.LevelWarn:
		internalLevel = logger.WarnLevel
	case level <= slog.LevelError:
		internalLevel = logger.ErrorLevel
	default:
		internalLevel = logger.FatalLevel
	}
	logger.SetGlobalLevel(internalLevel)
}

// ToLevel converts a string to a Level.
func ToLevel(s string) (Level, error) {
	return logger.LvlFromString(s)
}

// Ctx returns the Logger associated with the ctx.
func Ctx(ctx context.Context) *logger.Logger {
	return logger.Ctx(ctx)
}

// New creates a new child logger with the given context fields.
// This is compatible with geth-style log.New("key1", val1, "key2", val2).
func New(ctx ...interface{}) Logger {
	return L.With(ctx...)
}

// Crit logs a critical-level message (alias for Fatal).
func Crit(msg string, args ...interface{}) {
	L.Fatal(msg, args...)
}

// NewNoOpLogger returns a no-op logger.
func NewNoOpLogger() Logger {
	return NoLog{}
}

// Root returns the default logger (geth compatibility).
func Root() Logger {
	return L
}

// SetDefault sets the default logger.
// Accepts both Logger and SlogLogger interfaces.
func SetDefault(l interface{}) {
	switch v := l.(type) {
	case Logger:
		L = v
	case SlogLogger:
		L = &slogLoggerWrapper{l: v}
		logger.SetSlogDefault(v)
	default:
		// Fallback: try to use as Logger
		if logger, ok := l.(Logger); ok {
			L = logger
		}
	}
}

// LogFormat represents the format of log output.
type LogFormat int

const (
	// Plain is plain text format.
	Plain LogFormat = iota
	// JSON is JSON format.
	JSON
)

// Config represents the logging configuration.
type Config struct {
	Directory               string
	LogLevel                Level
	DisplayLevel            Level
	LogFormat               LogFormat
	DisableWriterDisplaying bool
	MaxSize                 int
	MaxFiles                int
	MaxAge                  int
	Compress                bool
}

// ToFormat converts a string to a LogFormat.
func ToFormat(s string, fd uintptr) (LogFormat, error) {
	switch s {
	case "plain", "text", "":
		return Plain, nil
	case "json":
		return JSON, nil
	default:
		return Plain, fmt.Errorf("unknown log format: %s", s)
	}
}

// Re-exports for geth/coreth slog compatibility

// GlogHandler type alias.
type GlogHandler = logger.GlogHandler

// TerminalHandler type alias.
type TerminalHandler = logger.TerminalHandler

// SlogLogger interface re-export.
type SlogLogger = logger.SlogLogger

// NewGlogHandler creates a new GlogHandler wrapping the given handler.
func NewGlogHandler(h slog.Handler) *GlogHandler {
	return logger.NewGlogHandler(h)
}

// NewTerminalHandler returns a handler which formats log records for human readability.
func NewTerminalHandler(wr io.Writer, useColor bool) *TerminalHandler {
	return logger.NewTerminalHandler(wr, useColor)
}

// NewTerminalHandlerWithLevel returns a terminal handler with level filtering.
func NewTerminalHandlerWithLevel(wr io.Writer, lvl slog.Leveler, useColor bool) *TerminalHandler {
	return logger.NewTerminalHandlerWithLevel(wr, lvl, useColor)
}

// JSONHandler returns a handler which prints records in JSON format.
func JSONHandler(wr io.Writer) slog.Handler {
	return logger.JSONHandler(wr)
}

// JSONHandlerWithLevel returns a JSON handler with level filtering.
func JSONHandlerWithLevel(wr io.Writer, level slog.Leveler) slog.Handler {
	return logger.JSONHandlerWithLevel(wr, level)
}

// LogfmtHandler returns a handler which prints records in logfmt format.
func LogfmtHandler(wr io.Writer) slog.Handler {
	return logger.LogfmtHandler(wr)
}

// LogfmtHandlerWithLevel returns a logfmt handler with level filtering.
func LogfmtHandlerWithLevel(wr io.Writer, level slog.Leveler) slog.Handler {
	return logger.LogfmtHandlerWithLevel(wr, level)
}

// DiscardHandler returns a no-op handler.
func DiscardHandler() slog.Handler {
	return logger.DiscardHandler()
}

// FromLegacyLevel converts old geth verbosity level to slog.Level.
func FromLegacyLevel(lvl int) slog.Level {
	return logger.FromLegacyLevel(lvl)
}

// LevelAlignedString returns a 5-character string containing the name of a level.
func LevelAlignedString(l slog.Level) string {
	return logger.LevelAlignedString(l)
}

// LevelString returns a string containing the name of a level.
func LevelString(l slog.Level) string {
	return logger.LevelString(l)
}

// NewLogger creates a new SlogLogger with the given handler.
func NewSlogLogger(h slog.Handler) SlogLogger {
	return logger.NewLogger(h)
}

// NewLoggerFromHandler creates a new SlogLogger from a slog.Handler.
func NewLoggerFromHandler(h slog.Handler) SlogLogger {
	return logger.NewLoggerFromHandler(h)
}

// SlogRoot returns the root slog-based logger.
func SlogRoot() SlogLogger {
	return logger.SlogRoot()
}

// SetSlogDefault sets the default slog-based logger.
func SetSlogDefault(l SlogLogger) {
	logger.SetSlogDefault(l)
	// Also set as the default Logger
	L = &slogLoggerWrapper{l: l}
}

// slogLoggerWrapper wraps SlogLogger to implement Logger interface.
type slogLoggerWrapper struct {
	l SlogLogger
}

func (w *slogLoggerWrapper) Trace(msg string, args ...interface{}) { w.l.Trace(msg, args...) }
func (w *slogLoggerWrapper) Debug(msg string, args ...interface{}) { w.l.Debug(msg, args...) }
func (w *slogLoggerWrapper) Info(msg string, args ...interface{})  { w.l.Info(msg, args...) }
func (w *slogLoggerWrapper) Warn(msg string, args ...interface{})  { w.l.Warn(msg, args...) }
func (w *slogLoggerWrapper) Error(msg string, args ...interface{}) { w.l.Error(msg, args...) }
func (w *slogLoggerWrapper) Fatal(msg string, args ...interface{}) { w.l.Crit(msg, args...) }
func (w *slogLoggerWrapper) Panic(msg string, args ...interface{}) { w.l.Crit(msg, args...) }
func (w *slogLoggerWrapper) Verbo(msg string, args ...interface{}) { w.l.Trace(msg, args...) }
func (w *slogLoggerWrapper) With(args ...interface{}) Logger       { return &slogLoggerWrapper{l: w.l.With(args...)} }
func (w *slogLoggerWrapper) New(ctx ...interface{}) Logger         { return &slogLoggerWrapper{l: w.l.New(ctx...)} }
func (w *slogLoggerWrapper) Enabled(ctx context.Context, level Level) bool { return w.l.Enabled(ctx, level) }

// LvlFromString returns the appropriate level from a string name.
func LvlFromString(lvlString string) (slog.Level, error) {
	return logger.LvlFromString(lvlString)
}

// NewTestLogger returns a logger suitable for testing.
func NewTestLogger(level ...Level) logger.Logger {
	if len(level) > 0 {
		// Convert slog.Level to logger.Level
		var internalLevel logger.Level
		lvl := level[0]
		switch {
		case lvl <= logger.SlogLevelTrace:
			internalLevel = logger.TraceLevel
		case lvl <= slog.LevelDebug:
			internalLevel = logger.DebugLevel
		case lvl <= slog.LevelInfo:
			internalLevel = logger.InfoLevel
		case lvl <= slog.LevelWarn:
			internalLevel = logger.WarnLevel
		case lvl <= slog.LevelError:
			internalLevel = logger.ErrorLevel
		default:
			internalLevel = logger.FatalLevel
		}
		return logger.NewTestLogger(internalLevel)
	}
	return logger.NewTestLogger()
}
