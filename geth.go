// Copyright (C) 2019-2025, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package logger

import (
	"fmt"
	"os"
	"time"
)

// Level aliases for geth compatibility.
// These are Level type (not slog.Level) for use with Logger.Enabled().
const (
	LevelTrace = TraceLevel
	LevelDebug = DebugLevel
	LevelInfo  = InfoLevel
	LevelWarn  = WarnLevel
	LevelError = ErrorLevel
	LevelFatal = FatalLevel
	LevelPanic = PanicLevel
)

// Field represents a key-value pair for geth-style structured logging.
// This provides compatibility with go-ethereum's logging patterns.
type Field struct {
	Key   string
	Value interface{}
}

// Field constructors for geth-style logging
func String(key, val string) Field              { return Field{Key: key, Value: val} }
func Stringer(key string, val fmt.Stringer) Field { return Field{Key: key, Value: val} }
func Int(key string, val int) Field             { return Field{Key: key, Value: val} }
func Int8(key string, val int8) Field           { return Field{Key: key, Value: val} }
func Int16(key string, val int16) Field         { return Field{Key: key, Value: val} }
func Int32(key string, val int32) Field         { return Field{Key: key, Value: val} }
func Int64(key string, val int64) Field         { return Field{Key: key, Value: val} }
func Uint(key string, val uint) Field           { return Field{Key: key, Value: val} }
func Uint8(key string, val uint8) Field         { return Field{Key: key, Value: val} }
func Uint16(key string, val uint16) Field       { return Field{Key: key, Value: val} }
func Uint32(key string, val uint32) Field       { return Field{Key: key, Value: val} }
func Uint64(key string, val uint64) Field       { return Field{Key: key, Value: val} }
func Float32(key string, val float32) Field     { return Field{Key: key, Value: val} }
func Float64(key string, val float64) Field     { return Field{Key: key, Value: val} }
func Bool(key string, val bool) Field           { return Field{Key: key, Value: val} }
func Duration(key string, val time.Duration) Field { return Field{Key: key, Value: val} }
func Time(key string, val time.Time) Field      { return Field{Key: key, Value: val} }
func Err(err error) Field                       { return Field{Key: ErrorFieldName, Value: err} }
func NamedErr(key string, err error) Field      { return Field{Key: key, Value: err} }
func Any(key string, val interface{}) Field     { return Field{Key: key, Value: val} }
func Binary(key string, val []byte) Field       { return Field{Key: key, Value: val} }
func ByteString(key string, val []byte) Field   { return Field{Key: key, Value: string(val)} }

// Short-form aliases (matching chaining API style)
func Str(key, val string) Field                 { return String(key, val) }
func Dur(key string, val time.Duration) Field   { return Duration(key, val) }
func AnErr(key string, err error) Field         { return NamedErr(key, err) }

// Stack returns a Field with the current stack trace.
func Stack(key string) Field {
	return Field{Key: key, Value: "stack"} // Placeholder, actual stack in event
}

// defaultLogger is the global logger for geth-style functions
var defaultLogger = NewWriter(os.Stderr).With().Timestamp().Logger()

// SetDefault sets the default logger for geth-style functions
func SetDefault(l Logger) {
	defaultLogger = l
}

// Root returns the default logger
func Root() Logger {
	return defaultLogger
}

// applyContext applies geth-style key-value pairs to an Event.
// Accepts alternating key-value pairs: key1, val1, key2, val2, ...
func applyContext(e *Event, ctx []any) *Event {
	if e == nil {
		return nil
	}
	for i := 0; i+1 < len(ctx); i += 2 {
		key, ok := ctx[i].(string)
		if !ok {
			continue
		}
		val := ctx[i+1]
		switch v := val.(type) {
		case string:
			e = e.Str(key, v)
		case int:
			e = e.Int(key, v)
		case int8:
			e = e.Int8(key, v)
		case int16:
			e = e.Int16(key, v)
		case int32:
			e = e.Int32(key, v)
		case int64:
			e = e.Int64(key, v)
		case uint:
			e = e.Uint(key, v)
		case uint8:
			e = e.Uint8(key, v)
		case uint16:
			e = e.Uint16(key, v)
		case uint32:
			e = e.Uint32(key, v)
		case uint64:
			e = e.Uint64(key, v)
		case float32:
			e = e.Float32(key, v)
		case float64:
			e = e.Float64(key, v)
		case bool:
			e = e.Bool(key, v)
		case time.Duration:
			e = e.Dur(key, v)
		case time.Time:
			e = e.Time(key, v)
		case error:
			if v != nil {
				e = e.AnErr(key, v)
			}
		case []byte:
			e = e.Bytes(key, v)
		case fmt.Stringer:
			if v != nil {
				e = e.Str(key, v.String())
			}
		case Field:
			// Support Field type for backward compatibility
			switch fv := v.Value.(type) {
			case string:
				e = e.Str(v.Key, fv)
			case error:
				e = e.AnErr(v.Key, fv)
			default:
				e = e.Interface(v.Key, v.Value)
			}
		default:
			e = e.Interface(key, v)
		}
	}
	return e
}

// Geth-style global logging functions
// These accept alternating key-value pairs: msg, key1, val1, key2, val2, ...

// Trace logs at trace level with geth-style context
func Trace(msg string, ctx ...any) {
	applyContext(defaultLogger.TraceEvent(), ctx).Msg(msg)
}

// Debug logs at debug level with geth-style context
func Debug(msg string, ctx ...any) {
	applyContext(defaultLogger.DebugEvent(), ctx).Msg(msg)
}

// Info logs at info level with geth-style context
func Info(msg string, ctx ...any) {
	applyContext(defaultLogger.InfoEvent(), ctx).Msg(msg)
}

// Warn logs at warn level with geth-style context
func Warn(msg string, ctx ...any) {
	applyContext(defaultLogger.WarnEvent(), ctx).Msg(msg)
}

// Error logs at error level with geth-style context
func Error(msg string, ctx ...any) {
	applyContext(defaultLogger.ErrorEvent(), ctx).Msg(msg)
}

// Fatal logs at fatal level with geth-style context and exits
func Fatal(msg string, ctx ...any) {
	applyContext(defaultLogger.FatalEvent(), ctx).Msg(msg)
}

// Crit is an alias for Fatal (geth compatibility)
func Crit(msg string, ctx ...any) {
	Fatal(msg, ctx...)
}

// Log logs at the specified level with geth-style context
func Log(level Level, msg string, ctx ...any) {
	applyContext(defaultLogger.WithLevel(level), ctx).Msg(msg)
}

// NewNoOpLogger returns a disabled logger.
func NewNoOpLogger() Logger {
	return Nop()
}

// NewTestLogger returns a logger suitable for testing.
// If a level is provided, the logger is set to that level.
func NewTestLogger(level ...Level) Logger {
	l := NewWriter(os.Stderr).With().Timestamp().Logger()
	if len(level) > 0 {
		l = l.Level(level[0])
	}
	return l
}

