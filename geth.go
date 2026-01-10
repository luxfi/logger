// Copyright (C) 2019-2025, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package logger

import (
	"fmt"
	"os"
	"time"
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

// Stack returns a Field with the current stack trace.
func Stack(key string) Field {
	return Field{Key: key, Value: "stack"} // Placeholder, actual stack in event
}

// defaultLogger is the global logger for geth-style functions
var defaultLogger = New(os.Stderr).With().Timestamp().Logger()

// SetDefault sets the default logger for geth-style functions
func SetDefault(l Logger) {
	defaultLogger = l
}

// Root returns the default logger
func Root() Logger {
	return defaultLogger
}

// applyFields applies geth-style Fields to an Event
func applyFields(e *Event, fields []Field) *Event {
	if e == nil {
		return nil
	}
	for _, f := range fields {
		switch v := f.Value.(type) {
		case string:
			e = e.Str(f.Key, v)
		case int:
			e = e.Int(f.Key, v)
		case int8:
			e = e.Int8(f.Key, v)
		case int16:
			e = e.Int16(f.Key, v)
		case int32:
			e = e.Int32(f.Key, v)
		case int64:
			e = e.Int64(f.Key, v)
		case uint:
			e = e.Uint(f.Key, v)
		case uint8:
			e = e.Uint8(f.Key, v)
		case uint16:
			e = e.Uint16(f.Key, v)
		case uint32:
			e = e.Uint32(f.Key, v)
		case uint64:
			e = e.Uint64(f.Key, v)
		case float32:
			e = e.Float32(f.Key, v)
		case float64:
			e = e.Float64(f.Key, v)
		case bool:
			e = e.Bool(f.Key, v)
		case time.Duration:
			e = e.Dur(f.Key, v)
		case time.Time:
			e = e.Time(f.Key, v)
		case error:
			e = e.AnErr(f.Key, v)
		case []byte:
			e = e.Bytes(f.Key, v)
		case fmt.Stringer:
			if v != nil {
				e = e.Str(f.Key, v.String())
			}
		default:
			e = e.Interface(f.Key, v)
		}
	}
	return e
}

// Geth-style global logging functions

// Trace logs at trace level with geth-style fields
func Trace(msg string, fields ...Field) {
	applyFields(defaultLogger.Trace(), fields).Msg(msg)
}

// Debug logs at debug level with geth-style fields
func Debug(msg string, fields ...Field) {
	applyFields(defaultLogger.Debug(), fields).Msg(msg)
}

// Info logs at info level with geth-style fields
func Info(msg string, fields ...Field) {
	applyFields(defaultLogger.Info(), fields).Msg(msg)
}

// Warn logs at warn level with geth-style fields
func Warn(msg string, fields ...Field) {
	applyFields(defaultLogger.Warn(), fields).Msg(msg)
}

// Error logs at error level with geth-style fields
func Error(msg string, fields ...Field) {
	applyFields(defaultLogger.Error(), fields).Msg(msg)
}

// Fatal logs at fatal level with geth-style fields and exits
func Fatal(msg string, fields ...Field) {
	applyFields(defaultLogger.Fatal(), fields).Msg(msg)
}

// Crit is an alias for Fatal (geth compatibility)
func Crit(msg string, fields ...Field) {
	Fatal(msg, fields...)
}

// Log logs at the specified level with geth-style fields
func Log(level Level, msg string, fields ...Field) {
	applyFields(defaultLogger.WithLevel(level), fields).Msg(msg)
}
