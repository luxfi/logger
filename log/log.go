// Copyright (C) 2019-2025, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

// Package log provides a global logger for chaining-style logging.
// Import this package for convenient access to the global logger.
//
//	import "github.com/luxfi/logger/log"
//
//	log.Info().Str("key", "value").Msg("hello")
package log

import (
	"context"
	"io"
	"os"

	"github.com/luxfi/logger"
)

// Logger is the global logger.
var Logger = logger.New(os.Stderr).With().Timestamp().Logger()

// Output duplicates the global logger and sets w as its output.
func Output(w io.Writer) logger.Logger {
	return Logger.Output(w)
}

// With creates a child logger with the field added to its context.
func With() logger.Context {
	return Logger.With()
}

// Level creates a child logger with the minimum accepted level set to level.
func Level(level logger.Level) logger.Logger {
	return Logger.Level(level)
}

// Sample returns a logger with the s sampler.
func Sample(s logger.Sampler) logger.Logger {
	return Logger.Sample(s)
}

// Hook returns a logger with the h Hook.
func Hook(h logger.Hook) logger.Logger {
	return Logger.Hook(h)
}

// Err starts a new message with error level with err as a field if not nil or
// with info level if err is nil.
func Err(err error) *logger.Event {
	return Logger.Err(err)
}

// Trace starts a new message with trace level.
func Trace() *logger.Event {
	return Logger.Trace()
}

// Debug starts a new message with debug level.
func Debug() *logger.Event {
	return Logger.Debug()
}

// Info starts a new message with info level.
func Info() *logger.Event {
	return Logger.Info()
}

// Warn starts a new message with warn level.
func Warn() *logger.Event {
	return Logger.Warn()
}

// Error starts a new message with error level.
func Error() *logger.Event {
	return Logger.Error()
}

// Fatal starts a new message with fatal level.
func Fatal() *logger.Event {
	return Logger.Fatal()
}

// Panic starts a new message with panic level.
func Panic() *logger.Event {
	return Logger.Panic()
}

// WithLevel starts a new message with level.
func WithLevel(level logger.Level) *logger.Event {
	return Logger.WithLevel(level)
}

// Log starts a new message with no level.
func Log() *logger.Event {
	return Logger.Log()
}

// Print sends a log event using debug level.
func Print(v ...interface{}) {
	Logger.Print(v...)
}

// Printf sends a log event using debug level.
func Printf(format string, v ...interface{}) {
	Logger.Printf(format, v...)
}

// Ctx returns the Logger associated with the ctx.
func Ctx(ctx context.Context) *logger.Logger {
	return logger.Ctx(ctx)
}
