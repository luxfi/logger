// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package log

import (
	"io"
)

// Level represents the severity of a log message
type Level int

const (
	DebugLevel Level = iota
	InfoLevel
	WarnLevel
	ErrorLevel
	FatalLevel
)

// Logger defines the interface for logging
type Logger interface {
	// Basic logging methods
	Debug(msg string, fields ...Field)
	Info(msg string, fields ...Field)
	Warn(msg string, fields ...Field)
	Error(msg string, fields ...Field)
	Fatal(msg string, fields ...Field)

	// Formatted logging methods
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})

	// Create sub-logger with additional context
	With(fields ...Field) Logger
	Named(name string) Logger

	// Control methods
	SetLevel(level Level)
	GetLevel() Level
	SetOutput(w io.Writer)
}

// Field represents a key-value pair for structured logging
type Field struct {
	Key   string
	Value interface{}
}

// String creates a string field
func String(key, val string) Field {
	return Field{Key: key, Value: val}
}

// Int creates an int field
func Int(key string, val int) Field {
	return Field{Key: key, Value: val}
}

// Error creates an error field
func Error(err error) Field {
	return Field{Key: "error", Value: err}
}

// Any creates a field with any value
func Any(key string, val interface{}) Field {
	return Field{Key: key, Value: val}
}

// Factory creates new logger instances
type Factory interface {
	// Create a new logger
	New(name string) Logger
	
	// Create a new logger with fields
	NewWithFields(name string, fields ...Field) Logger
	
	// Get the root logger
	Root() Logger
}

// Global factory instance
var defaultFactory Factory = NewNoOpFactory()

// SetFactory sets the global logger factory
func SetFactory(factory Factory) {
	defaultFactory = factory
}

// New creates a new logger using the global factory
func New(name string) Logger {
	return defaultFactory.New(name)
}

// NewWithFields creates a new logger with fields using the global factory
func NewWithFields(name string, fields ...Field) Logger {
	return defaultFactory.NewWithFields(name, fields...)
}

// Root returns the root logger
func Root() Logger {
	return defaultFactory.Root()
}