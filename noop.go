// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build ignore
// +build ignore

package log

import "io"

// noopLogger is a logger that does nothing
type noopLogger struct {
	level Level
}

// NewNoOpLogger creates a logger that discards all log messages
func NewNoOpLogger() Logger {
	return &noopLogger{level: InfoLevel}
}

func (n *noopLogger) Debug(msg string, fields ...Field) {}
func (n *noopLogger) Info(msg string, fields ...Field)  {}
func (n *noopLogger) Warn(msg string, fields ...Field)  {}
func (n *noopLogger) Error(msg string, fields ...Field) {}
func (n *noopLogger) Fatal(msg string, fields ...Field) {}

func (n *noopLogger) Debugf(format string, args ...interface{}) {}
func (n *noopLogger) Infof(format string, args ...interface{})  {}
func (n *noopLogger) Warnf(format string, args ...interface{})  {}
func (n *noopLogger) Errorf(format string, args ...interface{}) {}
func (n *noopLogger) Fatalf(format string, args ...interface{}) {}

func (n *noopLogger) With(fields ...Field) Logger {
	return n
}

func (n *noopLogger) Named(name string) Logger {
	return n
}

func (n *noopLogger) SetLevel(level Level) {
	n.level = level
}

func (n *noopLogger) GetLevel() Level {
	return n.level
}

func (n *noopLogger) SetOutput(w io.Writer) {}

// noopFactory creates noop loggers
type noopFactory struct{}

// NewNoOpFactory creates a factory that produces noop loggers
func NewNoOpFactory() Factory {
	return &noopFactory{}
}

func (f *noopFactory) New(name string) Logger {
	return NewNoOpLogger()
}

func (f *noopFactory) NewWithFields(name string, fields ...Field) Logger {
	return NewNoOpLogger()
}

func (f *noopFactory) Root() Logger {
	return NewNoOpLogger()
}
