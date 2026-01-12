// Copyright (C) 2019-2025, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

// Package level provides log level constants for compatibility with existing code.
package level

import (
	"fmt"
	"strings"

	logger "github.com/luxfi/log"
)

// Level wraps logger.Level to provide additional methods.
type Level logger.Level

// Level constants matching logger.Level values
const (
	Trace Level = Level(logger.TraceLevel)
	Debug Level = Level(logger.DebugLevel)
	Info  Level = Level(logger.InfoLevel)
	Warn  Level = Level(logger.WarnLevel)
	Error Level = Level(logger.ErrorLevel)
	Fatal Level = Level(logger.FatalLevel)
	Panic Level = Level(logger.PanicLevel)

	// Additional level constants for compatibility
	Verbo Level = Level(logger.TraceLevel) // Alias for Trace
	Off   Level = Level(logger.Disabled)   // Disabled level
)

// ToLoggerLevel converts Level to logger.Level
func (l Level) ToLoggerLevel() logger.Level {
	return logger.Level(l)
}

// String returns the string representation of a Level.
func (l Level) String() string {
	switch l {
	case Trace: // Note: Verbo is an alias for Trace, same underlying value
		return "TRACE"
	case Debug:
		return "DEBUG"
	case Info:
		return "INFO"
	case Warn:
		return "WARN"
	case Error:
		return "ERROR"
	case Fatal:
		return "FATAL"
	case Panic:
		return "PANIC"
	case Off:
		return "OFF"
	default:
		return "UNKNOWN"
	}
}

// LowerString returns the lowercase string representation of a Level.
func (l Level) LowerString() string {
	switch l {
	case Trace: // Note: Verbo is an alias for Trace, same underlying value
		return "trace"
	case Debug:
		return "debug"
	case Info:
		return "info"
	case Warn:
		return "warn"
	case Error:
		return "error"
	case Fatal:
		return "fatal"
	case Panic:
		return "panic"
	case Off:
		return "off"
	default:
		return "unknown"
	}
}

// ToLevel converts a string to a Level.
// Supported strings (case-insensitive): trace, debug, info, warn, error, fatal, panic, verbo, off
func ToLevel(s string) (Level, error) {
	switch strings.ToLower(s) {
	case "trace":
		return Trace, nil
	case "debug":
		return Debug, nil
	case "info":
		return Info, nil
	case "warn", "warning":
		return Warn, nil
	case "error":
		return Error, nil
	case "fatal":
		return Fatal, nil
	case "panic":
		return Panic, nil
	case "verbo", "verbose":
		return Verbo, nil
	case "off", "disabled":
		return Off, nil
	default:
		return Info, fmt.Errorf("unknown level: %s", s)
	}
}
