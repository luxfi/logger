// Copyright (C) 2019-2025, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

// Package level provides log level constants for compatibility with existing code.
package level

import "github.com/luxfi/logger"

// Level type alias for compatibility
type Level = logger.Level

// Level constants matching logger.Level values
const (
	Trace Level = logger.TraceLevel
	Debug Level = logger.DebugLevel
	Info  Level = logger.InfoLevel
	Warn  Level = logger.WarnLevel
	Error Level = logger.ErrorLevel
	Fatal Level = logger.FatalLevel
	Panic Level = logger.PanicLevel
)
