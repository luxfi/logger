// Copyright (C) 2019-2025, Lux Industries Inc All rights reserved.
// See the file LICENSE for licensing terms.

package log

import "go.uber.org/zap/zapcore"

// Re-export zapcore types for backwards compatibility
type (
	EncoderConfig         = zapcore.EncoderConfig
	Encoder               = zapcore.Encoder
	StringDurationEncoder = zapcore.DurationEncoder
)

// Re-export zapcore functions
var (
	NewConsoleEncoder = zapcore.NewConsoleEncoder
)
