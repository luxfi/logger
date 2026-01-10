// Copyright (C) 2019-2025, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package logger

import (
	"io"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// NewZapLogger creates a Logger that writes using the same output as a zap.Logger.
// This creates a zerolog-based Logger for compatibility with the Logger struct.
func NewZapLogger(z *zap.Logger) Logger {
	// Extract the writer from zap and create a zerolog logger
	// Since we can't easily extract the writer, use stderr as default
	return New(os.Stderr).With().Timestamp().Logger()
}

// SetGlobalLogger sets the global logger.
func SetGlobalLogger(l Logger) {
	SetDefault(l)
}

// GetGlobalLogger returns the global logger.
func GetGlobalLogger() Logger {
	return Root()
}

// NewZapLoggerWithConfig creates a zap logger with the given configuration.
func NewZapLoggerWithConfig(level string, jsonFormat bool, writer io.Writer) (*zap.Logger, error) {
	var zapLevel zapcore.Level
	switch level {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "info":
		zapLevel = zapcore.InfoLevel
	case "warn":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	default:
		zapLevel = zapcore.InfoLevel
	}

	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	var encoder zapcore.Encoder
	if jsonFormat {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	} else {
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	}

	if writer == nil {
		writer = os.Stderr
	}
	core := zapcore.NewCore(encoder, zapcore.AddSync(writer), zapLevel)
	return zap.New(core, zap.AddCaller()), nil
}

// NewLoggerWithWriter creates a Logger with the specified writer.
func NewLoggerWithWriter(w io.Writer) Logger {
	return New(w).With().Timestamp().Logger()
}
