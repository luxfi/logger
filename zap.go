// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package log

import (
	"fmt"
	"io"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// zapLogger wraps zap.Logger to implement our Logger interface
type zapLogger struct {
	logger *zap.Logger
	level  *zap.AtomicLevel
}

// NewZapLogger creates a new logger backed by zap
func NewZapLogger(config zap.Config) (Logger, error) {
	logger, err := config.Build()
	if err != nil {
		return nil, err
	}
	return &zapLogger{
		logger: logger,
		level:  &config.Level,
	}, nil
}

// NewZapLoggerFromCore creates a logger from a zapcore.Core
func NewZapLoggerFromCore(core zapcore.Core) Logger {
	logger := zap.New(core)
	level := zap.NewAtomicLevelAt(zapcore.InfoLevel)
	return &zapLogger{
		logger: logger,
		level:  &level,
	}
}

func (z *zapLogger) Debug(msg string, fields ...Field) {
	z.logger.Debug(msg, toZapFields(fields)...)
}

func (z *zapLogger) Info(msg string, fields ...Field) {
	z.logger.Info(msg, toZapFields(fields)...)
}

func (z *zapLogger) Warn(msg string, fields ...Field) {
	z.logger.Warn(msg, toZapFields(fields)...)
}

func (z *zapLogger) Error(msg string, fields ...Field) {
	z.logger.Error(msg, toZapFields(fields)...)
}

func (z *zapLogger) Fatal(msg string, fields ...Field) {
	z.logger.Fatal(msg, toZapFields(fields)...)
}

func (z *zapLogger) Debugf(format string, args ...interface{}) {
	z.logger.Debug(fmt.Sprintf(format, args...))
}

func (z *zapLogger) Infof(format string, args ...interface{}) {
	z.logger.Info(fmt.Sprintf(format, args...))
}

func (z *zapLogger) Warnf(format string, args ...interface{}) {
	z.logger.Warn(fmt.Sprintf(format, args...))
}

func (z *zapLogger) Errorf(format string, args ...interface{}) {
	z.logger.Error(fmt.Sprintf(format, args...))
}

func (z *zapLogger) Fatalf(format string, args ...interface{}) {
	z.logger.Fatal(fmt.Sprintf(format, args...))
}

func (z *zapLogger) With(fields ...Field) Logger {
	return &zapLogger{
		logger: z.logger.With(toZapFields(fields)...),
		level:  z.level,
	}
}

func (z *zapLogger) Named(name string) Logger {
	return &zapLogger{
		logger: z.logger.Named(name),
		level:  z.level,
	}
}

func (z *zapLogger) SetLevel(level Level) {
	z.level.SetLevel(toZapLevel(level))
}

func (z *zapLogger) GetLevel() Level {
	return fromZapLevel(z.level.Level())
}

func (z *zapLogger) SetOutput(w io.Writer) {
	// Note: Changing output requires rebuilding the logger with zap
	// This is a simplified implementation
}

// toZapFields converts our Field type to zap.Field
func toZapFields(fields []Field) []zap.Field {
	zapFields := make([]zap.Field, len(fields))
	for i, f := range fields {
		zapFields[i] = zap.Any(f.Key, f.Value)
	}
	return zapFields
}

// toZapLevel converts our Level to zapcore.Level
func toZapLevel(level Level) zapcore.Level {
	switch level {
	case DebugLevel:
		return zapcore.DebugLevel
	case InfoLevel:
		return zapcore.InfoLevel
	case WarnLevel:
		return zapcore.WarnLevel
	case ErrorLevel:
		return zapcore.ErrorLevel
	case FatalLevel:
		return zapcore.FatalLevel
	default:
		return zapcore.InfoLevel
	}
}

// fromZapLevel converts zapcore.Level to our Level
func fromZapLevel(level zapcore.Level) Level {
	switch level {
	case zapcore.DebugLevel:
		return DebugLevel
	case zapcore.InfoLevel:
		return InfoLevel
	case zapcore.WarnLevel:
		return WarnLevel
	case zapcore.ErrorLevel:
		return ErrorLevel
	case zapcore.FatalLevel:
		return FatalLevel
	default:
		return InfoLevel
	}
}

// zapFactory creates zap-backed loggers
type zapFactory struct {
	config zap.Config
	root   Logger
}

// NewZapFactory creates a factory that produces zap-backed loggers
func NewZapFactory(config zap.Config) (Factory, error) {
	root, err := NewZapLogger(config)
	if err != nil {
		return nil, err
	}
	return &zapFactory{
		config: config,
		root:   root,
	}, nil
}

// NewZapFactoryFromLogger creates a factory from an existing zap logger
func NewZapFactoryFromLogger(logger *zap.Logger) Factory {
	level := zap.NewAtomicLevelAt(zapcore.InfoLevel)
	return &zapFactory{
		root: &zapLogger{
			logger: logger,
			level:  &level,
		},
	}
}

func (f *zapFactory) New(name string) Logger {
	return f.root.Named(name)
}

func (f *zapFactory) NewWithFields(name string, fields ...Field) Logger {
	return f.root.Named(name).With(fields...)
}

func (f *zapFactory) Root() Logger {
	return f.root
}

// DefaultZapConfig returns a sensible default zap configuration
func DefaultZapConfig() zap.Config {
	return zap.Config{
		Level:            zap.NewAtomicLevelAt(zapcore.InfoLevel),
		Development:      false,
		Encoding:         "json",
		EncoderConfig:    zap.NewProductionEncoderConfig(),
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}
}

// DevelopmentZapConfig returns a zap configuration suitable for development
func DevelopmentZapConfig() zap.Config {
	config := zap.NewDevelopmentConfig()
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	return config
}