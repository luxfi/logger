package log

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"github.com/luxfi/log/level"
)

// NewTestLogger creates a logger suitable for testing
func NewTestLogger(lvl Level) Logger {
	config := zap.NewDevelopmentConfig()
	config.Level = zap.NewAtomicLevelAt(level.ToZapLevel(lvl))
	config.DisableStacktrace = true
	config.Encoding = "console"
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	config.EncoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder

	logger, _ := config.Build()
	return NewZapLogger(logger)
}

// DefaultConfig returns a default configuration for the logger factory
func DefaultConfig() Config {
	return Config{
		RotatingWriterConfig: RotatingWriterConfig{
			MaxSize:   100, // 100 MB
			MaxFiles:  10,
			MaxAge:    30, // 30 days
			Directory: "./logs",
			Compress:  true,
		},
		DisableWriterDisplaying: false,
		LogLevel:                level.Info,
		DisplayLevel:            level.Info,
		LogFormat:               Auto,
	}
}