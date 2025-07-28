package log

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	
	"github.com/luxfi/log/level"
)

// Func defines the method signature used for all logging methods on the Logger interface
type Func func(msg string, fields ...zap.Field)

// UserString creates a zap field for user-provided strings that may need sanitization
func UserString(key, val string) zap.Field {
	return zap.String(key, val)
}

// UserStrings creates a zap field for user-provided string slices that may need sanitization
func UserStrings(key string, vals []string) zap.Field {
	return zap.Strings(key, vals)
}

// Stringer creates a zap field for fmt.Stringer objects
func Stringer(key string, val interface{}) zap.Field {
	return zap.Stringer(key, val.(interface{ String() string }))
}

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