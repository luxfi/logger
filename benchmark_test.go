package log

import (
	"io"
	"testing"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func BenchmarkZapLogger(b *testing.B) {
	// Create a zap logger that discards output
	config := zap.NewProductionConfig()
	config.DisableStacktrace = true
	config.OutputPaths = []string{}
	config.ErrorOutputPaths = []string{}
	
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(config.EncoderConfig),
		zapcore.AddSync(io.Discard),
		zapcore.InfoLevel,
	)
	
	logger := zap.New(core)
	l := NewZapLogger(logger)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.Info("test message", "key", "value", "number", i)
	}
}

func BenchmarkZapLoggerWithFields(b *testing.B) {
	config := zap.NewProductionConfig()
	config.DisableStacktrace = true
	config.OutputPaths = []string{}
	config.ErrorOutputPaths = []string{}
	
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(config.EncoderConfig),
		zapcore.AddSync(io.Discard),
		zapcore.InfoLevel,
	)
	
	logger := zap.New(core)
	l := NewZapLogger(logger)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.With("request_id", "12345").Info("test message", "key", "value", "number", i)
	}
}

func BenchmarkRootLogger(b *testing.B) {
	// Test the root logger performance
	SetDefault(NewNoOpLogger())
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Info("test message", "key", "value", "number", i)
	}
}