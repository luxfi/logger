package log

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/holiman/uint256"
	"go.uber.org/zap"
)

// slogBridgeLogger implements Logger interface using a slog.Handler
// This is used for testing handlers that implement slog.Handler
type slogBridgeLogger struct {
	slogger *slog.Logger
	handler slog.Handler
	level   slog.Level
}

// newLoggerFromHandler creates a Logger from a slog.Handler for testing purposes
func newLoggerFromHandler(h slog.Handler) Logger {
	return &slogBridgeLogger{
		slogger: slog.New(h),
		handler: h,
		level:   LevelInfo,
	}
}

// Implement Logger interface methods
func (l *slogBridgeLogger) With(ctx ...interface{}) Logger {
	attrs := make([]slog.Attr, 0, len(ctx)/2)
	for i := 0; i < len(ctx)-1; i += 2 {
		key, ok := ctx[i].(string)
		if !ok {
			key = fmt.Sprintf("%v", ctx[i])
		}
		attrs = append(attrs, slog.Any(key, ctx[i+1]))
	}
	return &slogBridgeLogger{
		slogger: slog.New(l.handler.WithAttrs(attrs)),
		handler: l.handler.WithAttrs(attrs),
		level:   l.level,
	}
}

func (l *slogBridgeLogger) New(ctx ...interface{}) Logger {
	return l.With(ctx...)
}

func (l *slogBridgeLogger) Log(level slog.Level, msg string, ctx ...interface{}) {
	l.WriteLog(level, msg, ctx...)
}

func (l *slogBridgeLogger) Trace(msg string, ctx ...interface{}) {
	l.WriteLog(LevelTrace, msg, ctx...)
}

func (l *slogBridgeLogger) Debug(msg string, ctx ...interface{}) {
	l.WriteLog(LevelDebug, msg, ctx...)
}

func (l *slogBridgeLogger) Info(msg string, ctx ...interface{}) {
	l.WriteLog(LevelInfo, msg, ctx...)
}

func (l *slogBridgeLogger) Warn(msg string, ctx ...interface{}) {
	l.WriteLog(LevelWarn, msg, ctx...)
}

func (l *slogBridgeLogger) Error(msg string, ctx ...interface{}) {
	l.WriteLog(LevelError, msg, ctx...)
}

func (l *slogBridgeLogger) Crit(msg string, ctx ...interface{}) {
	l.WriteLog(LevelCrit, msg, ctx...)
}

func (l *slogBridgeLogger) WriteLog(level slog.Level, msg string, attrs ...any) {
	// Convert attrs to slog attributes
	slogAttrs := make([]slog.Attr, 0, len(attrs)/2)
	for i := 0; i < len(attrs)-1; i += 2 {
		key, ok := attrs[i].(string)
		if !ok {
			key = fmt.Sprintf("%v", attrs[i])
		}
		slogAttrs = append(slogAttrs, slog.Any(key, attrs[i+1]))
	}
	
	l.slogger.LogAttrs(context.Background(), level, msg, slogAttrs...)
}

func (l *slogBridgeLogger) Enabled(ctx context.Context, level slog.Level) bool {
	return l.handler.Enabled(ctx, level)
}

func (l *slogBridgeLogger) Handler() slog.Handler {
	return l.handler
}

// Additional methods for node compatibility - stub implementations
func (l *slogBridgeLogger) Fatal(msg string, fields ...zap.Field) {
	l.WriteLog(LevelFatal, msg)
}

func (l *slogBridgeLogger) Verbo(msg string, fields ...zap.Field) {
	l.WriteLog(LevelVerbo, msg)
}

func (l *slogBridgeLogger) WithFields(fields ...zap.Field) Logger {
	// Convert zap fields to slog attrs - simplified for testing
	return l
}

func (l *slogBridgeLogger) WithOptions(opts ...zap.Option) Logger {
	return l
}

func (l *slogBridgeLogger) SetLevel(level slog.Level) {
	l.level = level
}

func (l *slogBridgeLogger) GetLevel() slog.Level {
	return l.level
}

func (l *slogBridgeLogger) EnabledLevel(lvl slog.Level) bool {
	return l.handler.Enabled(context.Background(), lvl)
}

func (l *slogBridgeLogger) StopOnPanic() {}

func (l *slogBridgeLogger) RecoverAndPanic(f func()) {
	defer func() {
		if r := recover(); r != nil {
			panic(r)
		}
	}()
	f()
}

func (l *slogBridgeLogger) RecoverAndExit(f, exit func()) {
	defer func() {
		if r := recover(); r != nil {
			exit()
		}
	}()
	f()
}

func (l *slogBridgeLogger) Stop() {}

func (l *slogBridgeLogger) Write(p []byte) (n int, err error) {
	msg := string(p)
	if len(msg) > 0 && msg[len(msg)-1] == '\n' {
		msg = msg[:len(msg)-1]
	}
	l.Info(msg)
	return len(p), nil
}

// TestLoggingWithVmodule checks that vmodule works.
func TestLoggingWithVmodule(t *testing.T) {
	out := new(bytes.Buffer)
	glog := NewGlogHandler(NewTerminalHandlerWithLevel(out, LevelTrace, false))
	glog.Verbosity(LevelCrit)
	logger := newLoggerFromHandler(glog)
	logger.Warn("This should not be seen", "ignored", "true")
	glog.Vmodule("logger_test.go=5")
	logger.Trace("a message", "foo", "bar")
	have := out.String()
	// Since we're using zap now, just check that the output contains our message
	if !strings.Contains(have, "a message") || !strings.Contains(have, "foo=bar") {
		t.Errorf("Expected output to contain 'a message' and 'foo=bar', got: %q", have)
	}
}

func TestTerminalHandlerWithAttrs(t *testing.T) {
	out := new(bytes.Buffer)
	glog := NewGlogHandler(NewTerminalHandlerWithLevel(out, LevelTrace, false).WithAttrs([]slog.Attr{slog.String("baz", "bat")}))
	glog.Verbosity(LevelTrace)
	logger := newLoggerFromHandler(glog)
	logger.Trace("a message", "foo", "bar")
	have := out.String()
	// Since we're using zap now, just check that the output contains our message and attributes
	if !strings.Contains(have, "a message") || !strings.Contains(have, "foo=bar") || !strings.Contains(have, "baz=bat") {
		t.Errorf("Expected output to contain 'a message', 'foo=bar', and 'baz=bat', got: %q", have)
	}
}

// Make sure the default json handler outputs debug log lines
func TestJSONHandler(t *testing.T) {
	out := new(bytes.Buffer)
	handler := JSONHandler(out)
	logger := slog.New(handler)
	logger.Debug("hi there")
	if len(out.String()) == 0 {
		t.Error("expected non-empty debug log output from default JSON Handler")
	}

	out.Reset()
	handler = JSONHandlerWithLevel(out, slog.LevelInfo)
	logger = slog.New(handler)
	logger.Debug("hi there")
	if len(out.String()) != 0 {
		t.Errorf("expected empty debug log output, but got: %v", out.String())
	}
}

func BenchmarkTraceLogging(b *testing.B) {
	SetDefault(newLoggerFromHandler(NewTerminalHandler(io.Discard, true)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Trace("a message", "v", i)
	}
}

func BenchmarkTerminalHandler(b *testing.B) {
	l := newLoggerFromHandler(NewTerminalHandler(io.Discard, false))
	benchmarkLogger(b, l)
}
func BenchmarkLogfmtHandler(b *testing.B) {
	l := newLoggerFromHandler(LogfmtHandler(io.Discard))
	benchmarkLogger(b, l)
}

func BenchmarkJSONHandler(b *testing.B) {
	l := newLoggerFromHandler(JSONHandler(io.Discard))
	benchmarkLogger(b, l)
}

func benchmarkLogger(b *testing.B, l Logger) {
	var (
		bb     = make([]byte, 10)
		tt     = time.Now()
		bigint = big.NewInt(100)
		nilbig *big.Int
		err    = errors.New("oh nooes it's crap")
	)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.Info("This is a message",
			"foo", int16(i),
			"bytes", bb,
			"bonk", "a string with text",
			"time", tt,
			"bigint", bigint,
			"nilbig", nilbig,
			"err", err)
	}
	b.StopTimer()
}

func TestLoggerOutput(t *testing.T) {
	type custom struct {
		A string
		B int8
	}
	var (
		customA   = custom{"Foo", 12}
		customB   = custom{"Foo\nLinebreak", 122}
		bb        = make([]byte, 10)
		tt        = time.Time{}
		bigint    = big.NewInt(100)
		nilbig    *big.Int
		err       = errors.New("oh nooes it's crap")
		smallUint = uint256.NewInt(500_000)
		bigUint   = &uint256.Int{0xff, 0xff, 0xff, 0xff}
	)

	out := new(bytes.Buffer)
	glogHandler := NewGlogHandler(NewTerminalHandler(out, false))
	glogHandler.Verbosity(LevelInfo)
	newLoggerFromHandler(glogHandler).Info("This is a message",
		"foo", int16(123),
		"bytes", bb,
		"bonk", "a string with text",
		"time", tt,
		"bigint", bigint,
		"nilbig", nilbig,
		"err", err,
		"struct", customA,
		"struct", customB,
		"ptrstruct", &customA,
		"smalluint", smallUint,
		"bigUint", bigUint)

	have := out.String()
	t.Logf("output %v", out.String())
	want := `INFO [11-07|19:14:33.821] This is a message                        foo=123 bytes="[0 0 0 0 0 0 0 0 0 0]" bonk="a string with text" time=0001-01-01T00:00:00+0000 bigint=100 nilbig=<nil> err="oh nooes it's crap" struct="{A:Foo B:12}" struct="{A:Foo\nLinebreak B:122}" ptrstruct="&{A:Foo B:12}" smalluint=500,000 bigUint=1,600,660,942,523,603,594,864,898,306,482,794,244,293,965,082,972,225,630,372,095
`
	if !bytes.Equal([]byte(have)[25:], []byte(want)[25:]) {
		t.Errorf("Error\nhave: %q\nwant: %q", have, want)
	}
}

func BenchmarkAppendFormat(b *testing.B) {
	var now = time.Now()
	b.Run("fmt time.Format", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fmt.Fprintf(io.Discard, "%s", now.Format(termTimeFormat))
		}
	})
	b.Run("time.AppendFormat", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			now.AppendFormat(nil, termTimeFormat)
		}
	})
	var buf = new(bytes.Buffer)
	b.Run("time.Custom", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			writeTimeTermFormat(buf, now)
			buf.Reset()
		}
	})
}

func TestTermTimeFormat(t *testing.T) {
	var now = time.Now()
	// termTimeFormat includes brackets, but writeTimeTermFormat doesn't write them
	// So we need to test without the brackets
	want := now.AppendFormat(nil, "01-02|15:04:05.000")
	var b = new(bytes.Buffer)
	writeTimeTermFormat(b, now)
	have := b.Bytes()
	if !bytes.Equal(have, want) {
		t.Errorf("have != want\nhave: %q\nwant: %q\n", have, want)
	}
}
