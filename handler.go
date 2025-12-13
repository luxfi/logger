package log

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"reflect"
	"sync"
	"time"

	"github.com/holiman/uint256"
)

type discardHandler struct{}

// DiscardHandler returns a no-op handler
func DiscardHandler() slog.Handler {
	return &discardHandler{}
}

func (h *discardHandler) Handle(_ context.Context, r slog.Record) error {
	return nil
}

func (h *discardHandler) Enabled(_ context.Context, level slog.Level) bool {
	return false
}

func (h *discardHandler) WithGroup(name string) slog.Handler {
	panic("not implemented")
}

func (h *discardHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &discardHandler{}
}

type TerminalHandler struct {
	mu       sync.Mutex
	wr       io.Writer
	lvl      slog.Level
	useColor bool
	attrs    []slog.Attr
	// fieldPadding is a map with maximum field value lengths seen until now
	// to allow padding log contexts in a bit smarter way.
	fieldPadding map[string]int

	buf []byte
}

// NewTerminalHandler returns a handler which formats log records at all levels optimized for human readability on
// a terminal with color-coded level output and terser human friendly timestamp.
// This format should only be used for interactive programs or while developing.
//
//	[LEVEL] [TIME] MESSAGE key=value key=value ...
//
// Example:
//
//	[DBUG] [May 16 20:58:45] remove route ns=haproxy addr=127.0.0.1:50002
func NewTerminalHandler(wr io.Writer, useColor bool) *TerminalHandler {
	return NewTerminalHandlerWithLevel(wr, levelMaxVerbosity, useColor)
}

// NewTerminalHandlerWithLevel returns the same handler as NewTerminalHandler but only outputs
// records which are less than or equal to the specified verbosity level.
func NewTerminalHandlerWithLevel(wr io.Writer, lvl slog.Level, useColor bool) *TerminalHandler {
	return &TerminalHandler{
		wr:           wr,
		lvl:          lvl,
		useColor:     useColor,
		fieldPadding: make(map[string]int),
	}
}

func (h *TerminalHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	buf := h.format(h.buf, r, h.useColor)
	_, err := h.wr.Write(buf)
	h.buf = buf[:0]
	return err
}

func (h *TerminalHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.lvl
}

func (h *TerminalHandler) WithGroup(name string) slog.Handler {
	panic("not implemented")
}

func (h *TerminalHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &TerminalHandler{
		wr:           h.wr,
		lvl:          h.lvl,
		useColor:     h.useColor,
		attrs:        append(h.attrs, attrs...),
		fieldPadding: make(map[string]int),
	}
}

// ResetFieldPadding zeroes the field-padding for all attribute pairs.
func (h *TerminalHandler) ResetFieldPadding() {
	h.mu.Lock()
	h.fieldPadding = make(map[string]int)
	h.mu.Unlock()
}

type leveler struct{ minLevel slog.Level }

func (l *leveler) Level() slog.Level {
	return l.minLevel
}

// JSONHandler returns a handler which prints records in JSON format.
func JSONHandler(wr io.Writer) slog.Handler {
	return JSONHandlerWithLevel(wr, levelMaxVerbosity)
}

// JSONHandlerWithLevel returns a handler which prints records in JSON format that are less than or equal to
// the specified verbosity level.
func JSONHandlerWithLevel(wr io.Writer, level slog.Level) slog.Handler {
	return slog.NewJSONHandler(wr, &slog.HandlerOptions{
		ReplaceAttr: builtinReplaceJSON,
		Level:       &leveler{level},
	})
}

// LogfmtHandler returns a handler which prints records in logfmt format, an easy machine-parseable but human-readable
// format for key/value pairs.
//
// For more details see: http://godoc.org/github.com/kr/logfmt
func LogfmtHandler(wr io.Writer) slog.Handler {
	return slog.NewTextHandler(wr, &slog.HandlerOptions{
		ReplaceAttr: builtinReplaceLogfmt,
	})
}

// LogfmtHandlerWithLevel returns the same handler as LogfmtHandler but it only outputs
// records which are less than or equal to the specified verbosity level.
func LogfmtHandlerWithLevel(wr io.Writer, level slog.Level) slog.Handler {
	return slog.NewTextHandler(wr, &slog.HandlerOptions{
		ReplaceAttr: builtinReplaceLogfmt,
		Level:       &leveler{level},
	})
}

func builtinReplaceLogfmt(_ []string, attr slog.Attr) slog.Attr {
	return builtinReplace(nil, attr, true)
}

func builtinReplaceJSON(_ []string, attr slog.Attr) slog.Attr {
	return builtinReplace(nil, attr, false)
}

func builtinReplace(_ []string, attr slog.Attr, logfmt bool) slog.Attr {
	switch attr.Key {
	case slog.TimeKey:
		if attr.Value.Kind() == slog.KindTime {
			if logfmt {
				return slog.String("t", attr.Value.Time().Format(timeFormat))
			} else {
				return slog.Attr{Key: "t", Value: attr.Value}
			}
		}
	case slog.LevelKey:
		if l, ok := attr.Value.Any().(slog.Level); ok {
			attr = slog.Any("lvl", LevelString(l))
			return attr
		}
	}

	switch v := attr.Value.Any().(type) {
	case time.Time:
		if logfmt {
			attr = slog.String(attr.Key, v.Format(timeFormat))
		}
	case *big.Int:
		if v == nil {
			attr.Value = slog.StringValue("<nil>")
		} else {
			attr.Value = slog.StringValue(v.String())
		}
	case *uint256.Int:
		if v == nil {
			attr.Value = slog.StringValue("<nil>")
		} else {
			attr.Value = slog.StringValue(v.Dec())
		}
	case fmt.Stringer:
		if v == nil || (reflect.ValueOf(v).Kind() == reflect.Pointer && reflect.ValueOf(v).IsNil()) {
			attr.Value = slog.StringValue("<nil>")
		} else {
			attr.Value = slog.StringValue(v.String())
		}
	}
	return attr
}

// SlogBridgeLogger implements Logger interface using a slog.Handler
// This bridges geth-style slog handlers to luxfi/log Logger interface
type SlogBridgeLogger struct {
	slogger *slog.Logger
	handler slog.Handler
	level   slog.Level
}

// NewLoggerFromHandler creates a Logger from a slog.Handler
// This is used for geth compatibility where handlers implement slog.Handler
func NewLoggerFromHandler(h slog.Handler) Logger {
	return &SlogBridgeLogger{
		slogger: slog.New(h),
		handler: h,
		level:   LevelInfo,
	}
}

func (l *SlogBridgeLogger) With(ctx ...interface{}) Logger {
	attrs := make([]slog.Attr, 0, len(ctx)/2)
	for i := 0; i < len(ctx)-1; i += 2 {
		key, ok := ctx[i].(string)
		if !ok {
			key = fmt.Sprintf("%v", ctx[i])
		}
		attrs = append(attrs, slog.Any(key, ctx[i+1]))
	}
	return &SlogBridgeLogger{
		slogger: slog.New(l.handler.WithAttrs(attrs)),
		handler: l.handler.WithAttrs(attrs),
		level:   l.level,
	}
}

func (l *SlogBridgeLogger) New(ctx ...interface{}) Logger {
	return l.With(ctx...)
}

func (l *SlogBridgeLogger) Log(level slog.Level, msg string, ctx ...interface{}) {
	l.WriteLog(level, msg, ctx...)
}

func (l *SlogBridgeLogger) Trace(msg string, ctx ...interface{}) {
	l.WriteLog(LevelTrace, msg, ctx...)
}

func (l *SlogBridgeLogger) Debug(msg string, ctx ...interface{}) {
	l.WriteLog(LevelDebug, msg, ctx...)
}

func (l *SlogBridgeLogger) Info(msg string, ctx ...interface{}) {
	l.WriteLog(LevelInfo, msg, ctx...)
}

func (l *SlogBridgeLogger) Warn(msg string, ctx ...interface{}) {
	l.WriteLog(LevelWarn, msg, ctx...)
}

func (l *SlogBridgeLogger) Error(msg string, ctx ...interface{}) {
	l.WriteLog(LevelError, msg, ctx...)
}

func (l *SlogBridgeLogger) Crit(msg string, ctx ...interface{}) {
	l.WriteLog(LevelCrit, msg, ctx...)
}

func (l *SlogBridgeLogger) WriteLog(level slog.Level, msg string, attrs ...any) {
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

func (l *SlogBridgeLogger) Enabled(ctx context.Context, level slog.Level) bool {
	return l.handler.Enabled(ctx, level)
}

func (l *SlogBridgeLogger) Handler() slog.Handler {
	return l.handler
}

func (l *SlogBridgeLogger) Fatal(msg string, fields ...Field) {
	l.WriteLog(LevelFatal, msg)
}

func (l *SlogBridgeLogger) Verbo(msg string, fields ...Field) {
	l.WriteLog(LevelVerbo, msg)
}

func (l *SlogBridgeLogger) WithFields(fields ...Field) Logger {
	return l
}

func (l *SlogBridgeLogger) WithOptions(opts ...Option) Logger {
	return l
}

func (l *SlogBridgeLogger) SetLevel(level slog.Level) {
	l.level = level
}

func (l *SlogBridgeLogger) GetLevel() slog.Level {
	return l.level
}

func (l *SlogBridgeLogger) EnabledLevel(lvl slog.Level) bool {
	return l.handler.Enabled(context.Background(), lvl)
}

func (l *SlogBridgeLogger) StopOnPanic() {}

func (l *SlogBridgeLogger) RecoverAndPanic(f func()) {
	defer func() {
		if r := recover(); r != nil {
			panic(r)
		}
	}()
	f()
}

func (l *SlogBridgeLogger) RecoverAndExit(f, exit func()) {
	defer func() {
		if r := recover(); r != nil {
			exit()
		}
	}()
	f()
}

func (l *SlogBridgeLogger) Stop() {}

func (l *SlogBridgeLogger) Write(p []byte) (n int, err error) {
	msg := string(p)
	if len(msg) > 0 && msg[len(msg)-1] == '\n' {
		msg = msg[:len(msg)-1]
	}
	l.Info(msg)
	return len(p), nil
}
