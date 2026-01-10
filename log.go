// Package logger provides a high-performance structured logging library.
//
// This package supports two logging styles:
//
// 1. Geth-style variadic logging (recommended for compatibility):
//
//	log := logger.New("component", "myapp")
//	log.Info("server started", "port", 8080)
//	log.Debug("processing request", "id", reqID, "user", userID)
//
// 2. Method chaining (zero-allocation):
//
//	log := logger.NewWriter(os.Stderr).With().Str("component", "myapp").Logger()
//	log.Info().Str("port", "8080").Msg("server started")
//
// Both styles can be mixed. The geth-style methods internally use the
// zero-allocation Event system for high performance.
package logger

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

// Level defines log levels.
type Level int8

const (
	// DebugLevel defines debug log level.
	DebugLevel Level = iota
	// InfoLevel defines info log level.
	InfoLevel
	// WarnLevel defines warn log level.
	WarnLevel
	// ErrorLevel defines error log level.
	ErrorLevel
	// FatalLevel defines fatal log level.
	FatalLevel
	// PanicLevel defines panic log level.
	PanicLevel
	// NoLevel defines an absent log level.
	NoLevel
	// Disabled disables the logger.
	Disabled

	// TraceLevel defines trace level.
	TraceLevel Level = -1
	// Values less than TraceLevel are handled as numbers.
)

func (l Level) String() string {
	switch l {
	case TraceLevel:
		return LevelTraceValue
	case DebugLevel:
		return LevelDebugValue
	case InfoLevel:
		return LevelInfoValue
	case WarnLevel:
		return LevelWarnValue
	case ErrorLevel:
		return LevelErrorValue
	case FatalLevel:
		return LevelFatalValue
	case PanicLevel:
		return LevelPanicValue
	case Disabled:
		return "disabled"
	case NoLevel:
		return ""
	}
	return strconv.Itoa(int(l))
}

// ParseLevel converts a level string into a logger Level value.
func ParseLevel(levelStr string) (Level, error) {
	switch {
	case strings.EqualFold(levelStr, LevelFieldMarshalFunc(TraceLevel)):
		return TraceLevel, nil
	case strings.EqualFold(levelStr, LevelFieldMarshalFunc(DebugLevel)):
		return DebugLevel, nil
	case strings.EqualFold(levelStr, LevelFieldMarshalFunc(InfoLevel)):
		return InfoLevel, nil
	case strings.EqualFold(levelStr, LevelFieldMarshalFunc(WarnLevel)):
		return WarnLevel, nil
	case strings.EqualFold(levelStr, LevelFieldMarshalFunc(ErrorLevel)):
		return ErrorLevel, nil
	case strings.EqualFold(levelStr, LevelFieldMarshalFunc(FatalLevel)):
		return FatalLevel, nil
	case strings.EqualFold(levelStr, LevelFieldMarshalFunc(PanicLevel)):
		return PanicLevel, nil
	case strings.EqualFold(levelStr, LevelFieldMarshalFunc(Disabled)):
		return Disabled, nil
	case strings.EqualFold(levelStr, LevelFieldMarshalFunc(NoLevel)):
		return NoLevel, nil
	}
	i, err := strconv.Atoi(levelStr)
	if err != nil {
		return NoLevel, fmt.Errorf("Unknown Level String: '%s', defaulting to NoLevel", levelStr)
	}
	if i > 127 || i < -128 {
		return NoLevel, fmt.Errorf("Out-Of-Bounds Level: '%d', defaulting to NoLevel", i)
	}
	return Level(i), nil
}

// UnmarshalText implements encoding.TextUnmarshaler
func (l *Level) UnmarshalText(text []byte) error {
	if l == nil {
		return errors.New("can't unmarshal a nil *Level")
	}
	var err error
	*l, err = ParseLevel(string(text))
	return err
}

// MarshalText implements encoding.TextMarshaler
func (l Level) MarshalText() ([]byte, error) {
	return []byte(LevelFieldMarshalFunc(l)), nil
}

// Logger represents an active logging object that generates lines
// of JSON output to an io.Writer.
type Logger struct {
	w       LevelWriter
	level   Level
	sampler Sampler
	context []byte
	hooks   []Hook
	stack   bool
	ctx     context.Context
}

// New creates a new child logger with the given context key-value pairs.
// This is the geth-style constructor for creating loggers with context.
//
//	log := logger.New("component", "myapp", "version", "1.0")
//	log.Info("started")
func New(ctx ...interface{}) Logger {
	l := NewWriter(os.Stderr).With().Timestamp().Logger()
	if len(ctx) > 0 {
		return l.With().Fields(ctx).Logger()
	}
	return l
}

// NewWriter creates a root logger with given output writer.
// Use this when you need to specify a custom output destination.
//
//	log := logger.NewWriter(os.Stderr).With().Timestamp().Logger()
func NewWriter(w io.Writer) Logger {
	if w == nil {
		w = io.Discard
	}
	lw, ok := w.(LevelWriter)
	if !ok {
		lw = LevelWriterAdapter{w}
	}
	return Logger{w: lw, level: TraceLevel}
}

// Nop returns a disabled logger for which all operations are no-op.
func Nop() Logger {
	return NewWriter(nil).Level(Disabled)
}

// Output duplicates the current logger and sets w as its output.
func (l Logger) Output(w io.Writer) Logger {
	l2 := NewWriter(w)
	l2.level = l.level
	l2.sampler = l.sampler
	l2.stack = l.stack
	if len(l.hooks) > 0 {
		l2.hooks = append(l2.hooks, l.hooks...)
	}
	if l.context != nil {
		l2.context = make([]byte, len(l.context), cap(l.context))
		copy(l2.context, l.context)
	}
	return l2
}

// With creates a child logger with the field added to its context.
// Returns a Context for method chaining.
func (l Logger) With() Context {
	context := l.context
	l.context = make([]byte, 0, 500)
	if context != nil {
		l.context = append(l.context, context...)
	} else {
		l.context = enc.AppendBeginMarker(l.context)
	}
	return Context{l}
}

// UpdateContext updates the internal logger's context.
// Caution: This method is not concurrency safe.
func (l *Logger) UpdateContext(update func(c Context) Context) {
	if l == disabledLogger {
		return
	}
	if cap(l.context) == 0 {
		l.context = make([]byte, 0, 500)
	}
	if len(l.context) == 0 {
		l.context = enc.AppendBeginMarker(l.context)
	}
	c := update(Context{*l})
	l.context = c.l.context
}

// Level creates a child logger with the minimum accepted level set to level.
func (l Logger) Level(lvl Level) Logger {
	l.level = lvl
	return l
}

// GetLevel returns the current Level of l.
func (l Logger) GetLevel() Level {
	return l.level
}

// New creates a child logger with the given context key-value pairs.
// This is a method for geth compatibility - creates a child logger with additional context.
//
//	childLog := log.New("component", "myapp")
func (l Logger) New(ctx ...interface{}) Logger {
	if len(ctx) > 0 {
		return l.With().Fields(ctx).Logger()
	}
	return l
}

// Enabled checks if the given level is enabled for this logger.
// This is used for conditional logging to avoid expensive argument evaluation.
// Accepts slog.Level for compatibility with geth's slog-based logging.
func (l Logger) Enabled(ctx context.Context, level slog.Level) bool {
	// Convert slog.Level to internal Level
	var internalLevel Level
	switch {
	case level <= slogLevelTrace:
		internalLevel = TraceLevel
	case level <= slog.LevelDebug:
		internalLevel = DebugLevel
	case level <= slog.LevelInfo:
		internalLevel = InfoLevel
	case level <= slog.LevelWarn:
		internalLevel = WarnLevel
	case level <= slog.LevelError:
		internalLevel = ErrorLevel
	default:
		internalLevel = FatalLevel
	}
	return l.should(internalLevel)
}

// IsZero returns true if this is a zero-value logger (uninitialized).
func (l Logger) IsZero() bool {
	return l.w == nil
}

// Sample returns a logger with the s sampler.
func (l Logger) Sample(s Sampler) Logger {
	l.sampler = s
	return l
}

// Hook returns a logger with the h Hook.
func (l Logger) Hook(hooks ...Hook) Logger {
	if len(hooks) == 0 {
		return l
	}
	newHooks := make([]Hook, len(l.hooks), len(l.hooks)+len(hooks))
	copy(newHooks, l.hooks)
	l.hooks = append(newHooks, hooks...)
	return l
}

// --- Geth-style variadic logging methods ---
// These methods accept a message and variadic key-value pairs.

// Trace logs a message at trace level with optional key-value pairs.
func (l Logger) Trace(msg string, ctx ...interface{}) {
	if e := l.newEvent(TraceLevel, nil); e != nil {
		applyContext(e, ctx).Msg(msg)
	}
}

// Debug logs a message at debug level with optional key-value pairs.
func (l Logger) Debug(msg string, ctx ...interface{}) {
	if e := l.newEvent(DebugLevel, nil); e != nil {
		applyContext(e, ctx).Msg(msg)
	}
}

// Info logs a message at info level with optional key-value pairs.
func (l Logger) Info(msg string, ctx ...interface{}) {
	if e := l.newEvent(InfoLevel, nil); e != nil {
		applyContext(e, ctx).Msg(msg)
	}
}

// Warn logs a message at warn level with optional key-value pairs.
func (l Logger) Warn(msg string, ctx ...interface{}) {
	if e := l.newEvent(WarnLevel, nil); e != nil {
		applyContext(e, ctx).Msg(msg)
	}
}

// Error logs a message at error level with optional key-value pairs.
func (l Logger) Error(msg string, ctx ...interface{}) {
	if e := l.newEvent(ErrorLevel, nil); e != nil {
		applyContext(e, ctx).Msg(msg)
	}
}

// Fatal logs a message at fatal level with optional key-value pairs and exits.
func (l Logger) Fatal(msg string, ctx ...interface{}) {
	if e := l.newEvent(FatalLevel, func(msg string) {
		if closer, ok := l.w.(io.Closer); ok {
			closer.Close()
		}
		os.Exit(1)
	}); e != nil {
		applyContext(e, ctx).Msg(msg)
	}
}

// Panic logs a message at panic level with optional key-value pairs and panics.
func (l Logger) Panic(msg string, ctx ...interface{}) {
	if e := l.newEvent(PanicLevel, func(msg string) { panic(msg) }); e != nil {
		applyContext(e, ctx).Msg(msg)
	}
}

// Crit logs a message at critical level (alias for Fatal).
func (l Logger) Crit(msg string, ctx ...interface{}) {
	l.Fatal(msg, ctx...)
}

// Log logs a message at the specified level with optional key-value pairs.
func (l Logger) Log(level Level, msg string, ctx ...interface{}) {
	if e := l.newEvent(level, nil); e != nil {
		applyContext(e, ctx).Msg(msg)
	}
}

// --- Method chaining API (zero-allocation) ---
// These methods return an Event for building log messages.

// TraceEvent starts a new message with trace level.
// You must call Msg on the returned event in order to send the event.
func (l Logger) TraceEvent() *Event {
	return l.newEvent(TraceLevel, nil)
}

// DebugEvent starts a new message with debug level.
func (l Logger) DebugEvent() *Event {
	return l.newEvent(DebugLevel, nil)
}

// InfoEvent starts a new message with info level.
func (l Logger) InfoEvent() *Event {
	return l.newEvent(InfoLevel, nil)
}

// WarnEvent starts a new message with warn level.
func (l Logger) WarnEvent() *Event {
	return l.newEvent(WarnLevel, nil)
}

// ErrorEvent starts a new message with error level.
func (l Logger) ErrorEvent() *Event {
	return l.newEvent(ErrorLevel, nil)
}

// FatalEvent starts a new message with fatal level.
func (l Logger) FatalEvent() *Event {
	return l.newEvent(FatalLevel, func(msg string) {
		if closer, ok := l.w.(io.Closer); ok {
			closer.Close()
		}
		os.Exit(1)
	})
}

// PanicEvent starts a new message with panic level.
func (l Logger) PanicEvent() *Event {
	return l.newEvent(PanicLevel, func(msg string) { panic(msg) })
}

// Err starts a new message with error level with err as a field if not nil.
func (l Logger) Err(err error) *Event {
	if err != nil {
		return l.ErrorEvent().Err(err)
	}
	return l.InfoEvent()
}

// WithLevel starts a new message with the specified level.
func (l Logger) WithLevel(level Level) *Event {
	switch level {
	case TraceLevel:
		return l.TraceEvent()
	case DebugLevel:
		return l.DebugEvent()
	case InfoLevel:
		return l.InfoEvent()
	case WarnLevel:
		return l.WarnEvent()
	case ErrorLevel:
		return l.ErrorEvent()
	case FatalLevel:
		return l.newEvent(FatalLevel, nil)
	case PanicLevel:
		return l.newEvent(PanicLevel, nil)
	case NoLevel:
		return l.LogEvent()
	case Disabled:
		return nil
	default:
		return l.newEvent(level, nil)
	}
}

// LogEvent starts a new message with no level.
func (l Logger) LogEvent() *Event {
	return l.newEvent(NoLevel, nil)
}

// Print sends a log event using debug level.
func (l Logger) Print(v ...interface{}) {
	if e := l.DebugEvent(); e.Enabled() {
		e.CallerSkipFrame(1).Msg(fmt.Sprint(v...))
	}
}

// Printf sends a log event using debug level.
func (l Logger) Printf(format string, v ...interface{}) {
	if e := l.DebugEvent(); e.Enabled() {
		e.CallerSkipFrame(1).Msg(fmt.Sprintf(format, v...))
	}
}

// Write implements the io.Writer interface.
func (l Logger) Write(p []byte) (n int, err error) {
	n = len(p)
	if n > 0 && p[n-1] == '\n' {
		p = p[0 : n-1]
	}
	l.LogEvent().CallerSkipFrame(1).Msg(string(p))
	return
}

func (l Logger) newEvent(level Level, done func(string)) *Event {
	enabled := l.should(level)
	if !enabled {
		if done != nil {
			done("")
		}
		return nil
	}
	e := newEvent(l.w, level, l.stack, l.ctx, l.hooks)
	e.done = done
	if level != NoLevel && LevelFieldName != "" {
		e.Str(LevelFieldName, LevelFieldMarshalFunc(level))
	}
	if len(l.context) > 1 {
		e.buf = enc.AppendObjectData(e.buf, l.context)
	}
	return e
}

func (l Logger) scratchEvent() *Event {
	return newEvent(LevelWriterAdapter{io.Discard}, DebugLevel, l.stack, l.ctx, l.hooks)
}

func (l Logger) should(lvl Level) bool {
	if l.w == nil {
		return false
	}
	if lvl < l.level || lvl < GlobalLevel() {
		return false
	}
	if l.sampler != nil && !samplingDisabled() {
		return l.sampler.Sample(lvl)
	}
	return true
}

