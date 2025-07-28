package log

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/exp/maps"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/luxfi/log/level"
)

// Level is an alias for level.Level for backwards compatibility
type Level = level.Level

// Re-export level error
var ErrUnknownLevel = level.ErrUnknownLevel

// Re-export ToLevel for backwards compatibility
func ToLevel(l string) (Level, error) {
	return level.ToLevel(l)
}

// RotatingWriterConfig defines rotating log file configuration
type RotatingWriterConfig struct {
	MaxSize   int    `json:"maxSize"` // in megabytes
	MaxFiles  int    `json:"maxFiles"`
	MaxAge    int    `json:"maxAge"` // in days
	Directory string `json:"directory"`
	Compress  bool   `json:"compress"`
}

// Config defines the configuration of a logger
type Config struct {
	RotatingWriterConfig
	DisableWriterDisplaying bool   `json:"disableWriterDisplaying"`
	LogLevel                Level  `json:"logLevel"`
	DisplayLevel            Level  `json:"displayLevel"`
	LogFormat               Format `json:"logFormat"`
	MsgPrefix               string `json:"-"`
	LoggerName              string `json:"-"`
}

// Format specifies the log format
type Format int

const (
	Auto Format = iota
	Plain
	Colors
	JSON
)

// Color represents ANSI color codes
type Color string

// Colors
const (
	Black       Color = "\033[0;30m"
	DarkGray    Color = "\033[1;30m"
	Red         Color = "\033[0;31m"
	LightRed    Color = "\033[1;31m"
	Green       Color = "\033[0;32m"
	LightGreen  Color = "\033[1;32m"
	Orange      Color = "\033[0;33m"
	Yellow      Color = "\033[1;33m"
	Blue        Color = "\033[0;34m"
	LightBlue   Color = "\033[1;34m"
	Purple      Color = "\033[0;35m"
	LightPurple Color = "\033[1;35m"
	Cyan        Color = "\033[0;36m"
	LightCyan   Color = "\033[1;36m"
	LightGray   Color = "\033[0;37m"
	White       Color = "\033[1;37m"

	Reset   Color = "\033[0;0m"
	Bold    Color = "\033[;1m"
	Reverse Color = "\033[;7m"
)

var (
	levelToColor = map[Level]Color{
		level.Fatal: Red,
		level.Error: Orange,
		level.Warn:  Yellow,
		level.Info:  Reset,
		level.Trace: LightPurple,
		level.Debug: LightBlue,
		level.Verbo: LightGreen,
	}

	levelToCapitalColorString = make(map[Level]string, len(levelToColor))
	unknownLevelColor         = Reset
)

// Wrap wraps text with color
func (lc Color) Wrap(text string) string {
	return string(lc) + text + string(Reset)
}

// MarshalJSON marshals Format to JSON
func (f Format) MarshalJSON() ([]byte, error) {
	formatJSON := []string{`"auto"`, `"plain"`, `"colors"`, `"json"`}
	if f < 0 || int(f) >= len(formatJSON) {
		return nil, errors.New("unknown format")
	}
	return []byte(formatJSON[f]), nil
}

// ToFormat converts a string to Format
func ToFormat(h string, fd uintptr) (Format, error) {
	switch strings.ToLower(h) {
	case "auto":
		// Note: We're not checking if it's a terminal for now
		// This would require importing golang.org/x/term
		return Colors, nil
	case "plain":
		return Plain, nil
	case "colors":
		return Colors, nil
	case "json":
		return JSON, nil
	default:
		return Plain, fmt.Errorf("unknown format mode: %s", h)
	}
}

// Factory interface for creating loggers - extended version with all methods needed by node
type Factory interface {
	// Make creates a new logger with name [name]
	Make(name string) (Logger, error)

	// MakeChain creates a new logger to log the events of chain [chainID]
	MakeChain(chainID string) (Logger, error)

	// SetLogLevel sets log levels for all loggers in factory with given logger name, level pairs.
	SetLogLevel(name string, level Level) error

	// SetDisplayLevel sets log display levels for all loggers in factory with given logger name, level pairs.
	SetDisplayLevel(name string, level Level) error

	// GetLogLevel returns all log levels in factory as name, level pairs
	GetLogLevel(name string) (Level, error)

	// GetDisplayLevel returns all log display levels in factory as name, level pairs
	GetDisplayLevel(name string) (Level, error)

	// GetLoggerNames returns the names of all logs created by this factory
	GetLoggerNames() []string

	// Close stops and clears all of a Factory's instantiated loggers
	Close()

	// Legacy methods for compatibility
	New(name string) Logger
	NewWithFields(name string, fields ...zap.Field) Logger
}

type logWrapper struct {
	logger       Logger
	displayLevel zap.AtomicLevel
	logLevel     zap.AtomicLevel
}

type factory struct {
	config Config
	lock   sync.RWMutex

	// For each logger created by this factory:
	// Logger name --> the logger.
	loggers map[string]logWrapper
}

// NewFactory creates a new logger factory with config
func NewFactoryWithConfig(config Config) Factory {
	return &factory{
		config:  config,
		loggers: make(map[string]logWrapper),
	}
}

const termTimeFormat = "[01-02|15:04:05.000]"

var (
	defaultEncoderConfig = zapcore.EncoderConfig{
		TimeKey:        "timestamp",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
	jsonEncoderConfig zapcore.EncoderConfig
	termTimeEncoder   = zapcore.TimeEncoderOfLayout(termTimeFormat)
)

func init() {
	jsonEncoderConfig = defaultEncoderConfig
	jsonEncoderConfig.EncodeLevel = jsonLevelEncoder
	jsonEncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	jsonEncoderConfig.EncodeDuration = zapcore.NanosDurationEncoder
	for level, color := range levelToColor {
		levelToCapitalColorString[level] = color.Wrap(level.String())
	}
}

func levelEncoder(l zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(Level(l).String())
}

func jsonLevelEncoder(l zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(Level(l).LowerString())
}

func ConsoleColorLevelEncoder(l zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
	s, ok := levelToCapitalColorString[Level(l)]
	if !ok {
		s = unknownLevelColor.Wrap(l.String())
	}
	enc.AppendString(s)
}

func newTermEncoderConfig(lvlEncoder zapcore.LevelEncoder) zapcore.EncoderConfig {
	config := defaultEncoderConfig
	config.EncodeLevel = lvlEncoder
	config.EncodeTime = termTimeEncoder
	config.ConsoleSeparator = " "
	return config
}

// ConsoleEncoder returns a zapcore.Encoder for console output
func (f Format) ConsoleEncoder() zapcore.Encoder {
	switch f {
	case Colors:
		return zapcore.NewConsoleEncoder(newTermEncoderConfig(ConsoleColorLevelEncoder))
	case JSON:
		return zapcore.NewJSONEncoder(jsonEncoderConfig)
	default:
		return zapcore.NewConsoleEncoder(newTermEncoderConfig(levelEncoder))
	}
}

// FileEncoder returns a zapcore.Encoder for file output
func (f Format) FileEncoder() zapcore.Encoder {
	switch f {
	case JSON:
		return zapcore.NewJSONEncoder(jsonEncoderConfig)
	default:
		return zapcore.NewConsoleEncoder(newTermEncoderConfig(levelEncoder))
	}
}

// WrapPrefix adds a prefix to messages if non-empty
func (f Format) WrapPrefix(prefix string) string {
	if prefix == "" || f == JSON {
		return prefix
	}
	return fmt.Sprintf("<%s>", prefix)
}

// toZapLevel converts our Level to zapcore.Level
func toZapLevel(l Level) zapcore.Level {
	return level.ToZapLevel(l)
}

// NewWrappedCore creates a wrapped core with atomic level
func NewWrappedCore(lvl Level, writer zapcore.WriteSyncer, encoder zapcore.Encoder) *WrappedCore {
	atomicLevel := zap.NewAtomicLevelAt(toZapLevel(lvl))
	core := zapcore.NewCore(encoder, writer, atomicLevel)
	return &WrappedCore{
		Core:           core,
		AtomicLevel:    atomicLevel,
		Writer:         writer,
		WriterDisabled: false,
	}
}

// WrappedCore wraps a zapcore.Core with additional functionality
type WrappedCore struct {
	zapcore.Core
	AtomicLevel    zap.AtomicLevel
	Writer         zapcore.WriteSyncer
	WriterDisabled bool
}

// Write implements zapcore.Core
func (c *WrappedCore) Write(ent zapcore.Entry, fields []zapcore.Field) error {
	if c.WriterDisabled {
		return nil
	}
	return c.Core.Write(ent, fields)
}

// Check implements zapcore.Core
func (c *WrappedCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.AtomicLevel.Level() > ent.Level {
		return ce
	}
	return c.Core.Check(ent, ce)
}

// With implements zapcore.Core
func (c *WrappedCore) With(fields []zapcore.Field) zapcore.Core {
	return &WrappedCore{
		Core:           c.Core.With(fields),
		AtomicLevel:    c.AtomicLevel,
		Writer:         c.Writer,
		WriterDisabled: c.WriterDisabled,
	}
}

// Sync implements zapcore.Core
func (c *WrappedCore) Sync() error {
	return c.Core.Sync()
}

// Enabled implements zapcore.Core
func (c *WrappedCore) Enabled(level zapcore.Level) bool {
	return c.AtomicLevel.Enabled(level)
}

// Assumes [f.lock] is held
func (f *factory) makeLogger(config Config) (Logger, error) {
	if _, ok := f.loggers[config.LoggerName]; ok {
		return nil, fmt.Errorf("logger with name %q already exists", config.LoggerName)
	}
	consoleEnc := config.LogFormat.ConsoleEncoder()
	fileEnc := config.LogFormat.FileEncoder()

	consoleCore := NewWrappedCore(config.DisplayLevel, zapcore.AddSync(os.Stdout), consoleEnc)
	consoleCore.WriterDisabled = config.DisableWriterDisplaying

	rw := &lumberjack.Logger{
		Filename:   path.Join(config.Directory, config.LoggerName+".log"),
		MaxSize:    config.MaxSize,  // megabytes
		MaxAge:     config.MaxAge,   // days
		MaxBackups: config.MaxFiles, // files
		Compress:   config.Compress,
	}
	fileCore := NewWrappedCore(config.LogLevel, zapcore.AddSync(rw), fileEnc)

	// Combine cores with prefix if needed
	cores := []zapcore.Core{consoleCore, fileCore}
	core := zapcore.NewTee(cores...)

	zapLogger := zap.New(core)
	if config.MsgPrefix != "" {
		zapLogger = zapLogger.Named(config.MsgPrefix)
	}

	l := NewZapLogger(zapLogger)
	f.loggers[config.LoggerName] = logWrapper{
		logger:       l,
		displayLevel: consoleCore.AtomicLevel,
		logLevel:     fileCore.AtomicLevel,
	}
	return l, nil
}

func (f *factory) Make(name string) (Logger, error) {
	f.lock.Lock()
	defer f.lock.Unlock()

	config := f.config
	config.LoggerName = name
	return f.makeLogger(config)
}

func (f *factory) MakeChain(chainID string) (Logger, error) {
	f.lock.Lock()
	defer f.lock.Unlock()

	config := f.config
	config.MsgPrefix = chainID + " Chain"
	config.LoggerName = chainID
	return f.makeLogger(config)
}

func (f *factory) SetLogLevel(name string, level Level) error {
	f.lock.RLock()
	defer f.lock.RUnlock()

	logger, ok := f.loggers[name]
	if !ok {
		return fmt.Errorf("logger with name %q not found", name)
	}
	logger.logLevel.SetLevel(toZapLevel(level))
	return nil
}

func (f *factory) SetDisplayLevel(name string, level Level) error {
	f.lock.RLock()
	defer f.lock.RUnlock()

	logger, ok := f.loggers[name]
	if !ok {
		return fmt.Errorf("logger with name %q not found", name)
	}
	logger.displayLevel.SetLevel(toZapLevel(level))
	return nil
}

func (f *factory) GetLogLevel(name string) (Level, error) {
	f.lock.RLock()
	defer f.lock.RUnlock()

	logger, ok := f.loggers[name]
	if !ok {
		return -1, fmt.Errorf("logger with name %q not found", name)
	}
	return fromZapLevel(logger.logLevel.Level()), nil
}

func (f *factory) GetDisplayLevel(name string) (Level, error) {
	f.lock.RLock()
	defer f.lock.RUnlock()

	logger, ok := f.loggers[name]
	if !ok {
		return -1, fmt.Errorf("logger with name %q not found", name)
	}
	return fromZapLevel(logger.displayLevel.Level()), nil
}

func (f *factory) GetLoggerNames() []string {
	f.lock.RLock()
	defer f.lock.RUnlock()

	return maps.Keys(f.loggers)
}

func (f *factory) Close() {
	f.lock.Lock()
	defer f.lock.Unlock()

	for _, lw := range f.loggers {
		lw.logger.Stop()
	}
	f.loggers = nil
}

// Legacy methods for compatibility
func (f *factory) New(name string) Logger {
	logger, err := f.Make(name)
	if err != nil {
		// Fallback to creating a new logger
		config := zap.NewProductionConfig()
		config.DisableStacktrace = true
		config.Encoding = "console"
		zapLogger, _ := config.Build()
		return NewZapLogger(zapLogger.Named(name))
	}
	return logger
}

func (f *factory) NewWithFields(name string, fields ...zap.Field) Logger {
	logger := f.New(name)
	return logger.WithFields(fields...)
}

// fromZapLevel converts zapcore.Level to our Level
func fromZapLevel(l zapcore.Level) Level {
	return level.FromZapLevel(l)
}

// discard is a writer that discards all data
type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
func (discard) Close() error                { return nil }

// Discard is a writer that discards all data
var Discard io.WriteCloser = discard{}

// NewLogger creates a logger with custom cores
func NewLogger(prefix string, wrappedCores ...WrappedCore) Logger {
	cores := make([]zapcore.Core, len(wrappedCores))
	for i, wc := range wrappedCores {
		cores[i] = &wc
	}
	core := zapcore.NewTee(cores...)
	zapLogger := zap.New(core)
	if prefix != "" {
		zapLogger = zapLogger.Named(prefix)
	}
	return NewZapLogger(zapLogger)
}
