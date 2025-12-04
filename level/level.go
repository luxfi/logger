package level

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap/zapcore"
)

// Level represents a logging level
// Values are aligned with zapcore.Level for direct casting
type Level int8

const (
	// Verbo is the most verbose level, below debug
	Verbo Level = -2
	// Debug level (matches zapcore.DebugLevel = -1)
	Debug Level = -1
	// Trace level (same as debug since zap doesn't have trace)
	Trace Level = -1
	// Info level (matches zapcore.InfoLevel = 0)
	Info Level = 0
	// Warn level (matches zapcore.WarnLevel = 1)
	Warn Level = 1
	// Error level (matches zapcore.ErrorLevel = 2)
	Error Level = 2
	// Fatal level (matches zapcore.FatalLevel = 5)
	Fatal Level = 5
	// Off disables logging
	Off Level = 6
)

var ErrUnknownLevel = errors.New("unknown log level")

// String returns the string representation of a Level
func (l Level) String() string {
	switch l {
	case Off:
		return "OFF"
	case Fatal:
		return "FATAL"
	case Error:
		return "ERROR"
	case Warn:
		return "WARN"
	case Info:
		return "INFO"
	case Debug: // Debug and Trace are both -1, mapped to DEBUG
		return "DEBUG"
	case Verbo:
		return "VERBO"
	default:
		return "UNKNO"
	}
}

// LowerString returns the lowercase string representation of a Level
func (l Level) LowerString() string {
	return strings.ToLower(l.String())
}

// MarshalJSON marshals the Level to JSON
func (l Level) MarshalJSON() ([]byte, error) {
	return json.Marshal(l.String())
}

// UnmarshalJSON unmarshals the Level from JSON
func (l *Level) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	var err error
	*l, err = ToLevel(str)
	return err
}

// ToLevel converts a string to a Level
func ToLevel(l string) (Level, error) {
	switch strings.ToUpper(l) {
	case "OFF":
		return Off, nil
	case "FATAL":
		return Fatal, nil
	case "ERROR":
		return Error, nil
	case "WARN":
		return Warn, nil
	case "INFO":
		return Info, nil
	case "TRACE":
		return Trace, nil
	case "DEBUG":
		return Debug, nil
	case "VERBO":
		return Verbo, nil
	default:
		return Off, fmt.Errorf("%w: %q", ErrUnknownLevel, l)
	}
}

// ToZapLevel converts our Level to zapcore.Level
func ToZapLevel(level Level) zapcore.Level {
	return zapcore.Level(level)
}

// FromZapLevel converts zapcore.Level to our Level
func FromZapLevel(level zapcore.Level) Level {
	return Level(level)
}
