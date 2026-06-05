// Copyright (C) 2019-2025, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package log

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestNewLogger(t *testing.T) {
	l := New()
	if l == nil {
		t.Fatal("New() returned nil")
	}
	if l.IsZero() {
		t.Fatal("New() returned zero logger")
	}
}

func TestNewLoggerWithContext(t *testing.T) {
	l := New("component", "test", "version", "1.0")
	if l == nil {
		t.Fatal("New(...) returned nil")
	}
	if l.IsZero() {
		t.Fatal("New(...) returned zero logger")
	}
}

func TestNewWriterLogger(t *testing.T) {
	var buf bytes.Buffer
	l := NewWriter(&buf)
	if l == nil {
		t.Fatal("NewWriter() returned nil")
	}
}

func TestNoopLogger(t *testing.T) {
	l := Noop()
	if l == nil {
		t.Fatal("Noop() returned nil")
	}
	if !l.IsZero() {
		t.Fatal("Noop() should be zero")
	}
	if l.GetLevel() != Disabled {
		t.Fatalf("Noop() level = %v, want Disabled", l.GetLevel())
	}

	// Should not panic
	l.Info("test")
	l.Debug("test", "key", "value")
	l.Error("test")
	l.Warn("test")
	l.Trace("test")
}

func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	l := NewWriter(&buf).Level(WarnLevel)

	// Debug should be filtered out
	l.DebugEvent().Msg("should not appear")
	if buf.Len() > 0 {
		t.Fatalf("debug message should be filtered at warn level, got: %s", buf.String())
	}

	// Info should be filtered out
	l.InfoEvent().Msg("should not appear")
	if buf.Len() > 0 {
		t.Fatalf("info message should be filtered at warn level, got: %s", buf.String())
	}

	// Warn should pass
	l.WarnEvent().Msg("warning")
	if buf.Len() == 0 {
		t.Fatal("warn message should pass at warn level")
	}

	buf.Reset()

	// Error should pass
	l.ErrorEvent().Msg("error")
	if buf.Len() == 0 {
		t.Fatal("error message should pass at warn level")
	}
}

func TestLevelString(t *testing.T) {
	tests := []struct {
		level Level
		want  string
	}{
		{TraceLevel, "trace"},
		{DebugLevel, "debug"},
		{InfoLevel, "info"},
		{WarnLevel, "warn"},
		{ErrorLevel, "error"},
		{FatalLevel, "fatal"},
		{PanicLevel, "panic"},
		{Disabled, "disabled"},
		{NoLevel, ""},
	}

	for _, tt := range tests {
		got := tt.level.String()
		if got != tt.want {
			t.Errorf("Level(%d).String() = %q, want %q", tt.level, got, tt.want)
		}
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input string
		want  Level
		err   bool
	}{
		{"trace", TraceLevel, false},
		{"debug", DebugLevel, false},
		{"info", InfoLevel, false},
		{"warn", WarnLevel, false},
		{"error", ErrorLevel, false},
		{"fatal", FatalLevel, false},
		{"panic", PanicLevel, false},
		{"disabled", Disabled, false},
		{"INFO", InfoLevel, false},
		{"WARN", WarnLevel, false},
		{"bogus", NoLevel, true},
	}

	for _, tt := range tests {
		got, err := ParseLevel(tt.input)
		if tt.err && err == nil {
			t.Errorf("ParseLevel(%q) expected error", tt.input)
		}
		if !tt.err && err != nil {
			t.Errorf("ParseLevel(%q) unexpected error: %v", tt.input, err)
		}
		if got != tt.want {
			t.Errorf("ParseLevel(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestToLevel(t *testing.T) {
	tests := []struct {
		input string
		want  Level
		err   bool
	}{
		{"trace", TraceLevel, false},
		{"trce", TraceLevel, false},
		{"verbo", TraceLevel, false},
		{"verbose", TraceLevel, false},
		{"debug", DebugLevel, false},
		{"dbug", DebugLevel, false},
		{"info", InfoLevel, false},
		{"warn", WarnLevel, false},
		{"warning", WarnLevel, false},
		{"error", ErrorLevel, false},
		{"eror", ErrorLevel, false},
		{"fatal", FatalLevel, false},
		{"panic", PanicLevel, false},
		{"disabled", Disabled, false},
		{"off", Disabled, false},
		{"unknown", NoLevel, true},
	}

	for _, tt := range tests {
		got, err := ToLevel(tt.input)
		if tt.err && err == nil {
			t.Errorf("ToLevel(%q) expected error", tt.input)
		}
		if !tt.err && err != nil {
			t.Errorf("ToLevel(%q) unexpected error: %v", tt.input, err)
		}
		if got != tt.want {
			t.Errorf("ToLevel(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestToFormat(t *testing.T) {
	tests := []struct {
		input string
		want  LogFormat
		err   bool
	}{
		{"plain", Plain, false},
		{"text", Plain, false},
		{"", Plain, false},
		{"json", JSON, false},
		{"auto", Auto, false},
		{"colors", Colors, false},
		{"color", Colors, false},
		{"unknown", Plain, true},
	}

	for _, tt := range tests {
		got, err := ToFormat(tt.input, 0)
		if tt.err && err == nil {
			t.Errorf("ToFormat(%q) expected error", tt.input)
		}
		if !tt.err && err != nil {
			t.Errorf("ToFormat(%q) unexpected error: %v", tt.input, err)
		}
		if got != tt.want {
			t.Errorf("ToFormat(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestLevelMarshalText(t *testing.T) {
	for _, level := range []Level{TraceLevel, DebugLevel, InfoLevel, WarnLevel, ErrorLevel} {
		text, err := level.MarshalText()
		if err != nil {
			t.Errorf("MarshalText(%v) error: %v", level, err)
			continue
		}
		var parsed Level
		if err := parsed.UnmarshalText(text); err != nil {
			t.Errorf("UnmarshalText(%q) error: %v", text, err)
			continue
		}
		if parsed != level {
			t.Errorf("roundtrip: got %v, want %v", parsed, level)
		}
	}
}

func TestJSONOutput(t *testing.T) {
	var buf bytes.Buffer
	l := NewWriter(&buf).With().Str("component", "test").Logger()

	l.InfoEvent().Str("key", "value").Msg("hello")

	var m map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("output is not valid JSON: %v\nraw: %s", err, buf.String())
	}

	if m[LevelFieldName] != LevelInfoValue {
		t.Errorf("level = %v, want %v", m[LevelFieldName], LevelInfoValue)
	}
	if m[MessageFieldName] != "hello" {
		t.Errorf("message = %v, want hello", m[MessageFieldName])
	}
	if m["component"] != "test" {
		t.Errorf("component = %v, want test", m["component"])
	}
	if m["key"] != "value" {
		t.Errorf("key = %v, want value", m["key"])
	}
}

func TestGethStyleLogging(t *testing.T) {
	var buf bytes.Buffer
	l := NewWriter(&buf)

	l.Info("server started", "port", 8080, "host", "localhost")

	output := buf.String()
	if !strings.Contains(output, "server started") {
		t.Errorf("output missing message, got: %s", output)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("geth-style output is not valid JSON: %v\nraw: %s", err, buf.String())
	}

	if m["port"] != float64(8080) {
		t.Errorf("port = %v, want 8080", m["port"])
	}
}

func TestChildLogger(t *testing.T) {
	var buf bytes.Buffer
	parent := NewWriter(&buf).With().Str("parent", "true").Logger()
	child := parent.New("child", "true")

	child.InfoEvent().Msg("from child")

	var m map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("output is not valid JSON: %v\nraw: %s", err, buf.String())
	}

	if m["parent"] != "true" {
		t.Error("child logger missing parent context")
	}
	if m["child"] != "true" {
		t.Error("child logger missing own context")
	}
}

func TestGetLevel(t *testing.T) {
	var buf bytes.Buffer
	l := NewWriter(&buf).Level(ErrorLevel)
	if l.GetLevel() != ErrorLevel {
		t.Errorf("GetLevel() = %v, want ErrorLevel", l.GetLevel())
	}
}

func TestGlobalLevel(t *testing.T) {
	old := GlobalLevel()
	defer SetGlobalLevel(old)

	SetGlobalLevel(ErrorLevel)
	if GlobalLevel() != ErrorLevel {
		t.Fatalf("GlobalLevel() = %v, want ErrorLevel", GlobalLevel())
	}

	var buf bytes.Buffer
	l := NewWriter(&buf).Level(DebugLevel)

	// Even though logger is debug, global is error — debug should be filtered
	l.DebugEvent().Msg("should not appear")
	if buf.Len() > 0 {
		t.Fatalf("global level should filter debug, got: %s", buf.String())
	}

	l.ErrorEvent().Msg("should appear")
	if buf.Len() == 0 {
		t.Fatal("error should pass global error level")
	}
}

func TestFactoryMake(t *testing.T) {
	f := NewFactoryWithConfig(Config{
		LogLevel:                InfoLevel,
		DisplayLevel:            WarnLevel,
		DisableWriterDisplaying: true,
	})
	defer f.Close()

	l, err := f.Make("test")
	if err != nil {
		t.Fatalf("Make() error: %v", err)
	}
	if l == nil {
		t.Fatal("Make() returned nil logger")
	}

	// Same name should return same logger
	l2, err := f.Make("test")
	if err != nil {
		t.Fatalf("Make() second call error: %v", err)
	}
	if l != l2 {
		t.Fatal("Make() should return same logger for same name")
	}
}

func TestFactorySetLogLevel(t *testing.T) {
	f := NewFactoryWithConfig(Config{
		LogLevel:                InfoLevel,
		DisplayLevel:            WarnLevel,
		DisableWriterDisplaying: true,
	})
	defer f.Close()

	_, err := f.Make("test")
	if err != nil {
		t.Fatalf("Make() error: %v", err)
	}

	// Verify initial level
	level, err := f.GetLogLevel("test")
	if err != nil {
		t.Fatalf("GetLogLevel() error: %v", err)
	}
	if level != InfoLevel {
		t.Errorf("initial GetLogLevel() = %v, want InfoLevel", level)
	}

	// SetLogLevel updates the internal tracking; re-fetch via Make to get updated logger
	f.SetLogLevel("test", DebugLevel)
	l2, err := f.Make("test")
	if err != nil {
		t.Fatalf("Make() after SetLogLevel error: %v", err)
	}
	if l2 == nil {
		t.Fatal("Make() after SetLogLevel returned nil")
	}
}

func TestFactoryClose(t *testing.T) {
	f := NewFactoryWithConfig(Config{
		LogLevel:                InfoLevel,
		DisableWriterDisplaying: true,
	})

	_, err := f.Make("before-close")
	if err != nil {
		t.Fatalf("Make() error: %v", err)
	}

	f.Close()

	// After close, Make should return noop
	l, err := f.Make("after-close")
	if err != nil {
		t.Fatalf("Make() after Close() error: %v", err)
	}
	if !l.IsZero() {
		t.Fatal("Make() after Close() should return noop logger")
	}
}

func TestNoLog(t *testing.T) {
	var nl NoLog
	if !nl.IsZero() {
		t.Fatal("NoLog.IsZero() should be true")
	}
	if nl.GetLevel() != Disabled {
		t.Fatalf("NoLog.GetLevel() = %v, want Disabled", nl.GetLevel())
	}

	// Should not panic
	nl.Info("test")
	nl.Debug("test")
	nl.Error("test")
	nl.Warn("test")
	nl.Trace("test")

	n, err := nl.Write([]byte("test"))
	if n != 4 || err != nil {
		t.Errorf("NoLog.Write() = %d, %v, want 4, nil", n, err)
	}
}

func TestDisableSampling(t *testing.T) {
	DisableSampling(true)
	if !samplingDisabled() {
		t.Fatal("samplingDisabled() should be true")
	}
	DisableSampling(false)
	if samplingDisabled() {
		t.Fatal("samplingDisabled() should be false")
	}
}

func TestColorWrap(t *testing.T) {
	// Standard color
	got := Red.Wrap("hello")
	if !strings.Contains(got, "hello") {
		t.Errorf("Red.Wrap() should contain text")
	}
	if !strings.HasPrefix(got, "\x1b[31m") {
		t.Errorf("Red.Wrap() should start with ANSI red code")
	}

	// 256-color
	got = Orange.Wrap("hello")
	if !strings.Contains(got, "38;5;208") {
		t.Errorf("Orange.Wrap() should use 256-color format")
	}
}
