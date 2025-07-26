// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package log

import (
	"testing"
)

func TestNoOpLogger(t *testing.T) {
	logger := NewNoOpLogger()
	
	// These should not panic
	logger.Debug("debug message")
	logger.Info("info message")
	logger.Warn("warn message")
	logger.Error("error message")
	
	logger.Debugf("debug %s", "formatted")
	logger.Infof("info %s", "formatted")
	logger.Warnf("warn %s", "formatted")
	logger.Errorf("error %s", "formatted")
	
	// Test chaining
	logger.With(String("key", "value")).Named("test").Info("chained")
	
	// Test level
	logger.SetLevel(DebugLevel)
	if logger.GetLevel() != DebugLevel {
		t.Errorf("expected debug level, got %v", logger.GetLevel())
	}
}

func TestNoOpFactory(t *testing.T) {
	factory := NewNoOpFactory()
	
	logger1 := factory.New("test1")
	logger2 := factory.NewWithFields("test2", String("key", "value"))
	root := factory.Root()
	
	// These should not panic
	logger1.Info("logger1")
	logger2.Info("logger2")
	root.Info("root")
}

func TestZapLogger(t *testing.T) {
	// Test with default config
	config := DefaultZapConfig()
	logger, err := NewZapLogger(config)
	if err != nil {
		t.Fatalf("failed to create zap logger: %v", err)
	}
	
	// These should not panic
	logger.Debug("debug message")
	logger.Info("info message")
	logger.Warn("warn message")
	logger.Error("error message")
	
	logger.Debugf("debug %s", "formatted")
	logger.Infof("info %s", "formatted")
	logger.Warnf("warn %s", "formatted")
	logger.Errorf("error %s", "formatted")
	
	// Test chaining
	logger.With(String("key", "value")).Named("test").Info("chained")
	
	// Test level
	logger.SetLevel(DebugLevel)
	if logger.GetLevel() != DebugLevel {
		t.Errorf("expected debug level, got %v", logger.GetLevel())
	}
}

func TestZapFactory(t *testing.T) {
	config := DefaultZapConfig()
	factory, err := NewZapFactory(config)
	if err != nil {
		t.Fatalf("failed to create zap factory: %v", err)
	}
	
	logger1 := factory.New("test1")
	logger2 := factory.NewWithFields("test2", String("key", "value"))
	root := factory.Root()
	
	// These should not panic
	logger1.Info("logger1")
	logger2.Info("logger2")
	root.Info("root")
}

func TestFields(t *testing.T) {
	// Test field constructors
	strField := String("key", "value")
	if strField.Key != "key" || strField.Value != "value" {
		t.Error("String field mismatch")
	}
	
	intField := Int("count", 42)
	if intField.Key != "count" || intField.Value != 42 {
		t.Error("Int field mismatch")
	}
	
	errField := Error(nil)
	if errField.Key != "error" || errField.Value != nil {
		t.Error("Error field mismatch")
	}
	
	anyField := Any("data", struct{}{})
	if anyField.Key != "data" {
		t.Error("Any field mismatch")
	}
}