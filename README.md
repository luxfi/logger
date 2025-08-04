# Lux Log Package

A unified logging package for the Lux ecosystem that provides a consistent logging interface across all projects while abstracting away the underlying implementation details.

## Overview

The `log` package is designed to:
- Provide a consistent logging API across all Lux projects
- Abstract away the underlying logging implementation (currently zap)
- Support both structured and unstructured logging
- Maintain compatibility with different logging styles (geth-style, zap-style)
- Enable easy configuration and customization

## Features

### 1. Multiple Logging Styles

#### Structured Logging (Recommended)
```go
// Using the logger interface with zap-style fields
logger.Info("user logged in", 
    log.String("username", username),
    log.Int("user_id", userID),
    log.Duration("session_timeout", timeout),
)

// Error logging with stack trace
logger.Error("failed to process request",
    log.Error(err),
    log.String("request_id", reqID),
    log.Stack("stacktrace"),
)
```

#### Geth-Compatible Logging
```go
// Using variadic key-value pairs
logger.Info("block processed", "number", blockNum, "hash", blockHash, "txs", txCount)

// Global logger functions
log.Info("application started", "version", version, "config", configPath)
log.Error("connection failed", "error", err, "retry_in", retryDelay)
```

#### Simple String Logging
```go
// Basic logging without context
logger.Info("Starting server...")
logger.Warn("Deprecation warning: this feature will be removed")
logger.Error("Critical error occurred")
```

### 2. Global Logger

For quick logging without logger instantiation:

```go
import "github.com/luxfi/log"

// Global logging functions
log.Info("server started", "port", 8080)
log.Debug("processing request", "method", "GET", "path", "/api/v1/status")
log.Error("database connection failed", "error", err)
log.Warn("high memory usage", "usage_mb", memUsage)
```

### 3. Logger Creation and Configuration

```go
// Create a logger factory with configuration
logFactory := log.NewFactoryWithConfig(log.Config{
    RotatingWriterConfig: log.RotatingWriterConfig{
        Directory: "/var/log/myapp",
        MaxSize:   100, // 100 MB per file
        MaxFiles:  10,  // Keep 10 files
        MaxAge:    30,  // 30 days
        Compress:  true,
    },
    LogLevel:     log.Info,
    DisplayLevel: log.Info,
    LogFormat:    log.JSON, // or log.Console
})

// Create named loggers
mainLogger, _ := logFactory.Make("main")
apiLogger, _ := logFactory.Make("api")
dbLogger, _ := logFactory.Make("database")
```

### 4. Log Levels

Supported log levels (from lowest to highest severity):
- `Trace` - Detailed debugging information
- `Debug` - Debugging information
- `Info` - Informational messages
- `Warn` - Warning messages
- `Error` - Error messages
- `Fatal/Crit` - Critical errors (may terminate the program)

### 5. Field Types

The package provides type-safe field constructors that abstract away zap types:

```go
// Basic types
log.String("key", "value")
log.Int("count", 42)
log.Bool("enabled", true)
log.Float64("ratio", 0.95)
log.Duration("elapsed", time.Second)
log.Time("timestamp", time.Now())

// Error handling
log.Error(err)
log.NamedError("cause", err)

// Complex types
log.Any("data", complexObject)
log.Reflect("object", anyValue)
log.Binary("payload", []byte{...})

// Structured data
log.Object("user", userMarshaler)
log.Array("items", itemArrayMarshaler)

// Namespacing
log.Namespace("http")
```

### 6. Context and Child Loggers

```go
// Create a logger with context
requestLogger := logger.With(
    log.String("request_id", reqID),
    log.String("user_id", userID),
)

// All subsequent logs will include the context
requestLogger.Info("processing request")
requestLogger.Error("request failed", log.Error(err))
```

### 7. Performance Considerations

- Field constructors are lazy - expensive operations are deferred
- Use `log.Skip()` for conditional fields
- Prefer typed field constructors over `log.Any()`
- Use `log.Stack()` sparingly as it's expensive

## Usage Guidelines

### For New Projects

1. Always use the structured logging approach with typed fields
2. Create a logger factory at application startup
3. Use named loggers for different components
4. Include relevant context using `With()`

### For Existing Projects

The package maintains backward compatibility:
- Geth-style variadic logging works seamlessly
- Global logger functions are available
- No need to refactor existing code immediately

### Best Practices

1. **Use Structured Logging**: Prefer field constructors over variadic arguments
   ```go
   // Good
   logger.Info("user action", log.String("action", "login"), log.String("user", username))
   
   // Less preferred
   logger.Info("user action", "action", "login", "user", username)
   ```

2. **Include Context**: Add relevant context to loggers
   ```go
   // In HTTP handlers
   logger = logger.With(
       log.String("method", r.Method),
       log.String("path", r.URL.Path),
       log.String("remote_addr", r.RemoteAddr),
   )
   ```

3. **Use Appropriate Levels**: 
   - `Debug` for detailed debugging info
   - `Info` for normal operations
   - `Warn` for recoverable issues
   - `Error` for errors that need attention
   - `Fatal/Crit` for unrecoverable errors

4. **Handle Errors Properly**:
   ```go
   if err != nil {
       logger.Error("operation failed", 
           log.Error(err),
           log.String("operation", "data_sync"),
           log.Stack("stacktrace"),
       )
       return err
   }
   ```

## Configuration

### Environment Variables

- `LOG_LEVEL` - Set the minimum log level (trace, debug, info, warn, error, fatal)
- `LOG_FORMAT` - Set output format (json, console)
- `LOG_DIR` - Set log directory for file output

### Programmatic Configuration

```go
cfg := log.Config{
    LogLevel:     log.LevelFromString(os.Getenv("LOG_LEVEL")),
    DisplayLevel: log.Info,
    LogFormat:    log.JSON,
    RotatingWriterConfig: log.RotatingWriterConfig{
        Directory: "/var/log/myapp",
        MaxSize:   100,
        MaxFiles:  10,
        MaxAge:    30,
        Compress:  true,
    },
}
```

## Migration Guide

### From Direct Zap Usage

Replace zap imports and calls:
```go
// Before
import "go.uber.org/zap"
logger.Info("message", zap.String("key", "value"))

// After  
import "github.com/luxfi/log"
logger.Info("message", log.String("key", "value"))
```

### From Geth-style Logging

No changes required - the package supports geth-style logging:
```go
// This continues to work
log.Info("Block validated", "number", block.Number, "hash", block.Hash)
```

## Examples

### Basic Application Setup

```go
package main

import (
    "github.com/luxfi/log"
)

func main() {
    // Create logger factory
    logFactory := log.NewFactoryWithConfig(log.DefaultConfig())
    logger, _ := logFactory.Make("app")
    
    // Set as global logger
    log.SetGlobalLogger(logger)
    
    // Use throughout application
    log.Info("application started")
    
    // Create component loggers
    dbLogger, _ := logFactory.Make("database")
    apiLogger, _ := logFactory.Make("api")
    
    // Pass to components
    db := NewDatabase(dbLogger)
    api := NewAPI(apiLogger)
}
```

### HTTP Middleware

```go
func LoggingMiddleware(logger log.Logger) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            start := time.Now()
            
            // Create request-scoped logger
            reqLogger := logger.With(
                log.String("method", r.Method),
                log.String("path", r.URL.Path),
                log.String("remote_addr", r.RemoteAddr),
                log.String("request_id", generateRequestID()),
            )
            
            // Add logger to context
            ctx := context.WithValue(r.Context(), "logger", reqLogger)
            r = r.WithContext(ctx)
            
            // Log request start
            reqLogger.Info("request started")
            
            // Call next handler
            next.ServeHTTP(w, r)
            
            // Log request completion
            reqLogger.Info("request completed",
                log.Duration("duration", time.Since(start)),
            )
        })
    }
}
```

### Database Operations

```go
type Database struct {
    logger log.Logger
    conn   *sql.DB
}

func (db *Database) GetUser(ctx context.Context, userID string) (*User, error) {
    logger := db.logger.With(
        log.String("operation", "get_user"),
        log.String("user_id", userID),
    )
    
    logger.Debug("fetching user from database")
    
    var user User
    err := db.conn.QueryRowContext(ctx, "SELECT * FROM users WHERE id = ?", userID).Scan(&user)
    if err != nil {
        if err == sql.ErrNoRows {
            logger.Warn("user not found")
            return nil, ErrUserNotFound
        }
        logger.Error("database query failed", log.Error(err))
        return nil, err
    }
    
    logger.Debug("user fetched successfully")
    return &user, nil
}
```

## Performance Tips

1. **Avoid Expensive Operations in Hot Paths**:
   ```go
   // Bad - formats string even if debug is disabled
   logger.Debug(fmt.Sprintf("Processing %d items", len(items)))
   
   // Good - lazy evaluation
   logger.Debug("Processing items", log.Int("count", len(items)))
   ```

2. **Use Sampling for High-Volume Logs**:
   ```go
   // Configure sampling in production
   cfg := log.Config{
       LogLevel: log.Info,
       SamplingConfig: &log.SamplingConfig{
           Initial:    100,  // Log first 100 of each message
           Thereafter: 1000, // Then every 1000th
       },
   }
   ```

3. **Pre-allocate Fields for Repeated Use**:
   ```go
   // Pre-compute common fields
   baseFields := []log.Field{
       log.String("service", "api"),
       log.String("version", "1.0.0"),
   }
   
   // Reuse in hot path
   logger.Info("request processed", append(baseFields, 
       log.String("endpoint", endpoint),
       log.Duration("duration", elapsed),
   )...)
   ```

## Troubleshooting

### Common Issues

1. **No log output**: Check log level configuration
2. **Performance degradation**: Ensure not logging in tight loops
3. **Large log files**: Configure rotation properly
4. **Missing context**: Use `With()` to add persistent fields

### Debug Tips

```go
// Enable debug logging for specific component
if debug {
    logger = logger.WithOptions(log.WithLevel(log.Debug))
}

// Add caller information
logger = logger.WithOptions(log.AddCaller())

// Add stack traces to errors
logger = logger.WithOptions(log.AddStacktrace(log.Error))
```

## Contributing

When adding new features:
1. Maintain backward compatibility
2. Abstract implementation details
3. Provide both structured and unstructured APIs
4. Include comprehensive tests
5. Update this documentation

## Future Enhancements

- [ ] OpenTelemetry integration
- [ ] Metrics collection alongside logs
- [ ] Log forwarding to external services
- [ ] Enhanced sampling strategies
- [ ] Performance profiling integration