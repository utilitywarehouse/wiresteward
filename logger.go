package main

import (
	"fmt"
	"golang.zx2c4.com/wireguard/device"
)

// Use device package logger as the global logger for the application.
// device.Logger is effectively a collection of standard logging library loggers
var logger *device.Logger

// logLevel global var, defaults to info
var logLevel = device.LogLevelInfo

// Sets the logLevel global variable. Needs to be called before the
// initialisation of loggers
func setLogLevel(level string) {
	switch level {
	case "debug":
		logLevel = device.LogLevelDebug
	case "info":
		logLevel = device.LogLevelInfo
	case "error":
		logLevel = device.LogLevelError
	default:
		fmt.Printf(
			"Invalid log level: %s, can be debug|info|error. Defaulting to info",
			level,
		)
	}
}

// Returns a new logger using the global level variable
func newLogger(name string) *device.Logger {
	return device.NewLogger(
		logLevel,
		fmt.Sprintf("%s: ", name),
	)
}
