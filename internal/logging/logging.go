package logging

import (
	"fmt"

	"golang.zx2c4.com/wireguard/device"
)

// Logger is the device package logger used as the global logger for the
// application. device.Logger is effectively a collection of standard logging
// library loggers. Packages keep a reference to it and Init repopulates it.
var Logger = NewLogger("wiresteward")

// logLevel global var, defaults to error
var logLevel = device.LogLevelError

// SetLogLevel sets the logLevel global variable. Needs to be called before the
// initialisation of loggers
func SetLogLevel(level string) {
	switch level {
	case "debug":
		logLevel = device.LogLevelVerbose
	case "error":
		logLevel = device.LogLevelError
	default:
		fmt.Printf(
			"No valid log level set, defaulting to \"error\": userSetLog=%s\n",
			level,
		)
	}
}

// NewLogger returns a new logger using the global level variable
func NewLogger(name string) *device.Logger {
	return device.NewLogger(
		logLevel,
		fmt.Sprintf("%s: ", name),
	)
}

// Init populates the global Logger using the global level variable
func Init(name string) {
	*Logger = *NewLogger(name)
}
