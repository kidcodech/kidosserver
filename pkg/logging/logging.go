package logging

import (
	"log"
	"os"
)

var (
	// Logger is a package-level logger for simple diagnostics.
	Logger = log.New(os.Stdout, "kidos: ", log.LstdFlags|log.Lmicroseconds)
)

// Fatalf wraps log.Fatalf so callers can stub during testing.
func Fatalf(format string, args ...any) {
	Logger.Fatalf(format, args...)
}

// Infof logs a formatted info message.
func Infof(format string, args ...any) {
	Logger.Printf(format, args...)
}

// Errorf logs a formatted error message.
func Errorf(format string, args ...any) {
	Logger.Printf("ERROR: "+format, args...)
}
