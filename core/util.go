package core

import (
	"fmt"
	"os"
	"strings"

	"github.com/mitchellh/go-wordwrap"
)

func wordWrapLines(msg string, lineLength int) []string {
	wrapped := wordwrap.WrapString(msg, uint(lineLength))
	return strings.Split(wrapped, "\n")
}

func warning(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "Warning: "+format, a...)
}
