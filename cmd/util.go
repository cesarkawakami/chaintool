package cmd

import (
	"fmt"
	"os"
)

func fatal(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)

	os.Exit(1)
}

func msg(format string, a ...interface{}) {
	fmt.Printf(format+"\n", a...)
}

func title(format string, a ...interface{}) {
	formatted := fmt.Sprintf(format, a...)
	currentIsLeft := true
	spacesToPrint := 2
	for len(formatted) < 80 {
		charToAdd := "="
		if spacesToPrint > 0 {
			charToAdd = " "
			spacesToPrint--
		}
		if currentIsLeft {
			formatted = charToAdd + formatted
		} else {
			formatted = formatted + charToAdd
		}
		currentIsLeft = !currentIsLeft
	}
	fmt.Println(formatted)
}
