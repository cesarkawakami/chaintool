package core

import (
	"fmt"
	"io"
)

type Lines struct {
	Lines []string
}

func NewLines() *Lines {
	return &Lines{}
}

func (l *Lines) Print(format string, a ...interface{}) {
	l.Lines = append(l.Lines, fmt.Sprintf(format, a...))
}

func (l *Lines) AppendLines(otherLines *Lines) {
	l.Lines = append(l.Lines, otherLines.Lines...)
}

func (l *Lines) Indent(indent string) {
	for i, _ := range l.Lines {
		l.Lines[i] = indent + l.Lines[i]
	}
}

func (l *Lines) Clone() *Lines {
	other := NewLines()
	other.Lines = append(other.Lines, l.Lines...)
	return other
}

func (l *Lines) IndentedBy(indent string) *Lines {
	newLines := l.Clone()
	newLines.Indent(indent)
	return newLines
}

func (l *Lines) Write(out io.Writer) error {
	for _, line := range l.Lines {
		if _, err := fmt.Fprintln(out, line); err != nil {
			return err
		}
	}
	return nil
}
