package repl

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func (r *REPL) runScript(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: script <file>")
		return
	}

	filePath := args[0]
	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading script: %v\n", err)
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fmt.Fprintf(os.Stdout, "\033[90m[%d]\033[0m %s\n", lineNum, line)
		r.executeLine(line)
	}
}

func (r *REPL) runBatch() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		r.executeLine(line)
	}
}
