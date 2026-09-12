package tools

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

type Result struct {
	Tool     string
	Command  string
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
	Duration time.Duration
}

type RunOptions struct {
	Timeout time.Duration
	WorkDir string
	Env     []string
}

func DefaultRunOptions() RunOptions {
	return RunOptions{
		Timeout: 60 * time.Second,
	}
}

func DetectKali() bool {
	if runtime.GOOS != "linux" {
		return false
	}

	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return false
	}

	content := strings.ToLower(string(data))
	return strings.Contains(content, "kali")
}

func ToolExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func ToolPath(name string) string {
	path, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	return path
}

func Run(ctx context.Context, name string, args []string, opts RunOptions) *Result {
	start := time.Now()

	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = opts.WorkDir
	cmd.Env = opts.Env

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	duration := time.Since(start)

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
	}

	return &Result{
		Tool:     name,
		Command:  fmt.Sprintf("%s %s", name, strings.Join(args, " ")),
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
		Err:      err,
		Duration: duration,
	}
}

func RunWithCustomPath(ctx context.Context, toolPath string, args []string, opts RunOptions) *Result {
	if toolPath == "" {
		return &Result{
			Tool: "unknown",
			Err:  fmt.Errorf("tool path is empty"),
		}
	}
	return Run(ctx, toolPath, args, opts)
}

func RunWithOutput(name string, args ...string) (string, error) {
	opts := DefaultRunOptions()
	result := Run(context.Background(), name, args, opts)
	if result.Err != nil {
		return "", fmt.Errorf("command failed: %w (stderr: %s)", result.Err, result.Stderr)
	}
	return result.Stdout, nil
}

func RunWithOutputContext(ctx context.Context, name string, args ...string) (string, error) {
	opts := DefaultRunOptions()
	result := Run(ctx, name, args, opts)
	if result.Err != nil {
		return "", fmt.Errorf("command failed: %w (stderr: %s)", result.Err, result.Stderr)
	}
	return result.Stdout, nil
}

type Command struct {
	Name string
	Args []string
	Opts RunOptions
}

func RunParallel(ctx context.Context, cmds []Command, maxConcurrency int) []Result {
	if maxConcurrency <= 0 {
		maxConcurrency = runtime.NumCPU()
	}

	results := make([]Result, len(cmds))
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrency)

	for i, cmd := range cmds {
		wg.Add(1)
		go func(idx int, c Command) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[idx] = Result{
					Tool: c.Name,
					Err:  ctx.Err(),
				}
				return
			}

			results[idx] = *Run(ctx, c.Name, c.Args, c.Opts)
		}(i, cmd)
	}

	wg.Wait()
	return results
}

func RunParallelSimple(ctx context.Context, names []string, argsPerTool [][]string) []Result {
	if len(argsPerTool) == 0 {
		argsPerTool = make([][]string, len(names))
		for i := range argsPerTool {
			argsPerTool[i] = []string{}
		}
	}

	cmds := make([]Command, len(names))
	for i, name := range names {
		var args []string
		if i < len(argsPerTool) {
			args = argsPerTool[i]
		}
		cmds[i] = Command{
			Name: name,
			Args: args,
			Opts: DefaultRunOptions(),
		}
	}
	return RunParallel(ctx, cmds, 0)
}

func RunWithWordlist(ctx context.Context, tool string, args []string, wordlist string, opts RunOptions) *Result {
	fullArgs := make([]string, 0, len(args)+2)
	fullArgs = append(fullArgs, args...)
	fullArgs = append(fullArgs, "-w", wordlist)
	return Run(ctx, tool, fullArgs, opts)
}

func RunWithTimeout(name string, timeout time.Duration, args ...string) *Result {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return Run(ctx, name, args, RunOptions{Timeout: 0})
}

func RunBatch(ctx context.Context, cmds []Command) []Result {
	return RunParallel(ctx, cmds, runtime.NumCPU())
}
