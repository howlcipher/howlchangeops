package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os/exec"
	"sync"
	"time"
)

// Fixed helpers are adapter code, never configuration or repository scripts.
// Import unittest before exposing the trusted repository to module discovery.
const pythonTestHelper = `
import os
import sys
import unittest

root = os.getcwd()
tests = os.path.join(root, "tests")
if not os.path.isdir(tests):
    raise RuntimeError("missing tests directory")
sys.path.insert(0, root)
suite = unittest.defaultTestLoader.discover(tests)
count = suite.countTestCases()
if count <= 0:
    raise RuntimeError("empty unittest suite")
print("Discovered %d tests" % count, flush=True)
result = unittest.TextTestRunner(verbosity=2).run(suite)
if result.testsRun - len(result.skipped) <= 0:
    raise RuntimeError("no unittest executed (all skipped)")
sys.exit(0 if result.wasSuccessful() else 1)
`

const pythonBuildHelper = `
import os
import stat
import subprocess

result = subprocess.run(
    ["git", "ls-files", "-z", "--", "*.py"],
    stdout=subprocess.PIPE, check=True)
paths = result.stdout.split(b"\0")
count = 0
for raw in paths:
    if not raw:
        continue
    path = os.fsdecode(raw)
    parts = path.split("/")
    if os.path.isabs(path) or any(p in ("", ".", "..") for p in parts):
        raise RuntimeError("unsafe tracked source path")
    current = os.getcwd()
    for part in parts:
        current = os.path.join(current, part)
        mode = os.lstat(current).st_mode
        if stat.S_ISLNK(mode):
            raise RuntimeError("symlink in tracked source path")
    if not stat.S_ISREG(mode):
        raise RuntimeError("tracked source is not regular")
    with open(current, "rb") as source:
        compile(source.read(), path, "exec")
    count += 1
if count <= 0:
    raise RuntimeError("no tracked Python sources")
print("Compiled %d tracked Python sources in memory" % count)
`

type cappedOutput struct {
	mu        sync.Mutex
	data      bytes.Buffer
	limit     int
	truncated bool
	overflow  chan struct{}
}

func (b *cappedOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	remaining := b.limit - b.data.Len()
	if len(p) > remaining {
		p = p[:remaining]
		if !b.truncated {
			b.truncated = true
			close(b.overflow)
		}
	}
	b.data.Write(p)
	return n, nil
}

// Limits are injected only by Go tests, never repository configuration.
func runPythonCheck(name, root, helper string, deadline time.Duration, limit int) ValidationResult {
	start := time.Now().UTC()
	out := &cappedOutput{limit: limit, overflow: make(chan struct{})}
	cmd := exec.Command("python3", "-I", "-B", "-c", helper)
	cmd.Dir = root
	// Bound pipe draining even if trusted code starts a descendant outside the group.
	cmd.WaitDelay = 250 * time.Millisecond
	cmd.Stdout = out
	cmd.Stderr = out
	prepareValidationProcess(cmd)
	result := ValidationResult{Name: name, Status: "FAIL", ExitCode: -1, Profile: "local", Revision: "HEAD", StartedAt: start.Format(time.RFC3339)}
	if err := cmd.Start(); err == nil {
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		timer := time.NewTimer(deadline)
		select {
		case err = <-done:
		case <-timer.C:
			result.TimedOut = true
			killValidationProcess(cmd)
			err = <-done
		case <-out.overflow:
			killValidationProcess(cmd)
			err = <-done
		}
		timer.Stop()
		// Fence remaining same-group descendants even if the direct child exited.
		killValidationProcess(cmd)
		if err == nil {
			result.ExitCode = 0
		} else if e, ok := err.(*exec.ExitError); ok {
			result.ExitCode = e.ExitCode()
		}
		out.mu.Lock()
		result.OutputTruncated = out.truncated
		out.mu.Unlock()
		if err == nil && !result.TimedOut && !result.OutputTruncated {
			result.Status = "PASS"
		} else if result.ExitCode == 0 {
			result.ExitCode = -1
		}
	} else {
		out.Write([]byte(err.Error()))
	}
	result.OutputDigest = fmt.Sprintf("%x", sha256.Sum256(out.data.Bytes()))
	result.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	return result
}
