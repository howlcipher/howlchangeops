//go:build windows

package main

import "os/exec"

// Fail closed: direct-process Kill cannot bound descendants holding output pipes.
func prepareValidationProcess(cmd *exec.Cmd) {}
func killValidationProcess(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
