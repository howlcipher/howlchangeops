// A verification-only relay that records the real Go output used by the package.
package main

import (
	"encoding/json"
	"os"
	"os/exec"
)

func main() {
	realGo := os.Getenv("HOWL_NATIVE_REAL_GO")
	logPath := os.Getenv("HOWL_NATIVE_GO_LOG")
	if realGo == "" || logPath == "" {
		os.Exit(97)
	}
	cmd := exec.Command(realGo, os.Args[1:]...)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else {
			code = 98
		}
	}
	cwd, _ := os.Getwd()
	record, err := json.Marshal(map[string]interface{}{
		"argv": os.Args[1:], "cwd": cwd, "output": string(out), "exit_code": code,
	})
	if err != nil {
		os.Exit(96)
	}
	stream, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		os.Exit(95)
	}
	_, err = stream.Write(append(record, '\n'))
	if err != nil || stream.Close() != nil {
		os.Exit(94)
	}
	os.Stdout.Write(out)
	os.Exit(code)
}
