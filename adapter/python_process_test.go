//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPythonGroupKillsChild(t *testing.T) {
	root := t.TempDir()
	// A surviving child would create this sentinel after the check deadline.
	helper := fmt.Sprintf("import subprocess, time\nsubprocess.Popen(['python3','-I','-B','-c', %q])\ntime.sleep(10)", "import time; open('started', 'w').write('ready'); time.sleep(0.8); open('survived', 'w').write('alive')")
	got := runPythonCheck("child", root, helper, 300*time.Millisecond, 4096)
	if !got.TimedOut {
		t.Fatalf("%+v", got)
	}
	if _, err := os.Stat(filepath.Join(root, "started")); err != nil {
		t.Fatalf("child did not start: %v", err)
	}
	time.Sleep(900 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(root, "survived")); !os.IsNotExist(err) {
		t.Fatalf("child survived: %v", err)
	}
}

func TestPythonEscapedChildPipeDrainBound(t *testing.T) {
	root := t.TempDir()
	// The escaped child exits by itself shortly; group cleanup does not claim it.
	helper := "import subprocess\nsubprocess.Popen(['python3','-I','-B','-c', 'import time; time.sleep(0.8)'], start_new_session=True)"
	start := time.Now()
	got := runPythonCheck("escaped", root, helper, 2*time.Second, 4096)
	if got.Status != "FAIL" || time.Since(start) > 700*time.Millisecond {
		t.Fatalf("pipe drain unbounded: %+v elapsed=%s", got, time.Since(start))
	}
	time.Sleep(time.Second)
}
