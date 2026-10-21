package main

import (
	"bufio"
	"io"
	"os"
	"os/user"
	"strings"
)

type approveFlags struct {
	ownerConfirmed bool
	approver       string
}

// parseApproveFlags reads the flags after `approve <decision_id>`.
func parseApproveFlags(args []string) approveFlags {
	var f approveFlags
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--owner-confirmed":
			f.ownerConfirmed = true
		case a == "--approver" && i+1 < len(args):
			f.approver = args[i+1]
			i++
		case strings.HasPrefix(a, "--approver="):
			f.approver = strings.TrimPrefix(a, "--approver=")
		}
	}
	return f
}

// approverName is the named approver, else the operating-system user.
func approverName(named string) string {
	if n := strings.TrimSpace(named); n != "" {
		return n
	}
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	if n := os.Getenv("USER"); n != "" {
		return n
	}
	return "unknown"
}

// stdinIsTerminal reports an interactive stdin. /dev/null is also a
// character device, so it is excluded explicitly.
var stdinIsTerminal = func() bool {
	info, err := os.Stdin.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	if null, err := os.Stat(os.DevNull); err == nil && os.SameFile(info, null) {
		return false
	}
	return true
}

// confirmAtTerminal reads one answer; only y or yes approves.
func confirmAtTerminal(r io.Reader) bool {
	line, _ := bufio.NewReader(r).ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}
