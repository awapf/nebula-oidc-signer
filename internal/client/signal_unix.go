//go:build unix

package client

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// signalPIDFile sends SIGHUP to the process in pidFile so nebula reloads
// its certificate.
func signalPIDFile(pidFile string) error {
	b, err := os.ReadFile(pidFile)
	if err != nil {
		return fmt.Errorf("reading pid file: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		return fmt.Errorf("pid file %s does not hold a valid pid", pidFile)
	}
	if err := syscall.Kill(pid, syscall.SIGHUP); err != nil {
		return fmt.Errorf("signalling pid %d: %w", pid, err)
	}
	return nil
}
