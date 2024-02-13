//go:build !windows
// +build !windows

package pe

import "os/exec"

func hideWindow(cmd *exec.Cmd) {
}
