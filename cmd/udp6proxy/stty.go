package main

import (
	"os"
	"os/exec"
)

func execStty(arg string) error {
	cmd := exec.Command("stty", arg)
	cmd.Stdin = os.Stdin
	return cmd.Run()
}
