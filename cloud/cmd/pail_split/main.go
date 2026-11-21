// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// pail_split runs pail_cloud and pail_robot_agent as two processes of one container (the single-host split
// profile) and is the container's process 1. It replaces docker/pail_split_entrypoint.sh so that the image
// needs no shell. `pail_split hold` is the same image's replacement for `sleep infinity`.
//
// When process 1 exits the kernel kills whatever is left, so this program never exits before pail_cloud has
// finished its stop sequence (stop serving, close the journal under a signed checkpoint):
//
//	stop signal (TERM/INT): both children get TERM; exit with pail_cloud's code. A second signal is passed on
//	                        again and does not shorten the wait.
//	a child ends by itself:  stop the other one, wait for it, exit non-zero. One half of the pair ending is
//	                        never a clean stop, also when it ended with 0.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

const (
	cloudPath = "/usr/local/bin/pail_cloud"
	agentPath = "/usr/local/bin/pail_robot_agent"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// run takes no argument (supervise the pair) or exactly `hold`. Anything else starts nothing: a command line this
// program does not know is not a reason to bring an Issuer up.
func run(args []string) int {
	switch {
	case len(args) == 0:
		return supervise([]string{cloudPath}, []string{agentPath})
	case len(args) == 1 && args[0] == "hold":
		return hold()
	}
	fmt.Fprintln(os.Stderr, "usage: pail_split        run pail_cloud and pail_robot_agent as one container\n       pail_split hold   stay until a stop signal (the container that owns a shared namespace)")
	return 64
}

// hold is the pause process of a container whose only job is to own a network or IPC namespace that other
// containers join. It starts no child and ends with 0 on TERM or INT.
func hold() int {
	stop := make(chan os.Signal, 1)
	notifyStop(stop)
	defer signal.Stop(stop)
	<-stop
	return 0
}

func notifyStop(c chan os.Signal) {
	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT)
}

// codeOf is the exit code a shell would report: the exit status, or 128+signal for a child a signal ended.
func codeOf(ws syscall.WaitStatus) int {
	if ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ws.ExitStatus()
}

func codeOfWait(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok {
			return codeOf(ws)
		}
		return ee.ExitCode()
	}
	return 1
}

type ended struct {
	who  int // 0 = cloud, 1 = agent
	code int
}

func supervise(cloud, agent []string) int {
	stop := make(chan os.Signal, 8)
	notifyStop(stop)
	defer signal.Stop(stop)

	var cmds [2]*exec.Cmd
	var alive [2]bool
	exits := make(chan ended, 2)
	for i, argv := range [][]string{cloud, agent} {
		c := exec.Command(argv[0], argv[1:]...)
		c.Stdout, c.Stderr = os.Stdout, os.Stderr
		if err := c.Start(); err != nil {
			// A child that cannot start is a child that ended by itself: the other one is stopped below.
			fmt.Fprintf(os.Stderr, "pail_split: cannot start %s: %v\n", argv[0], err)
			exits <- ended{i, 127}
			continue
		}
		cmds[i], alive[i] = c, true
		go func(i int, c *exec.Cmd) { exits <- ended{i, codeOfWait(c.Wait())} }(i, c)
	}
	term := func() {
		for i, c := range cmds {
			if c != nil && alive[i] {
				_ = c.Process.Signal(syscall.SIGTERM)
			}
		}
	}

	codes := [2]int{}
	stopping, stoppedBeforeFirstExit, first := false, false, -1
	for remaining := 2; remaining > 0; {
		select {
		case <-stop:
			stopping = true
			term()
		case e := <-exits:
			alive[e.who], codes[e.who] = false, e.code
			remaining--
			if first < 0 {
				first, stoppedBeforeFirstExit = e.who, stopping
				if !stopping {
					term()
				}
			}
		}
	}
	if stoppedBeforeFirstExit {
		return codes[0]
	}
	if codes[first] == 0 {
		return 1
	}
	return codes[first]
}
