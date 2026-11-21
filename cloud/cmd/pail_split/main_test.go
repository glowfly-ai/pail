// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The test binary doubles as both fake children and as the supervisor process itself, so the six cases of the
// shell entrypoint it replaces (P021R-L1) are judged on real processes and real signals.
//
//	argv[1] = CLOUD | AGENT          -> behave like one child (<NAME>_TERM_SLEEP, _TERM_EXIT, _SELF_AFTER, _SELF_CODE)
//	SPLIT_HELPER_ROLE=super       -> run supervise() over two such children and exit with its code
//	SPLIT_HELPER_ROLE=hold        -> run the pause mode
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && (os.Args[1] == "CLOUD" || os.Args[1] == "AGENT") {
		os.Exit(fakeChild())
	}
	if os.Getenv("SPLIT_HELPER_ROLE") == "hold" {
		os.Exit(run([]string{"hold"}))
	}
	if os.Getenv("SPLIT_HELPER_ROLE") == "super" {
		self, _ := os.Executable()
		os.Exit(supervise([]string{self, "CLOUD"}, []string{self, "AGENT"}))
	}
	os.Exit(m.Run())
}

func seconds(name string) time.Duration {
	f, _ := strconv.ParseFloat(os.Getenv(name), 64)
	return time.Duration(f * float64(time.Second))
}

func fakeChild() int {
	name := os.Args[1]
	dir := os.Getenv("SPLIT_HELPER_DIR")
	done := func(code int) int {
		_ = os.WriteFile(filepath.Join(dir, name+".done"), []byte(strconv.Itoa(code)), 0o644)
		return code
	}
	term := make(chan os.Signal, 4)
	notifyStop(term)
	_ = os.WriteFile(filepath.Join(dir, name+".up"), nil, 0o644)
	var self <-chan time.Time
	if os.Getenv(name+"_SELF_AFTER") != "" {
		self = time.After(seconds(name + "_SELF_AFTER"))
	}
	select {
	case <-term:
		time.Sleep(seconds(name + "_TERM_SLEEP")) // the stop sequence; later signals do not shorten it
		code, _ := strconv.Atoi(os.Getenv(name + "_TERM_EXIT"))
		return done(code)
	case <-self:
		code, _ := strconv.Atoi(os.Getenv(name + "_SELF_CODE"))
		return done(code)
	}
}

type outcome struct {
	code    int
	elapsed time.Duration
	done    map[string]string
}

func runCase(t *testing.T, env map[string]string, signals []struct {
	after time.Duration
	sig   syscall.Signal
}) outcome {
	t.Helper()
	dir := t.TempDir()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(), "SPLIT_HELPER_ROLE=super", "SPLIT_HELPER_DIR="+dir)
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		_, e1 := os.Stat(filepath.Join(dir, "CLOUD.up"))
		_, e2 := os.Stat(filepath.Join(dir, "AGENT.up"))
		if e1 == nil && e2 == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			t.Fatal("fake children did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	start := time.Now()
	for _, s := range signals {
		time.Sleep(s.after)
		_ = cmd.Process.Signal(s.sig)
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	var werr error
	select {
	case werr = <-waited:
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("supervisor did not end")
	}
	out := outcome{elapsed: time.Since(start), done: map[string]string{}}
	if ee, ok := werr.(*exec.ExitError); ok {
		out.code = ee.ExitCode()
	} else if werr != nil {
		t.Fatal(werr)
	}
	for _, name := range []string{"CLOUD", "AGENT"} {
		if b, err := os.ReadFile(filepath.Join(dir, name+".done")); err == nil {
			out.done[name] = strings.TrimSpace(string(b))
		}
	}
	return out
}

type sig = struct {
	after time.Duration
	sig   syscall.Signal
}

func TestT01TermWaitsForTheCloudStopSequenceAndExits0(t *testing.T) {
	o := runCase(t, map[string]string{"CLOUD_TERM_SLEEP": "1.5"}, []sig{{0, syscall.SIGTERM}})
	if o.code != 0 || o.done["CLOUD"] != "0" || o.elapsed < 1500*time.Millisecond {
		t.Fatalf("code=%d elapsed=%s done=%v", o.code, o.elapsed, o.done)
	}
	if _, ok := o.done["AGENT"]; !ok {
		t.Fatalf("the agent was not stopped: %v", o.done)
	}
}

func TestT02TheExitCodeIsTheCloudExitCode(t *testing.T) {
	o := runCase(t, map[string]string{"CLOUD_TERM_EXIT": "3", "CLOUD_TERM_SLEEP": "0.5", "AGENT_TERM_EXIT": "7"}, []sig{{0, syscall.SIGTERM}})
	if o.code != 3 || o.done["CLOUD"] != "3" {
		t.Fatalf("code=%d done=%v", o.code, o.done)
	}
}

func TestT03AnAgentThatDiesByItselfBringsTheContainerDownFailing(t *testing.T) {
	o := runCase(t, map[string]string{"AGENT_SELF_AFTER": "0.3", "AGENT_SELF_CODE": "1"}, nil)
	if o.code == 0 {
		t.Fatalf("code=%d done=%v", o.code, o.done)
	}
	if _, ok := o.done["CLOUD"]; !ok {
		t.Fatalf("the cloud was not stopped through its stop sequence: %v", o.done)
	}
}

func TestT04ACloudThatEndsByItselfWith0IsStillAFailure(t *testing.T) {
	o := runCase(t, map[string]string{"CLOUD_SELF_AFTER": "0.3", "CLOUD_SELF_CODE": "0"}, nil)
	if o.code == 0 {
		t.Fatalf("code=%d done=%v", o.code, o.done)
	}
	if _, ok := o.done["AGENT"]; !ok {
		t.Fatalf("the agent was not stopped: %v", o.done)
	}
}

func TestT05ASecondTermDoesNotCutTheWait(t *testing.T) {
	o := runCase(t, map[string]string{"CLOUD_TERM_SLEEP": "1.5"}, []sig{{0, syscall.SIGTERM}, {300 * time.Millisecond, syscall.SIGTERM}})
	if o.code != 0 || o.done["CLOUD"] != "0" || o.elapsed < 1500*time.Millisecond {
		t.Fatalf("code=%d elapsed=%s done=%v", o.code, o.elapsed, o.done)
	}
}

func TestT06IntStopsLikeTerm(t *testing.T) {
	o := runCase(t, map[string]string{"CLOUD_TERM_SLEEP": "1.5"}, []sig{{0, syscall.SIGINT}})
	if o.code != 0 || o.done["CLOUD"] != "0" || o.elapsed < 1500*time.Millisecond {
		t.Fatalf("code=%d elapsed=%s done=%v", o.code, o.elapsed, o.done)
	}
}

func TestT07AChildThatCannotStartIsAFailureAndTheOtherIsStopped(t *testing.T) {
	dir := t.TempDir()
	self, _ := os.Executable()
	t.Setenv("SPLIT_HELPER_DIR", dir)
	// supervise returns only after both children have ended, so returning at all shows the cloud was stopped.
	// (It may be stopped before it installed its handler, so its stop sequence is not asserted here.)
	code := supervise([]string{self, "CLOUD"}, []string{filepath.Join(dir, "no-such-program")})
	if code != 127 {
		t.Fatalf("a missing agent executable must end the pair with 127, got %d", code)
	}
}

func TestT08ExitCodeOfAChildKilledByASignalIs128PlusTheSignal(t *testing.T) {
	if got := codeOf(syscall.WaitStatus(uint32(syscall.SIGKILL))); got != 128+int(syscall.SIGKILL) {
		t.Fatalf("got %d", got)
	}
}

// `pail_split hold` is the pause process of a container that only owns a namespace other containers join. The image
// has no `sleep`; unlike `sleep` as process 1 it ends on the stop signal instead of waiting for the kill.
func TestT09HoldWaitsForAStopSignalAndEndsWith0(t *testing.T) {
	for _, s := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT} {
		self, _ := os.Executable()
		cmd := exec.Command(self)
		cmd.Env = append(os.Environ(), "SPLIT_HELPER_ROLE=hold")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		waited := make(chan error, 1)
		go func() { waited <- cmd.Wait() }()
		select {
		case err := <-waited:
			t.Fatalf("hold ended by itself: %v", err)
		case <-time.After(700 * time.Millisecond):
		}
		_ = cmd.Process.Signal(s)
		select {
		case err := <-waited:
			if err != nil {
				t.Fatalf("hold must end with 0 on %v, got %v", s, err)
			}
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			t.Fatalf("hold did not end on %v", s)
		}
	}
}

func TestT10AnUnknownArgumentStartsNothing(t *testing.T) {
	for _, args := range [][]string{{"sleep"}, {"hold", "extra"}, {"--help"}, {"/usr/local/bin/pail_cloud"}} {
		if got := run(args); got != 64 {
			t.Fatalf("%v: want the usage code 64, got %d", args, got)
		}
	}
}
