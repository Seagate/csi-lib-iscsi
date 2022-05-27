package iscsi

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

var sysBlockPath = "/sys/block"
var devPath = "/dev"

func ExecWithTimeout(command string, args []string, timeout time.Duration) ([]byte, error) {
	debug.Printf("Executing command '%v' with args: '%v'.\n", command, args)

	// Create a new context and add a timeout to it
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Create command with context
	cmd := exec.CommandContext(ctx, command, args...)

	// This time we can simply use Output() to get the result.
	out, err := cmd.Output()

	// We want to check the context error to see if the timeout was executed.
	// The error returned by cmd.Output() will be OS specific based on what
	// happens when a process is killed.
	if ctx.Err() == context.DeadlineExceeded {
		debug.Printf("Command '%s' timeout reached.\n", command)
		return nil, ctx.Err()
	}

	// If there's no context error, we know the command completed (or errored).
	debug.Printf("Output from command: %s", string(out))
	if err != nil {
		debug.Printf("Non-zero exit code: %s\n", err)
	}

	debug.Println("Finished executing command.")
	return out, err
}

// GetSysDevicesFromMultipathDevice gets all slaves for multipath device dm-x
// in /sys/block/dm-x/slaves/
func GetSysDevicesFromMultipathDevice(device string) ([]string, error) {
	debug.Printf("Getting all slaves for multipath device %q\n", device)
	deviceSlavePath := filepath.Join(sysBlockPath, filepath.Base(device), "slaves")
	slaves, err := ioutil.ReadDir(deviceSlavePath)
	debug.Printf("Read device slaves path: %q, slaves=%v, err=%v\n", deviceSlavePath, slaves, err)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		debug.Printf("An error occured while looking for slaves: %v\n", err)
		return nil, err
	}

	var s []string
	for _, slave := range slaves {
		s = append(s, slave.Name())
	}
	debug.Printf("Found slaves: %v\n", s)
	return s, nil
}

// FlushMultipathDevice flushes a multipath device dm-x with command multipath -f /dev/dm-x
func FlushMultipathDevice(device string) error {
	debug.Printf("Flushing multipath device %q\n", device)

	err := RemoveAndClear(device)
	if err != nil {
		debug.Printf("device-mapper remove and clear device %q error=%v\n", device, err)
	}

	timeout := 5 * time.Second
	_, err = execWithTimeout("multipath", []string{"-f", device}, timeout)

	if err != nil {
		if _, e := os.Stat(device); os.IsNotExist(e) {
			debug.Printf("Multipath device %q was deleted\n", device)
		} else {
			debug.Printf("Command 'multipath -f %v' did not succeed to delete the device: %v\n", device, err)
			return err
		}
	}

	debug.Printf("Finshed flushing multipath device %q\n", device)
	return nil
}

// ResizeMultipathDevice resize a multipath device based on its underlying devices
func ResizeMultipathDevice(device string) error {
	debug.Printf("Resizing multipath device %s\n", device)

	if output, err := execCommand("multipathd", "resize", "map", device).CombinedOutput(); err != nil {
		return fmt.Errorf("could not resize multipath device: %s (%v)", output, err)
	}

	return nil
}

// RemoveAndClear calls 'dmsetup' to remove and clear a device entry
func RemoveAndClear(device string) error {
	debug.Printf("Remove and clear multipath device (%s)\n", device)

	// Remove device-mapper logical device
	debug.Printf("dmsetup remove -f %s\n", device)
	if output, err := execCommand("dmsetup", "remove", "-f", device).CombinedOutput(); err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if ok && exitErr.ExitCode() != 0 {
			debug.Printf("ERROR: dmsetup remove -f ExitCode: %d, err=%v\n", exitErr.ExitCode(), err)
		}

		return fmt.Errorf("device-mapper could not remove device: %s (%v)", output, err)
	}

	// Clear out device-mapper logical device if it still exists
	if _, e := os.Stat(device); os.IsNotExist(e) {
		debug.Printf("device-mapper logical device %q was removed\n", device)
	} else {
		debug.Printf("dmsetup clear %s\n", device)
		if output, err := execCommand("dmsetup", "clear", device).CombinedOutput(); err != nil {
			return fmt.Errorf("device-mapper could not clear device: %s (%v)", output, err)
		}
	}

	return nil
}
