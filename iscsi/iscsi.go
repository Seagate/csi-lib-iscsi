// Copyright (c) 2024 Seagate Technology LLC and/or its Affiliates
package iscsi

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	defaultPort          = "3260"
	maxMultipathAttempts = 10
	multipathDelay       = 10
)

var (
	debug           *log.Logger
	execCommand     = exec.Command
	execWithTimeout = ExecWithTimeout
)

type statFunc func(string) (os.FileInfo, error)
type globFunc func(string) ([]string, error)

type iscsiSession struct {
	Protocol string
	ID       int32
	Portal   string
	IQN      string
	Name     string
}

type TargetInfo struct {
	Iqn    string `json:"iqn"`
	Portal string `json:"portal"`
	Port   string `json:"port"`
}

type HCTL struct {
	HBA     int
	Channel int
	Target  int
	LUN     int
}

// Connector provides a struct to hold all of the needed parameters to make our iscsi connection
type Connector struct {
	VolumeName       string       `json:"volume_name"`
	Targets          []TargetInfo `json:"targets"`
	Lun              int32        `json:"lun"`
	AuthType         string       `json:"auth_type"`
	DiscoverySecrets Secrets      `json:"discovery_secrets"`
	SessionSecrets   Secrets      `json:"session_secrets"`
	Interface        string       `json:"interface"`
	Multipath        bool         `json:"multipath"`
	DevicePath       string       `json:"device_path"` // DevicePath is dm-x for a multipath device, and sdx for a normal device.
	RetryCount       int32        `json:"retry_count"`
	CheckInterval    int32        `json:"check_interval"`
	DoDiscovery      bool         `json:"do_discovery"`
	DoCHAPDiscovery  bool         `json:"do_chap_discovery"`
	TargetIqn        string       `json:"target_iqn"`
	TargetPortals    []string     `json:"target_portals"`
}

func init() {
	// by default we don't log anything, EnableDebugLogging() can turn on some tracing
	debug = log.New(ioutil.Discard, "", 0)

}

// EnableDebugLogging provides a mechanism to turn on debug logging for this package
// output is written to the provided io.Writer
func EnableDebugLogging(writer io.Writer) {
	debug = log.New(writer, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile)
}

// parseSession takes the raw stdout from the iscsiadm -m session command and encodes it into an iscsi session type
func parseSessions(lines string) []iscsiSession {
	entries := strings.Split(strings.TrimSpace(lines), "\n")
	r := strings.NewReplacer("[", "",
		"]", "")

	var sessions []iscsiSession
	for _, entry := range entries {
		e := strings.Fields(entry)
		if len(e) < 4 {
			continue
		}
		protocol := strings.Split(e[0], ":")[0]
		id := r.Replace(e[1])
		id64, _ := strconv.ParseInt(id, 10, 32)
		portal := strings.Split(e[2], ",")[0]

		s := iscsiSession{
			Protocol: protocol,
			ID:       int32(id64),
			Portal:   portal,
			IQN:      e[3],
			Name:     strings.Split(e[3], ":")[1],
		}
		sessions = append(sessions, s)
	}
	return sessions
}

func sessionExists(tgtPortal, tgtIQN string) (bool, error) {
	debug.Printf("Begin sessionExists (%s/%s)...\n", tgtIQN, tgtPortal)
	sessions, err := getCurrentSessions()
	if err != nil {
		return false, err
	}
	for _, s := range sessions {
		if tgtIQN == s.IQN && tgtPortal == s.Portal {
			return true, nil
		}
	}
	return false, nil
}

func extractTransportName(output string) string {
	res := regexp.MustCompile(`iface.transport_name = (.*)\n`).FindStringSubmatch(output)
	if res == nil {
		return ""
	}
	if res[1] == "" {
		return "tcp"
	}
	return res[1]
}

func getCurrentSessions() ([]iscsiSession, error) {

	out, err := GetSessions()
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if ok && exitErr.ProcessState.Sys().(syscall.WaitStatus).ExitStatus() == 21 {
			return []iscsiSession{}, nil
		}
		return nil, err
	}
	sessions := parseSessions(out)
	return sessions, err
}

func waitForPathToExist(devicePath *string, maxRetries, intervalSeconds int, deviceTransport string) (bool, error) {
	return waitForPathToExistImpl(devicePath, maxRetries, intervalSeconds, deviceTransport, os.Stat, filepath.Glob)
}

func waitForPathToExistImpl(devicePath *string, maxRetries, intervalSeconds int, deviceTransport string, osStat statFunc, filepathGlob globFunc) (bool, error) {
	debug.Printf("waitForPathToExistImpl (%v)", *devicePath)
	if devicePath == nil || *devicePath == "" {
		return false, fmt.Errorf("unable to check nil or unspecified devicePath")
	}

	var err error
	for i := 0; i < maxRetries; i++ {
		err = nil
		if deviceTransport == "tcp" {
			_, err = osStat(*devicePath)
			debug.Printf("[%d] os stat device: exist %v device %v", i, !os.IsNotExist(err), *devicePath)
			if err != nil && !os.IsNotExist(err) {
				debug.Printf("Error attempting to stat device: %s", err.Error())
				return false, err
			} else if err != nil {
				debug.Printf("Device not found for: %s", *devicePath)
			}

		} else {
			debug.Printf("[%d] filepathGlob: %s", i, *devicePath)
			fpath, _ := filepathGlob(*devicePath)
			if fpath == nil {
				err = os.ErrNotExist
			} else {
				// There might be a case that fpath contains multiple device paths if
				// multiple PCI devices connect to same iscsi target. We handle this
				// case at subsequent logic. Pick up only first path here.
				debug.Printf("set - devicePath %s", fpath[0])
				*devicePath = fpath[0]
			}
		}
		if err == nil {
			return true, nil
		}
		if i == maxRetries-1 {
			break
		}
		time.Sleep(time.Second * time.Duration(intervalSeconds))
	}
	debug.Printf("device does NOT exist [%d*%ds] (%v)", maxRetries, intervalSeconds, *devicePath)
	return false, err
}

func getMultipathDisk(path string) (string, error) {
	// Follow link to destination directory
	debug.Printf("Checking for multipath device for path: %s", path)
	devicePath, err := os.Readlink(path)
	if err != nil {
		debug.Printf("Failed reading link for multipath disk: %s -- error: %s\n", path, err.Error())
		return "", err
	}
	sdevice := filepath.Base(devicePath)
	debug.Printf("-- devicePath=%s, sdevice=%s", devicePath, sdevice)

	// If destination directory is already identified as a multipath device,
	// just return its path
	if strings.HasPrefix(sdevice, "dm-") {
		debug.Printf("Already found multipath device: %s", sdevice)
		return path, nil
	}
	// Fallback to iterating through all the entries under /sys/block/dm-* and
	// check to see if any have an entry under /sys/block/dm-*/slaves matching
	// the device the symlink was pointing at
	attempts := 1
	var dmPaths []string

	for attempts < (maxMultipathAttempts + 1) {
		var err error
		dmPaths, err = filepath.Glob("/sys/block/dm-*")
		debug.Printf("[%d] refresh dmPaths [%d] %v", attempts, len(dmPaths), dmPaths)
		if err != nil {
			debug.Printf("Glob error: %s", err)
			return "", err
		}

		for _, dmPath := range dmPaths {
			sdevices, err := filepath.Glob(filepath.Join(dmPath, "slaves", "*"))
			// debug.Printf(".. dmPath=%v, sdevices=[%d]%v", dmPath, len(sdevices), sdevices)
			if err != nil {
				debug.Printf("Glob error: %s", err)
			}
			for _, spath := range sdevices {
				s := filepath.Base(spath)
				// debug.Printf(".. Basepath: %s", s)
				if sdevice == s {
					// We've found a matching entry, return the path for the
					// dm-* device it was found under
					p := filepath.Join("/dev", filepath.Base(dmPath))
					debug.Printf("Found matching multipath device (%s) under dm-* device path (%s) p (%v)", sdevice, dmPath, p)
					return p, nil
				}
			}
		}

		// Force a reload of all existing multipath maps
		output, err := execCommand("multipath", "-r").CombinedOutput()
		debug.Printf("## multipath -r: output=%v, err=%v", output, err)

		time.Sleep(multipathDelay * time.Second)
		attempts++
	}
	debug.Printf("Couldn't find dm-* path for path: %s, found non dm-* path: %s", path, devicePath)
	return "", fmt.Errorf("couldn't find dm-* path for path: %s, found non dm-* path: %s", path, devicePath)
}

// Connect attempts to connect a volume to this node using the provided Connector info
func Connect(c *Connector) (string, error) {
	var lastErr error
	debug.Printf("Begin iSCSI Connect (dDoDiscovery=%v)...\n", c.DoDiscovery)
	if c.RetryCount == 0 {
		c.RetryCount = 10
	}
	if c.CheckInterval == 0 {
		c.CheckInterval = 1
	}

	if c.RetryCount < 0 || c.CheckInterval < 0 {
		return "", fmt.Errorf("invalid RetryCount and CheckInterval combination, both must be positive integers. "+
			"RetryCount: %d, CheckInterval: %d", c.RetryCount, c.CheckInterval)
	}
	var devicePaths []string
	iFace := "default"
	if c.Interface != "" {
		iFace = c.Interface
	}

	// make sure our iface exists and extract the transport type
	out, err := ShowInterface(iFace)
	if err != nil {
		return "", err
	}
	iscsiTransport := extractTransportName(out)

	for _, target := range c.Targets {
		debug.Printf("process targetIqn: %s, portal: %s\n", target.Iqn, target.Portal)
		// Rescan sessions to discover newly mapped LUNs.
		if err := ISCSIRescan(target.Iqn, int(c.Lun)); err != nil {
			debug.Printf("failed to rescan session, err: %v", err)
		}

		// create our devicePath that we'll be looking for based on the transport being used
		port := defaultPort
		if target.Port != "" {
			port = target.Port
		}
		// portal with port
		p := strings.Join([]string{target.Portal, port}, ":")
		devicePath := strings.Join([]string{"/dev/disk/by-path/ip", p, "iscsi", target.Iqn, "lun", fmt.Sprint(c.Lun)}, "-")
		if iscsiTransport != "tcp" {
			devicePath = strings.Join([]string{"/dev/disk/by-path/pci", "*", "ip", p, "iscsi", target.Iqn, "lun", fmt.Sprint(c.Lun)}, "-")
		}

		exists, _ := sessionExists(p, target.Iqn)
		if exists {
			debug.Printf("Session already exists, checking if device path %q exists", devicePath)
			exists, err := waitForPathToExist(&devicePath, int(c.RetryCount), int(c.CheckInterval), iscsiTransport)
			debug.Printf("waitForPathToExist: exists=%v err=%v", exists, err)
			if exists {
				debug.Printf("Appending device path: %s", devicePath)
				devicePaths = append(devicePaths, devicePath)
				continue
			} else if err != nil {
				return "", err
			}
		}

		if c.DoDiscovery {
			// build discoverydb and discover iscsi target
			if err := Discoverydb(p, iFace, c.DiscoverySecrets, c.DoCHAPDiscovery); err != nil {
				debug.Printf("Error in discovery of the target: %s\n", err.Error())
				lastErr = err
				continue
			}
		}

		if c.DoCHAPDiscovery {
			// Make sure we don't log the secrets
			err := CreateDBEntry(target.Iqn, p, iFace, c.DiscoverySecrets, c.SessionSecrets)
			if err != nil {
				debug.Printf("Error creating db entry: %s\n", err.Error())
				continue
			}
		}

		// perform the login
		err = Login(target.Iqn, p)
		if err != nil {
			debug.Printf("failed to login, err: %v", err)
			lastErr = err
			continue
		}
		retries := int(c.RetryCount / c.CheckInterval)
		if exists, err := waitForPathToExist(&devicePath, retries, int(c.CheckInterval), iscsiTransport); exists {
			devicePaths = append(devicePaths, devicePath)
			continue
		} else if err != nil {
			lastErr = fmt.Errorf("couldn't attach disk, err: %v", err)
		}
	}

	if len(devicePaths) < 1 {
		iscsiCmd([]string{"-m", "iface", "-I", iFace, "-o", "delete"}...)
		return "", fmt.Errorf("failed to find device path: %s, last error seen: %v", devicePaths, lastErr)
	}

	if lastErr != nil {
		debug.Printf("Last error occurred during iscsi init: \n%v", lastErr)
	}

	for i, path := range devicePaths {
		if path != "" {
			if mappedDevicePath, err := getMultipathDisk(path); mappedDevicePath != "" {
				debug.Printf("update devicePaths[%d] before=%v, after=%v", i, devicePaths[i], mappedDevicePath)
				devicePaths[i] = mappedDevicePath
				c.Multipath = true
				if err != nil {
					return "", err
				}
			}
		}
	}
	debug.Printf("After connect we're returning devicePaths: %v", devicePaths)
	if len(devicePaths) > 0 {
		c.DevicePath = devicePaths[0]
		debug.Printf("set -- devicePath %s", c.DevicePath)
		return devicePaths[0], err

	}
	return "", err
}

// Disconnect performs a disconnect operation on a volume
func Disconnect(tgtIqn string, portals []string) error {
	err := Logout(tgtIqn, portals)
	if err != nil {
		return err
	}
	err = DeleteDBEntry(tgtIqn)
	return err
}

// DisconnectVolume removes a volume from a Linux host.
func DisconnectVolume(c Connector) error {
	// Steps to safely remove an iSCSI storage volume from a Linux host are as following:
	// 1. Unmount the disk from a filesystem on the system.
	// 2. Flush the multipath map for the disk we’re removing (if multipath is enabled).
	// 3. Remove the physical disk entities that Linux maintains.
	// 4. Take the storage volume (disk) offline on the storage subsystem.
	// 5. Rescan the iSCSI sessions.
	//
	// DisconnectVolume focuses on step 2 and 3.
	// Note: make sure the volume is already unmounted before calling this method.

	debug.Printf("Disconnecting volume in path %s.\n", c.DevicePath)
	if c.Multipath {
		debug.Printf("Removing multipath device %s\n", c.DevicePath)
		devices, err := GetSysDevicesFromMultipathDevice(c.DevicePath)
		if err != nil {
			return err
		}
		err = FlushMultipathDevice(c.DevicePath)
		if err != nil {
			return err
		}
		debug.Printf("Found multipath slaves %v, removing all of them.\n", devices)
		if err := RemovePhysicalDevice(devices...); err != nil {
			return err
		}
	} else {
		debug.Printf("Removing normal device.\n")
		if err := RemovePhysicalDevice(c.DevicePath); err != nil {
			return err
		}
	}

	debug.Printf("Finished disconnecting volume.\n")
	return nil
}

// RemovePhysicalDevice removes device(s) sdx from a Linux host.
func RemovePhysicalDevice(devices ...string) error {
	debug.Printf("Removing scsi device %v.\n", devices)
	var errs []error
	for _, deviceName := range devices {
		if deviceName == "" {
			continue
		}

		debug.Printf("Delete scsi device %v.\n", deviceName)
		// Remove a scsi device by executing 'echo "1" > /sys/block/sdx/device/delete
		filename := filepath.Join(sysBlockPath, deviceName, "device", "delete")
		if f, err := os.OpenFile(filename, os.O_TRUNC|os.O_WRONLY, 0200); err != nil {
			if os.IsNotExist(err) {
				continue
			} else {
				debug.Printf("Error while opening file %v: %v\n", filename, err)
				errs = append(errs, err)
				continue
			}
		} else {
			defer f.Close()
			if _, err := f.WriteString("1"); err != nil {
				debug.Printf("Error while writing to file %v: %v", filename, err)
				errs = append(errs, err)
				continue
			}
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}
	debug.Println("Finshed removing SCSI devices.")
	return nil
}

// PersistConnector persists the provided Connector to the specified file (ie /var/lib/pfile/myConnector.json)
func PersistConnector(c *Connector, filePath string) error {
	//file := path.Join("mnt", c.VolumeName+".json")
	f, err := os.Create(filePath)
	if err != nil {
		debug.Printf("ERROR: creating iscsi persistence file %s: %s\n", filePath, err)
		return fmt.Errorf("error creating iscsi persistence file %s: %s", filePath, err)
	}
	defer f.Close()
	encoder := json.NewEncoder(f)
	debug.Printf("Connector Persistence File (write): file=%s\n", filePath)
	if err = encoder.Encode(c); err != nil {
		debug.Printf("ERROR: error encoding connector: %v\n", err)
		return fmt.Errorf("error encoding connector: %v", err)
	}
	return nil

}

// GetConnectorFromFile attempts to create a Connector using the specified json file (ie /var/lib/pfile/myConnector.json)
func GetConnectorFromFile(filePath string) (*Connector, error) {
	f, err := ioutil.ReadFile(filePath)
	debug.Printf("GetConnectorFromFile (%s), err=%v\n", filePath, err)
	if err != nil {
		return &Connector{}, err
	}

	data := Connector{}
	err = json.Unmarshal(f, &data)
	if err != nil {
		return &Connector{}, err
	}

	debug.Printf("ConnectorFromFile (read): file=%s\n", filePath)

	return &data, nil

}

func RescanISCSIDevices(hctls []HCTL) error {
	debug.Printf("Begin RescanISCSIDevices (%v)...", hctls)
	for _, hctl := range hctls {
		scanFilePath := fmt.Sprintf("/sys/class/scsi_host/host%d/scan", hctl.HBA)
		err := os.WriteFile(scanFilePath, []byte(fmt.Sprintf("%d %d %d\n", hctl.Channel, hctl.Target, hctl.LUN)), 0644)
		if err != nil {
			debug.Printf("error writing scan file %s: %v", scanFilePath, err)
			return err
		}
	}
	return nil
}

// ISCSIRescan takes a target iqn and lun and writes to the scan file in the scsi subsystem
// We do this manually instead of relying on iscsiadm -R. This prevents a race condition in which
// devices that are in the process of being removed can be re-discovered and left behind.
func ISCSIRescan(tgtIQN string, lun int) error {
	debug.Printf("Begin ISCSIRescan (%s, %d)...", tgtIQN, lun)
	var hctlsToScan []HCTL
	// Get all scsi targets
	sessionTargetFilenames, err := filepath.Glob("/sys/class/scsi_host/host*/device/session*/iscsi_session/session*/targetname")
	if err != nil {
		debug.Printf("Error searching for scsi session targets in /sys/class/scsi_host")
		return err
	}
	SCSIHostPath := ""
	// loop over all found sessions. if the targetname matches the target we want to scan, create an HCTL for it and add it to list of devices to scan
	for _, sessionTargetFile := range sessionTargetFilenames {
		targetName, err := os.ReadFile(sessionTargetFile)
		if err != nil {
			debug.Printf("Error reading session file %s, skipping to next session", sessionTargetFile)
			continue
		}
		if strings.TrimSpace(string(targetName)) == strings.TrimSpace(tgtIQN) {
			SCSIHostPath = strings.Split(sessionTargetFile, "/device/")[0]
			hba, err := strconv.Atoi(strings.TrimPrefix(SCSIHostPath, "/sys/class/scsi_host/host"))
			if err != nil {
				debug.Printf("Error retrieving HBA number from path %s", SCSIHostPath)
				return err
			}
			sessionPath := strings.Split(sessionTargetFile, "/iscsi_session")[0]
			targetFilesInSession, err := filepath.Glob(filepath.Join(sessionPath, "target*"))
			if err != nil {
				debug.Printf("Error getting target info from session directory %s", sessionPath)
				return err
			}
			for _, target := range targetFilesInSession {
				// this will be a filename formatted like "target3:0:0", we want to extract the last 2 numbers which represent the channel and target
				hostChannelTarget := strings.Split(strings.TrimPrefix(filepath.Base(target), "target"), ":")
				channel, err := strconv.Atoi(hostChannelTarget[1])
				if err != nil {
					debug.Printf("Error parsing channel number from path %s", target)
					return err
				}
				targetnum, err := strconv.Atoi(hostChannelTarget[2])
				if err != nil {
					debug.Printf("Error parsing target number from path %s", target)
					return err
				}
				hctlsToScan = append(hctlsToScan,
					HCTL{
						HBA:     hba,
						Channel: channel,
						Target:  targetnum,
						LUN:     lun})

			}
		}
	}
	if SCSIHostPath == "" {
		return fmt.Errorf("could not find scsi target in scsi_host directory tree")
	}
	err = RescanISCSIDevices(hctlsToScan)
	if err != nil {
		return err
	}

	return nil
}
