package agent

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var deviceIDRegexp = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// writeFile stores the device id, it is replaced in tests.
var writeFile = writeFileAtomically

// loadOrCreateDeviceID returns the device id kept in the file, which is a UUID
// that identifies this installation to the servers. The id is created and
// stored on first use, and it is the same after restarts.
//
// It fails when the id cannot be read or stored, and the agent does not run
// without one. An agent that started with a new id every time would take a new
// lease on every start.
func loadOrCreateDeviceID(path string) (string, error) {
	if path == "" {
		return "", errors.New("no file to keep the device id in")
	}
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if id := strings.ToLower(strings.TrimSpace(string(b))); deviceIDRegexp.MatchString(id) {
			return id, nil
		}
		logger.Errorf("Invalid device id in %s, creating a new one", path)
	case errors.Is(err, os.ErrNotExist):
	default:
		return "", fmt.Errorf("cannot read the device id from %s: %w", path, err)
	}

	id, err := newDeviceID()
	if err != nil {
		return "", fmt.Errorf("cannot create a device id: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return "", fmt.Errorf("cannot store the device id in %s: %w", path, err)
	}
	if err := writeFile(path, []byte(id+"\n")); err != nil {
		return "", fmt.Errorf("cannot store the device id in %s: %w", path, err)
	}
	logger.Verbosef("Created device id %s in %s", id, path)
	return id, nil
}

// newDeviceID returns a random (version 4) UUID.
func newDeviceID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

// writeFileAtomically replaces the file with the content, so that a crash never
// leaves a partial file. The file is only readable by its owner.
func writeFileAtomically(path string, content []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".device-id-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
