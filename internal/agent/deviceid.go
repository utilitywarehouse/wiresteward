package agent

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

var deviceIDRegexp = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// writeFile stores the device id, it is replaced in tests. With exclusive set
// it only creates the file and reports false when it already exists.
var writeFile = writeFileAtomically

// loadOrCreateDeviceID returns the device id kept in the file, which is a UUID
// that identifies this installation to the servers. The id is created and
// stored on first use, and it is the same after restarts.
//
// It fails when the id cannot be read or stored, and the agent does not run
// without one. An agent that started with a new id every time would take a new
// lease on every start. It also fails when the file has other content than an
// id, which it does not replace: an id that is written by hand can be a
// canonical UUID, with or without dashes, braces or a `urn:uuid:` prefix. Only
// an empty file, what a crash can leave behind, is replaced.
func loadOrCreateDeviceID(path string) (string, error) {
	if path == "" {
		return "", errors.New("no file to keep the device id in")
	}
	// Another start of the agent can create the file after we found it
	// missing. It wins, and its id is read.
	for attempt := 0; attempt < 3; attempt++ {
		b, err := os.ReadFile(path)
		exists := err == nil
		switch {
		case exists:
			content := strings.TrimSpace(strings.TrimPrefix(string(b), "\ufeff"))
			if content != "" {
				id, ok := normalizeDeviceID(content)
				if !ok {
					return "", fmt.Errorf("invalid device id in %s, remove the file to create a new one", path)
				}
				return id, nil
			}
			logger.Errorf("Empty device id file %s, creating a new id", path)
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
		created, err := writeFile(path, []byte(id+"\n"), !exists)
		if err != nil {
			return "", fmt.Errorf("cannot store the device id in %s: %w", path, err)
		}
		if created {
			logger.Verbosef("Created device id %s in %s", id, path)
			return id, nil
		}
	}
	return "", fmt.Errorf("cannot settle on a device id in %s", path)
}

// normalizeDeviceID returns the canonical form of a device id written as a
// UUID, in either case, with or without dashes, with braces or with a urn:uuid:
// prefix.
func normalizeDeviceID(s string) (string, bool) {
	s = strings.ToLower(s)
	s = strings.TrimPrefix(s, "urn:uuid:")
	if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
		s = s[1 : len(s)-1]
	}
	if len(s) == 32 && !strings.Contains(s, "-") {
		s = s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
	}
	return s, deviceIDRegexp.MatchString(s)
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

// linkFile is os.Link, replaced in tests.
var linkFile = os.Link

// writeFileAtomically stores the content in the file, so that a crash never
// leaves a partial file: it is written and synced under another name, which is
// then put in place, and the directory is synced. The file is only readable by
// its owner. With exclusive set an existing file is left alone and false is
// returned, which is what makes two processes that create it at once agree on
// one content.
func writeFileAtomically(path string, content []byte, exclusive bool) (bool, error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".device-id-*")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}

	if exclusive {
		err := linkFile(tmp.Name(), path)
		switch {
		case err == nil:
			syncDir(dir)
			return true, nil
		case errors.Is(err, os.ErrExist):
			return false, nil
		case !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.ENOTSUP) &&
			!errors.Is(err, syscall.EXDEV) && !errors.Is(err, syscall.ENOSYS) &&
			!errors.Is(err, syscall.EACCES):
			return false, err
		}
		// Hard links are not available, the file system has none or the
		// platform denies them (EACCES, the SELinux policy of Android
		// apps): fall back to a rename, which does not tell a file that was
		// created in the meantime. The temporary file was created in the
		// same directory, so a rename is not denied by its permissions.
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return false, err
	}
	syncDir(dir)
	return true, nil
}

// syncDir makes the entries of a directory durable. Some file systems do not
// support it, which is not an error for the agent.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
}
