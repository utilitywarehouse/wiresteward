package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadOrCreateDeviceID_CreatesAndKeepsAnID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device-id")

	id, err := loadOrCreateDeviceID(path)
	assert.NoError(t, err)
	assert.Regexp(t, deviceIDRegexp, id)
	// A version 4 UUID.
	assert.Equal(t, byte('4'), id[14])
	assert.Contains(t, "89ab", string(id[19]))

	b, err := os.ReadFile(path)
	assert.NoError(t, err)
	assert.Equal(t, id+"\n", string(b))
	info, err := os.Stat(path)
	assert.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	// Every start gets the same id.
	for i := 0; i < 5; i++ {
		again, err := loadOrCreateDeviceID(path)
		assert.NoError(t, err)
		assert.Equal(t, id, again)
	}
}

func TestLoadOrCreateDeviceID_IDsDiffer(t *testing.T) {
	a, err := loadOrCreateDeviceID(filepath.Join(t.TempDir(), "device-id"))
	assert.NoError(t, err)
	b, err := loadOrCreateDeviceID(filepath.Join(t.TempDir(), "device-id"))
	assert.NoError(t, err)
	assert.NotEqual(t, a, b)
}

func TestLoadOrCreateDeviceID_UsesTheIDInTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device-id")
	assert.NoError(t, os.WriteFile(path, []byte("  0B9E1C7A-4D52-4F0E-9A64-8D1F3C2B5E70\n"), 0600))
	id, err := loadOrCreateDeviceID(path)
	assert.NoError(t, err)
	assert.Equal(t, "0b9e1c7a-4d52-4f0e-9a64-8d1f3c2b5e70", id)
	b, _ := os.ReadFile(path)
	assert.Equal(t, "  0B9E1C7A-4D52-4F0E-9A64-8D1F3C2B5E70\n", string(b), "a valid file is not rewritten")
}

func TestLoadOrCreateDeviceID_ReplacesAnInvalidIDOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device-id")
	assert.NoError(t, os.WriteFile(path, []byte("not an id"), 0600))

	id, err := loadOrCreateDeviceID(path)
	assert.NoError(t, err)
	assert.Regexp(t, deviceIDRegexp, id)
	again, err := loadOrCreateDeviceID(path)
	assert.NoError(t, err)
	assert.Equal(t, id, again, "the replacement is kept")
}

func TestLoadOrCreateDeviceID_CreatesTheDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "agent", "device-id")
	id, err := loadOrCreateDeviceID(path)
	assert.NoError(t, err)
	assert.Regexp(t, deviceIDRegexp, id)
}

func TestLoadOrCreateDeviceID_FailsWhenItCannotBeStored(t *testing.T) {
	// A file where the directory should be: nothing can be written there. The
	// agent must not make up an id that it cannot keep.
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	assert.NoError(t, os.WriteFile(blocker, nil, 0600))
	id, err := loadOrCreateDeviceID(filepath.Join(blocker, "device-id"))
	assert.Error(t, err)
	assert.Equal(t, "", id)
}

func TestLoadOrCreateDeviceID_FailsWhenTheFileCannotBeWritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device-id")
	defer func(w func(string, []byte) error) { writeFile = w }(writeFile)
	writeFile = func(string, []byte) error { return errors.New("disk full") }

	id, err := loadOrCreateDeviceID(path)
	assert.ErrorContains(t, err, "disk full")
	assert.Equal(t, "", id)
	_, statErr := os.Stat(path)
	assert.True(t, os.IsNotExist(statErr))
}

func TestLoadOrCreateDeviceID_FailsInAReadOnlyDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write to a read-only directory")
	}
	dir := filepath.Join(t.TempDir(), "readonly")
	assert.NoError(t, os.Mkdir(dir, 0500))
	for _, path := range []string{
		filepath.Join(dir, "device-id"),            // the file cannot be created
		filepath.Join(dir, "missing", "device-id"), // the directory cannot be created
	} {
		id, err := loadOrCreateDeviceID(path)
		assert.Error(t, err, path)
		assert.Equal(t, "", id, path)
	}
}

func TestLoadOrCreateDeviceID_FailsWhenItCannotBeRead(t *testing.T) {
	// A directory in place of the file is an error that is not "not found".
	path := filepath.Join(t.TempDir(), "device-id")
	assert.NoError(t, os.Mkdir(path, 0700))
	id, err := loadOrCreateDeviceID(path)
	assert.Error(t, err)
	assert.Equal(t, "", id)
	info, err := os.Stat(path)
	assert.NoError(t, err)
	assert.True(t, info.IsDir(), "the path is left alone")
}

func TestLoadOrCreateDeviceID_FailsWithoutAFile(t *testing.T) {
	_, err := loadOrCreateDeviceID("")
	assert.Error(t, err)
}

func TestLoadOrCreateDeviceID_LeavesNoTemporaryFiles(t *testing.T) {
	dir := t.TempDir()
	_, err := loadOrCreateDeviceID(filepath.Join(dir, "device-id"))
	assert.NoError(t, err)
	entries, err := os.ReadDir(dir)
	assert.NoError(t, err)
	names := []string{}
	for _, e := range entries {
		names = append(names, e.Name())
	}
	assert.Equal(t, []string{"device-id"}, names)
	assert.False(t, strings.HasPrefix(names[0], "."))
}
