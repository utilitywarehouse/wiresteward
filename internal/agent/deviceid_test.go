package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
)

const testID = "0b9e1c7a-4d52-4f0e-9a64-8d1f3c2b5e70"

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

func TestLoadOrCreateDeviceID_CreatesTheDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "agent", "device-id")
	id, err := loadOrCreateDeviceID(path)
	assert.NoError(t, err)
	assert.Regexp(t, deviceIDRegexp, id)
}

// An id that is written by hand is used as it is, in its canonical form, and
// the file is left alone: the id must not rotate because of how it is spelled.
func TestLoadOrCreateDeviceID_AcceptsOtherSpellingsOfAUUID(t *testing.T) {
	for name, content := range map[string]string{
		"canonical":      testID + "\n",
		"no newline":     testID,
		"windows":        testID + "\r\n",
		"spaces":         "  " + testID + " \n\n",
		"uppercase":      strings.ToUpper(testID) + "\n",
		"braces":         "{" + testID + "}\n",
		"urn":            "urn:uuid:" + testID + "\n",
		"urn uppercase":  "URN:UUID:" + strings.ToUpper(testID),
		"without dashes": strings.ReplaceAll(testID, "-", "") + "\n",
		"byte order":     "\ufeff" + testID + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "device-id")
			assert.NoError(t, os.WriteFile(path, []byte(content), 0600))
			id, err := loadOrCreateDeviceID(path)
			assert.NoError(t, err)
			assert.Equal(t, testID, id)
			b, _ := os.ReadFile(path)
			assert.Equal(t, content, string(b), "the file is not rewritten")
		})
	}
}

// Content that is not an id is not replaced, the agent does not guess.
func TestLoadOrCreateDeviceID_FailsOnOtherContent(t *testing.T) {
	for name, content := range map[string]string{
		"text":        "not an id",
		"short":       testID[:35],
		"long":        testID + "0",
		"two ids":     testID + "\n" + testID + "\n",
		"not hex":     strings.Replace(testID, "0b9e", "zzzz", 1),
		"half braces": "{" + testID,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "device-id")
			assert.NoError(t, os.WriteFile(path, []byte(content), 0600))
			id, err := loadOrCreateDeviceID(path)
			assert.ErrorContains(t, err, "invalid device id")
			assert.Equal(t, "", id)
			b, _ := os.ReadFile(path)
			assert.Equal(t, content, string(b), "the file is left alone")
		})
	}
}

// An empty file is what a crash can leave behind.
func TestLoadOrCreateDeviceID_ReplacesAnEmptyFile(t *testing.T) {
	for name, content := range map[string]string{"empty": "", "blank": " \n\n", "byte order": "\ufeff"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "device-id")
			assert.NoError(t, os.WriteFile(path, []byte(content), 0600))
			id, err := loadOrCreateDeviceID(path)
			assert.NoError(t, err)
			assert.Regexp(t, deviceIDRegexp, id)
			again, err := loadOrCreateDeviceID(path)
			assert.NoError(t, err)
			assert.Equal(t, id, again, "the replacement is kept")
		})
	}
}

// Two starts of the agent that find no file at the same time end up with one id,
// the one that is stored.
func TestLoadOrCreateDeviceID_ConcurrentFirstStartsAgree(t *testing.T) {
	for round := 0; round < 20; round++ {
		dir := t.TempDir()
		path := filepath.Join(dir, "device-id")
		const starts = 16
		ids := make([]string, starts)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < starts; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				id, err := loadOrCreateDeviceID(path)
				assert.NoError(t, err)
				ids[i] = id
			}(i)
		}
		close(start)
		wg.Wait()

		b, err := os.ReadFile(path)
		assert.NoError(t, err)
		stored := strings.TrimSpace(string(b))
		for _, id := range ids {
			assert.Equal(t, stored, id)
		}
		entries, _ := os.ReadDir(dir)
		assert.Len(t, entries, 1, "no temporary files are left")
	}
}

func TestWriteFileAtomically_ExclusiveLeavesAnExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device-id")

	created, err := writeFileAtomically(path, []byte("first\n"), true)
	assert.NoError(t, err)
	assert.True(t, created)

	created, err = writeFileAtomically(path, []byte("second\n"), true)
	assert.NoError(t, err)
	assert.False(t, created)
	b, _ := os.ReadFile(path)
	assert.Equal(t, "first\n", string(b))

	// Without exclusive it replaces the file.
	created, err = writeFileAtomically(path, []byte("third\n"), false)
	assert.NoError(t, err)
	assert.True(t, created)
	b, _ = os.ReadFile(path)
	assert.Equal(t, "third\n", string(b))
}

func TestLoadOrCreateDeviceID_FailsWhenTheFileCannotBeWritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device-id")
	defer func(w func(string, []byte, bool) (bool, error)) { writeFile = w }(writeFile)
	writeFile = func(string, []byte, bool) (bool, error) { return false, errors.New("disk full") }

	id, err := loadOrCreateDeviceID(path)
	assert.ErrorContains(t, err, "disk full")
	assert.Equal(t, "", id)
	_, statErr := os.Stat(path)
	assert.True(t, os.IsNotExist(statErr))
}

func TestLoadOrCreateDeviceID_FailsWhenItCannotAgree(t *testing.T) {
	// The file keeps being created by someone else but is never there to read.
	path := filepath.Join(t.TempDir(), "device-id")
	defer func(w func(string, []byte, bool) (bool, error)) { writeFile = w }(writeFile)
	writeFile = func(string, []byte, bool) (bool, error) { return false, nil }

	id, err := loadOrCreateDeviceID(path)
	assert.Error(t, err)
	assert.Equal(t, "", id)
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
}

// Some platforms deny hard links (the SELinux policy of Android apps answers
// EACCES), the id is stored with a rename there.
func TestLoadOrCreateDeviceID_WorksWithoutHardLinks(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EACCES, syscall.EPERM, syscall.ENOTSUP, syscall.EXDEV, syscall.ENOSYS} {
		t.Run(errno.Error(), func(t *testing.T) {
			defer func(l func(string, string) error) { linkFile = l }(linkFile)
			linkFile = func(old, new string) error { return &os.LinkError{Op: "link", Old: old, New: new, Err: errno} }

			dir := t.TempDir()
			path := filepath.Join(dir, "device-id")
			id, err := loadOrCreateDeviceID(path)
			assert.NoError(t, err)
			assert.Regexp(t, deviceIDRegexp, id)
			again, err := loadOrCreateDeviceID(path)
			assert.NoError(t, err)
			assert.Equal(t, id, again)
			entries, _ := os.ReadDir(dir)
			assert.Len(t, entries, 1, "no temporary files are left")
		})
	}
}

func TestWriteFileAtomically_LinkErrorsOtherThanDeniedAreReturned(t *testing.T) {
	defer func(l func(string, string) error) { linkFile = l }(linkFile)
	linkFile = func(old, new string) error { return &os.LinkError{Op: "link", Old: old, New: new, Err: syscall.EIO} }
	created, err := writeFileAtomically(filepath.Join(t.TempDir(), "device-id"), []byte("x\n"), true)
	assert.Error(t, err)
	assert.False(t, created)
}
