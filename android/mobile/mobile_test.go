package mobile

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

type noProvider struct{}

func (noProvider) Establish(string, int, string, int) (int, error) { return -1, nil }

func TestStartOptions_Defaults(t *testing.T) {
	opts, err := (&StartOptions{ConfigPath: "/c", FilesDir: "/f"}).withDefaults()
	assert.NoError(t, err)
	assert.Equal(t, "localhost:7773", opts.ListenAddr)
	assert.Equal(t, "error", opts.LogLevel)
	assert.Equal(t, "wiresteward-android", opts.UserAgent, "an empty user agent is not sent empty")
	assert.Equal(t, "/c", opts.ConfigPath)
	assert.Equal(t, "/f", opts.FilesDir)

	opts, err = (&StartOptions{
		ConfigPath: "/c", FilesDir: "/f", ListenAddr: "127.0.0.1:1", LogLevel: "error",
		UserAgent: "wiresteward-android/1 (Android 15; arm64-v8a)",
	}).withDefaults()
	assert.NoError(t, err)
	assert.Equal(t, "127.0.0.1:1", opts.ListenAddr)
	assert.Equal(t, "error", opts.LogLevel)
	assert.Equal(t, "wiresteward-android/1 (Android 15; arm64-v8a)", opts.UserAgent)
}

func TestStartOptions_Required(t *testing.T) {
	var nilOpts *StartOptions
	_, err := nilOpts.withDefaults()
	assert.Error(t, err)
	_, err = (&StartOptions{FilesDir: "/f"}).withDefaults()
	assert.ErrorContains(t, err, "config path")
	_, err = (&StartOptions{ConfigPath: "/c"}).withDefaults()
	assert.ErrorContains(t, err, "files dir")
}

func TestStart_RejectsBadArguments(t *testing.T) {
	assert.Error(t, Start(nil, noProvider{}))
	assert.Error(t, Start(&StartOptions{ConfigPath: "/c", FilesDir: "/f"}, nil))
	// An unreadable config does not leave an agent running.
	assert.Error(t, Start(&StartOptions{ConfigPath: "/does/not/exist", FilesDir: t.TempDir()}, noProvider{}))
	var status struct{ Running bool }
	assert.NoError(t, json.Unmarshal([]byte(Status()), &status))
	assert.False(t, status.Running)
}
