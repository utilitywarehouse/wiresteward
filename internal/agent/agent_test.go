package agent

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/utilitywarehouse/wiresteward/internal/config"
)

func TestAgent_Stop(t *testing.T) {
	a := NewAgent(&config.AgentConfig{}, Options{
		ListenAddress: "127.0.0.1:0",
		TokenFile:     filepath.Join(t.TempDir(), "token"),
	})
	done := make(chan struct{})
	go func() {
		a.ListenAndServe()
		close(done)
	}()
	a.Stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ListenAndServe did not return after Stop")
	}
}

func TestAgent_StatusWithoutToken(t *testing.T) {
	a := NewAgent(&config.AgentConfig{}, Options{
		TokenFile: filepath.Join(t.TempDir(), "token"),
	})
	st := a.Status()
	if st.Token.Present {
		t.Fatal("expected no token")
	}
	if st.Devices == nil || len(st.Devices) != 0 {
		t.Fatalf("expected an empty device list, got %v", st.Devices)
	}
}
