package test

import (
	"my_project/client/internal/probe/ebpf/fentry"
	"os"
	"os/signal"
	"syscall"
	"testing"
)

func TestFentryManager(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("This test requires root privileges.")
	}

	// create a manager
	manager, err := fentry.NewFentryManager()
	if err != nil {
		t.Fatalf("Create fentry manager failed: %v", err)
	}
	defer manager.Close()

	// Start
	err = manager.Start()
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	defer manager.Stop()

	eventChan := manager.Events()
	go func() {
		for event := range eventChan {
			t.Logf("Event: %s", fentry.FormatEvent(event))
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	t.Log("Fentry manager stopped")
}
