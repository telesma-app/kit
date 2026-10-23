package ctapkit

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/ctap/transport/ctaphid"
	"github.com/telesma-app/hid"
	rtauthenticator "github.com/telesma-app/kit/internal/authenticator"
	"github.com/telesma-app/kit/internal/devicewatch"
	"github.com/telesma-app/kit/model/report"
	"github.com/telesma-app/kit/transport"
	"github.com/telesma-app/yubico"
)

type sourceInfo struct {
	value  protocol.AuthenticatorGetInfoResponse
	cached bool
	err    error
}

func (s *sourceInfo) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return s.value, s.cached
}
func (s *sourceInfo) GetInfo(context.Context) (protocol.AuthenticatorGetInfoResponse, error) {
	return s.value, s.err
}

type vendorReadFunc func(context.Context, ctaphid.Command, []byte) (ctaphid.VendorResponse, error)

func (f vendorReadFunc) Vendor(ctx context.Context, command ctaphid.Command, data []byte) (ctaphid.VendorResponse, error) {
	return f(ctx, command, data)
}

func oneHIDWatcher(vendor uint16) *fakeDeviceWatcher {
	candidate := hidCandidate("one")
	candidate.HID.VendorID = hid.Descriptor[uint16]{Value: new(vendor)}

	return &fakeDeviceWatcher{snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{candidate}}, events: make(chan devicewatch.Event, 1)}
}

func TestDiscoveryLeavesMDSExplicit(t *testing.T) {
	manager := newTestDeviceManager(t, oneHIDWatcher(0xffff), func(context.Context, transport.Mode, string) (*rtauthenticator.Opened, error) {
		return openedDevice(nil), nil
	})

	state := manager.State()
	if state.Selected == nil || state.Snapshot.Endpoints[0].Sources.MDS.State != report.SourceNotRequested {
		t.Fatal("discovery unexpectedly requested metadata")
	}
}

func TestUnknownVendorRemainsUsable(t *testing.T) {
	manager := newTestDeviceManagerWithResolver(t, oneHIDWatcher(0xffff), func(context.Context, transport.Mode, string) (*rtauthenticator.Opened, error) {
		return openedDevice(nil), nil
	}, readVendorSources)
	selected := manager.State().Selected

	result, err := manager.ReadEndpointSources(t.Context(), manager.State().Snapshot.SelectedEndpoint)
	if err != nil {
		t.Fatal(err)
	}

	if result.Sources.Yubico.State != report.SourceUnsupported || result.Sources.Yubico.Reason != report.ReasonVendorMismatch {
		t.Fatalf("vendor source = %#v", result.Sources.Yubico)
	}

	if manager.State().Selected != selected {
		t.Fatal("source enrichment replaced runtime")
	}

	if _, err := selected.GetInfo(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestKnownVendorWithoutHandleReportsTransportPrerequisite(t *testing.T) {
	target := newAttachment(oneHIDWatcher(yubicoVendorID).snapshot.Candidates[0])

	sources, err := readVendorSources(t.Context(), target, nil)
	if err != nil {
		t.Fatal(err)
	}

	if sources.yubico.State != report.SourceUnavailable || sources.yubico.Reason != report.ReasonTransport {
		t.Fatalf("Yubico = %#v", sources.yubico)
	}
}

func TestGetInfoFailureKeepsINITAndVendorResults(t *testing.T) {
	var (
		closes atomic.Int32
		reads  atomic.Int32
	)

	getInfoErr := errors.New("GetInfo failed")
	manager := newTestDeviceManagerWithResolver(t, oneHIDWatcher(yubicoVendorID), func(context.Context, transport.Mode, string) (*rtauthenticator.Opened, error) {
		return &rtauthenticator.Opened{
			Lifecycle: &fakeDeviceLifecycle{close: func() { closes.Add(1) }},
			HIDInit:   &ctaphid.InitResponse{MajorDeviceVersion: 7},
			Vendor: vendorReadFunc(func(context.Context, ctaphid.Command, []byte) (ctaphid.VendorResponse, error) {
				reads.Add(1)
				return ctaphid.VendorResponse{Data: yubicoInfoPayload()}, nil
			}),
		}, getInfoErr
	}, readVendorSources)
	id := manager.State().Snapshot.SelectedEndpoint

	result, err := manager.ReadEndpointSources(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}

	if result.Sources.GetInfo.State != report.SourceFailed || result.Sources.HIDInit.Data.MajorDeviceVersion != 7 {
		t.Fatalf("standard sources = %#v", result.Sources)
	}

	if result.Sources.Yubico.State != report.SourceAvailable || *result.Sources.Yubico.Data.SerialNumber != 42 {
		t.Fatalf("Yubico = %#v", result.Sources.Yubico)
	}

	if reads.Load() != 1 || closes.Load() != 2 {
		t.Fatalf("reads/closes = %d/%d", reads.Load(), closes.Load())
	}

	if manager.State().Selected != nil || manager.State().Snapshot.SelectedEndpoint != id {
		t.Fatal("failed runtime lost view selection")
	}
}

func TestReadSourcesSerializesWithWorkflowsAndKeepsSession(t *testing.T) {
	started := make(chan struct{})
	manager := newTestDeviceManagerWithResolver(t, oneHIDWatcher(yubicoVendorID), func(context.Context, transport.Mode, string) (*rtauthenticator.Opened, error) {
		return openedDevice(nil), nil
	}, func(context.Context, attachment, *rtauthenticator.Opened) (vendorSources, error) {
		close(started)
		return vendorSources{yubico: report.YubicoSource{Outcome: sourceOutcome(nil), Data: &yubico.DeviceInfo{SerialNumber: new(uint32(42))}}}, nil
	})

	selected := manager.State().Selected
	selected.runGate <- struct{}{}

	done := make(chan error, 1)

	go func() {
		_, err := manager.ReadEndpointSources(t.Context(), manager.State().Snapshot.SelectedEndpoint)
		done <- err
	}()

	select {
	case <-started:
		<-selected.runGate
		t.Fatal("management interleaved with workflow")
	case <-time.After(20 * time.Millisecond):
	}

	<-selected.runGate

	if err := <-done; err != nil {
		t.Fatal(err)
	}

	if manager.State().Selected != selected || selected.Endpoint().Sources.Yubico.Data == nil {
		t.Fatal("enrichment changed or did not update selected runtime")
	}
}

func TestReadSourcesPreservesPartialResultOnInvalidation(t *testing.T) {
	var closes atomic.Int32

	manager := newTestDeviceManagerWithResolver(t, oneHIDWatcher(yubicoVendorID), func(context.Context, transport.Mode, string) (*rtauthenticator.Opened, error) {
		return openedDevice(func() { closes.Add(1) }), nil
	}, func(context.Context, attachment, *rtauthenticator.Opened) (vendorSources, error) {
		return vendorSources{yubico: report.YubicoSource{Outcome: sourceOutcome(nil), Data: &yubico.DeviceInfo{SerialNumber: new(uint32(42))}}}, &ctaptransport.DeviceInvalidatedError{Err: errors.New("transport lost")}
	})
	id := manager.State().Snapshot.SelectedEndpoint

	result, err := manager.ReadEndpointSources(t.Context(), id)
	if err == nil || result.Sources.Yubico.Data == nil {
		t.Fatalf("partial result = %#v, err = %v", result, err)
	}

	if manager.State().Selected != nil || manager.State().Snapshot.SelectedEndpoint != id {
		t.Fatal("invalidation retained runtime or removed attachment")
	}

	if manager.State().Snapshot.Endpoints[0].Sources.Yubico.Data == nil || closes.Load() != 1 {
		t.Fatal("partial source lost or handle not released")
	}
}

func TestManagerCloseUnblocksSourceIOAndIsIdempotent(t *testing.T) {
	entered := make(chan struct{})
	closed := make(chan struct{})

	var closes atomic.Int32

	manager := newTestDeviceManagerWithResolver(t, oneHIDWatcher(yubicoVendorID), func(context.Context, transport.Mode, string) (*rtauthenticator.Opened, error) {
		return openedDevice(func() { closes.Add(1); close(closed) }), nil
	}, func(ctx context.Context, _ attachment, _ *rtauthenticator.Opened) (vendorSources, error) {
		close(entered)
		<-closed // Simulate I/O that needs transport Close, not just ctx.Done.

		return vendorSources{}, ctx.Err()
	})

	done := make(chan struct{})
	go func() {
		defer close(done)

		_, _ = manager.ReadEndpointSources(t.Context(), manager.State().Snapshot.SelectedEndpoint)
	}()

	<-entered

	var wait sync.WaitGroup
	for range 2 {
		wait.Go(func() { _ = manager.Close() })
	}

	finished := make(chan struct{})

	go func() { wait.Wait(); close(finished) }()

	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("Close blocked on source I/O")
	}

	<-done

	if closes.Load() != 1 {
		t.Fatalf("closes = %d", closes.Load())
	}
}

func yubicoInfoPayload() []byte {
	data := []byte{
		0, 1, 2, 0, 0,
		2, 4, 0, 0, 0, 42,
		3, 2, 0, 0,
		4, 1, 1,
		5, 3, 5, 7, 1,
		6, 2, 0, 0,
		7, 1, 0,
		8, 1, 0,
		10, 1, 0,
	}
	data[0] = byte(len(data) - 1)

	return data
}

func TestCanceledQueuedSourceReadKeepsActiveSession(t *testing.T) {
	info := &blockedWorkflowInfo{started: make(chan struct{})}
	info.cacheValid.Store(true)

	watcher := &fakeDeviceWatcher{
		snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{hidCandidate("a"), hidCandidate("b")}},
		events:   make(chan devicewatch.Event),
	}
	manager := newTestDeviceManager(t, watcher, func(_ context.Context, _ transport.Mode, path string) (*rtauthenticator.Opened, error) {
		opened := openedDevice(nil)
		if path == "a" {
			opened.Info = info
		}

		return opened, nil
	})
	selected := manager.State().Selected

	info.cacheValid.Store(false)

	workflowCtx, cancelWorkflow := context.WithCancel(t.Context())
	defer cancelWorkflow()

	workflowDone := make(chan error, 1)

	go func() { _, err := selected.GetInfo(workflowCtx); workflowDone <- err }()

	<-info.started

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	done := make(chan error, 1)

	go func() {
		_, err := manager.ReadEndpointSources(ctx, manager.State().Snapshot.SelectedEndpoint)
		done <- err
	}()

	waitForDeviceManager(t, func() bool { return manager.State().Snapshot.Endpoints[0].Sources.Yubico.State == report.SourceLoading })
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("queued read error = %v, want cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled read still waits for the active workflow")
	}

	if selected.Closed() || manager.State().Selected != selected {
		t.Fatal("queued cancellation closed active session")
	}

	select {
	case err := <-workflowDone:
		t.Fatalf("queued cancellation interrupted active workflow: %v", err)
	default:
	}

	nextCtx, cancelNext := context.WithTimeout(t.Context(), time.Second)
	defer cancelNext()

	if _, err := manager.ReadEndpointSources(nextCtx, attachmentID(transport.ModeHID, "b")); err != nil {
		t.Fatalf("canceled read retained the source slot: %v", err)
	}

	cancelWorkflow()

	if err := <-workflowDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("workflow error = %v, want cancellation", err)
	}
}

type blockedWorkflowInfo struct {
	cacheValid      atomic.Bool
	started         chan struct{}
	transportClosed <-chan struct{}
	waitForClose    bool
}

func (s *blockedWorkflowInfo) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return protocol.AuthenticatorGetInfoResponse{}, s.cacheValid.Load()
}

func (s *blockedWorkflowInfo) GetInfo(ctx context.Context) (protocol.AuthenticatorGetInfoResponse, error) {
	close(s.started)

	if s.waitForClose {
		<-s.transportClosed
	} else {
		<-ctx.Done()
	}

	return protocol.AuthenticatorGetInfoResponse{}, ctx.Err()
}

func TestManagerShutdownUnblocksWorkflowWithQueuedSourceRead(t *testing.T) {
	for _, waitForClose := range []bool{false, true} {
		name := "context-cancellation"
		if waitForClose {
			name = "transport-close"
		}

		t.Run(name, func(t *testing.T) {
			transportClosed := make(chan struct{})
			info := &blockedWorkflowInfo{
				started:         make(chan struct{}),
				transportClosed: transportClosed,
				waitForClose:    waitForClose,
			}
			info.cacheValid.Store(true)

			var closes atomic.Int32

			manager := newTestDeviceManager(t, oneHIDWatcher(0xffff), func(context.Context, transport.Mode, string) (*rtauthenticator.Opened, error) {
				opened := openedDevice(func() {
					closes.Add(1)
					close(transportClosed)
				})
				opened.Info = info

				return opened, nil
			})
			selected := manager.State().Selected
			id := manager.State().Snapshot.SelectedEndpoint

			info.cacheValid.Store(false)

			workflowDone := make(chan error, 1)

			go func() {
				_, err := selected.GetInfo(t.Context())
				workflowDone <- err
			}()

			<-info.started

			sourcesDone := make(chan error, 1)

			go func() {
				_, err := manager.ReadEndpointSources(t.Context(), id)
				sourcesDone <- err
			}()

			waitForDeviceManager(t, func() bool {
				return manager.State().Snapshot.Endpoints[0].Sources.Yubico.State == report.SourceLoading
			})

			closeStart := make(chan struct{})
			closeDone := make(chan error, 2)

			for range 2 {
				go func() {
					<-closeStart

					closeDone <- manager.Close()
				}()
			}

			close(closeStart)

			for range 2 {
				select {
				case err := <-closeDone:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("manager shutdown blocked behind the queued source read")
				}
			}

			if err := <-workflowDone; err == nil {
				t.Fatal("shutdown did not cancel the active workflow")
			}

			if err := <-sourcesDone; err == nil {
				t.Fatal("queued source read succeeded during shutdown")
			}

			if closes.Load() != 1 || manager.State().Selected != nil {
				t.Fatalf("shutdown state: closes = %d, selected = %p", closes.Load(), manager.State().Selected)
			}
		})
	}
}

func TestSmartCardReportSurvivesFailedCTAPOpen(t *testing.T) {
	watcher := &fakeDeviceWatcher{snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{smartCardCandidate("reader", 1)}}, events: make(chan devicewatch.Event)}
	manager := newTestDeviceManagerWithResolver(t, watcher, func(context.Context, transport.Mode, string) (*rtauthenticator.Opened, error) {
		card := &rtauthenticator.SmartCard{Card: &borrowedCard{}}
		return &rtauthenticator.Opened{Lifecycle: card, Card: card}, errors.New("GetInfo failed")
	}, readVendorSources)

	value, err := manager.ReadEndpointSources(t.Context(), manager.State().Snapshot.SelectedEndpoint)
	if err != nil {
		t.Fatal(err)
	}

	if value.Sources.GetInfo.State != report.SourceFailed || value.Sources.Yubico.Data == nil {
		t.Fatalf("partial report = %#v", value.Sources)
	}

	if manager.State().Selected != nil {
		t.Fatal("failed GetInfo created usable runtime")
	}
}
