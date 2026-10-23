package ctapkit

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	"github.com/telesma-app/ctap/protocol"
	rtauthenticator "github.com/telesma-app/kit/internal/authenticator"
	"github.com/telesma-app/kit/internal/devicewatch"
	appoperation "github.com/telesma-app/kit/model/operation"
	"github.com/telesma-app/kit/model/report"
	"github.com/telesma-app/kit/transport"
	"github.com/telesma-app/mds"
	mdsmodel "github.com/telesma-app/mds/model"
)

func TestSelectionAndRemovalInterruptWorkflowWithQueuedSources(t *testing.T) {
	for _, disconnect := range []bool{false, true} {
		name := "selection"
		if disconnect {
			name = "removal"
		}

		t.Run(name, func(t *testing.T) {
			info := &blockedWorkflowInfo{started: make(chan struct{})}
			info.cacheValid.Store(true)

			watcher := &fakeDeviceWatcher{
				snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{hidCandidate("a"), hidCandidate("b")}},
				events:   make(chan devicewatch.Event, 1),
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

			workflowDone := make(chan error, 1)

			go func() { _, err := selected.GetInfo(t.Context()); workflowDone <- err }()

			<-info.started

			sourceDone := make(chan error, 1)

			go func() {
				_, err := manager.ReadEndpointSources(t.Context(), attachmentID(transport.ModeHID, "a"))
				sourceDone <- err
			}()

			waitForDeviceManager(t, func() bool { return manager.State().Snapshot.Endpoints[0].Sources.Yubico.State == report.SourceLoading })

			if disconnect {
				watcher.events <- devicewatch.Event{Type: devicewatch.EventDisconnected, Candidate: hidCandidate("a")}
			} else {
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()

				if err := manager.SelectEndpoint(ctx, attachmentID(transport.ModeHID, "b")); err != nil {
					t.Fatalf("selection blocked behind source read: %v", err)
				}
			}

			waitForSelected(t, manager, attachmentID(transport.ModeHID, "b"))

			for _, done := range []<-chan error{workflowDone, sourceDone} {
				select {
				case err := <-done:
					if err == nil {
						t.Error("old operation was not canceled")
					}
				case <-time.After(time.Second):
					t.Fatal("old operation did not finish")
				}
			}

			if !selected.Closed() || manager.State().Selected == selected {
				t.Fatal("old runtime survived selection boundary")
			}
		})
	}
}

func holdWorkflow(t *testing.T, selected *Authenticator) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	started := make(chan struct{})
	done := make(chan error, 1)

	go func() {
		_, err := executeSerializedOperation(selected, ctx, appoperation.GetInfo, func(ctx context.Context) (struct{}, error) {
			close(started)
			<-ctx.Done()

			return struct{}{}, ctx.Err()
		})
		done <- err
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("workflow did not start")
	}

	return cancel, done
}

func TestHotplugWaitsForWorkflowAndKeepsGateThroughCleanup(t *testing.T) {
	watcher := &fakeDeviceWatcher{snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{hidCandidate("hid-a")}}, events: make(chan devicewatch.Event, 1)}
	opened := make(chan struct{}, 1)
	closing := make(chan struct{}, 1)
	release := make(chan struct{})

	var releaseOnce sync.Once

	manager := newTestDeviceManagerWithResolver(t, watcher, func(_ context.Context, _ transport.Mode, path string) (*rtauthenticator.Opened, error) {
		if path == "reader-a" {
			opened <- struct{}{}
			return openedDevice(func() { closing <- struct{}{}; <-release }), nil
		}

		return openedDevice(nil), nil
	}, func(context.Context, attachment, *rtauthenticator.Opened) (vendorSources, error) {
		return identitySources(report.DeviceIdentity{Vendor: report.VendorToken2, SerialNumber: "a"}), nil
	})
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })

	selected := manager.State().Selected
	if _, err := manager.ReadEndpointSources(t.Context(), manager.State().Snapshot.SelectedEndpoint); err != nil {
		t.Fatal(err)
	}

	id := manager.State().Snapshot.Selected
	cancel, workflowDone := holdWorkflow(t, selected)

	watcher.events <- devicewatch.Event{Type: devicewatch.EventConnected, Candidate: smartCardCandidate("reader-a", 1)}

	waitForDevices(t, manager, 2)

	if got := manager.State().Snapshot.Endpoints[1].Sources.GetInfo.State; got != report.SourceNotRequested {
		t.Fatalf("pending GetInfo = %s", got)
	}

	ctx, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()

	if err := manager.SelectEndpoint(ctx, manager.State().Snapshot.SelectedEndpoint); err != nil {
		t.Fatalf("manager blocked waiting for workflow: %v", err)
	}

	select {
	case <-opened:
		t.Fatal("hotplug opened a possible sibling during the workflow")
	case <-time.After(20 * time.Millisecond):
	}

	cancel()

	select {
	case err := <-workflowDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("workflow = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("workflow did not release its gate")
	}

	select {
	case <-closing:
	case <-time.After(time.Second):
		t.Fatal("hotplug did not reach temporary-handle cleanup")
	}

	nextStarted := make(chan struct{})
	nextDone := make(chan error, 1)

	go func() {
		_, err := executeSerializedOperation(selected, t.Context(), appoperation.GetInfo, func(context.Context) (struct{}, error) {
			close(nextStarted)
			return struct{}{}, nil
		})
		nextDone <- err
	}()

	select {
	case <-nextStarted:
		t.Fatal("next workflow entered before temporary-handle cleanup")
	case <-time.After(20 * time.Millisecond):
	}

	releaseOnce.Do(func() { close(release) })

	select {
	case err := <-nextDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("next workflow did not resume")
	}

	waitForDeviceManager(t, func() bool { return len(manager.State().Snapshot.Devices) == 1 })

	if manager.State().Snapshot.Selected != id || manager.State().Selected != selected {
		t.Fatal("sibling arrival replaced the selected physical runtime")
	}
}

func TestPendingHotplugRemovalAndShutdownDoNotWaitForWorkflow(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		name := "removal"
		if shutdown {
			name = "shutdown"
		}

		t.Run(name, func(t *testing.T) {
			watcher := &fakeDeviceWatcher{snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{hidCandidate("a")}}, events: make(chan devicewatch.Event, 1)}
			opened := make(chan struct{}, 1)
			manager := newTestDeviceManager(t, watcher, func(_ context.Context, _ transport.Mode, path string) (*rtauthenticator.Opened, error) {
				if path == "reader" {
					opened <- struct{}{}
				}

				return openedDevice(nil), nil
			})
			cancel, done := holdWorkflow(t, manager.State().Selected)

			candidate := smartCardCandidate("reader", 1)
			watcher.events <- devicewatch.Event{Type: devicewatch.EventConnected, Candidate: candidate}

			waitForDevices(t, manager, 2)

			if shutdown {
				closed := make(chan error, 1)
				go func() { closed <- manager.Close() }()

				select {
				case err := <-closed:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("shutdown waited for pending hotplug")
				}
			} else {
				watcher.events <- devicewatch.Event{Type: devicewatch.EventDisconnected, Candidate: candidate}

				waitForDevices(t, manager, 1)
				cancel()
			}

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("workflow did not finish")
			}

			select {
			case <-opened:
				t.Fatal("removed or shutdown arrival was opened")
			case <-time.After(20 * time.Millisecond):
			}
		})
	}
}

func TestSelectingPendingHotplugCancelsWorkflowAndInspectsOnce(t *testing.T) {
	watcher := &fakeDeviceWatcher{snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{hidCandidate("a")}}, events: make(chan devicewatch.Event, 1)}

	var opens atomic.Int32

	manager := newTestDeviceManager(t, watcher, func(_ context.Context, _ transport.Mode, path string) (*rtauthenticator.Opened, error) {
		if path == "reader" {
			opens.Add(1)
		}

		return openedDevice(nil), nil
	})
	_, done := holdWorkflow(t, manager.State().Selected)

	watcher.events <- devicewatch.Event{Type: devicewatch.EventConnected, Candidate: smartCardCandidate("reader", 1)}

	waitForDevices(t, manager, 2)

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	id := attachmentID(transport.ModeSmartCard, "reader")
	if err := manager.SelectEndpoint(ctx, id); err != nil {
		t.Fatalf("select pending arrival: %v", err)
	}

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("previous workflow = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("selection did not cancel previous workflow")
	}

	if err := manager.SelectEndpoint(ctx, id); err != nil {
		t.Fatal(err)
	}

	if opens.Load() != 1 || manager.State().Snapshot.SelectedEndpoint != id || manager.State().Selected == nil {
		t.Fatalf("pending selection: opens=%d state=%#v", opens.Load(), manager.State().Snapshot)
	}
}

func TestSourceReadAllowsTopologyAndMetadataUpdates(t *testing.T) {
	id := uuid.New()
	entered := make(chan struct{})
	release := make(chan struct{})
	watcher := oneHIDWatcher(0xffff)
	manager := newTestDeviceManagerWithResolver(t, watcher, func(context.Context, transport.Mode, string) (*rtauthenticator.Opened, error) {
		opened := openedDevice(nil)
		opened.Info = &sourceInfo{value: protocol.AuthenticatorGetInfoResponse{AAGUID: id}, cached: true}

		return opened, nil
	}, func(ctx context.Context, target attachment, opened *rtauthenticator.Opened) (vendorSources, error) {
		if target.path == "two" {
			return noSourceReader(ctx, target, opened)
		}

		close(entered)

		select {
		case <-release:
			return noSourceReader(ctx, target, opened)
		case <-ctx.Done():
			return vendorSources{}, ctx.Err()
		}
	})
	selected := manager.State().Selected
	attachmentID := manager.State().Snapshot.SelectedEndpoint
	done := make(chan reportReply, 1)

	go func() {
		value, err := manager.ReadEndpointSources(t.Context(), attachmentID)
		done <- reportReply{report: value, err: err}
	}()

	<-entered

	updated := watcher.snapshot.Candidates[0]
	updated.HID = new(*updated.HID)

	updated.HID.ProductStr.Value = new("Updated product")
	watcher.events <- devicewatch.Event{Type: devicewatch.EventUpdated, Candidate: updated}

	waitForDeviceManager(t, func() bool {
		return manager.State().Snapshot.Endpoints[0].Attachment.USB.Product.Value == "Updated product"
	})

	watcher.events <- devicewatch.Event{Type: devicewatch.EventConnected, Candidate: hidCandidate("two")}

	waitForDevices(t, manager, 2)

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	if err := manager.SelectEndpoint(ctx, attachmentID); err != nil {
		t.Fatal(err)
	}

	if selected.Closed() {
		t.Fatal("selecting current attachment canceled its read")
	}

	cache := &metadataCache{blob: &mds.Blob{Number: 1, CheckedAt: time.Now(), Entries: map[uuid.UUID]*mdsmodel.PayloadEntry{id: {AAGUID: id}}}}

	metadata, err := manager.RefreshMetadata(ctx, attachmentID, &mds.Client{Cache: cache}, mds.LookupOptions{})
	if err != nil || metadata.Sources.MDS.State != report.SourceAvailable {
		t.Fatalf("metadata blocked by local read: %v", err)
	}

	close(release)

	result := <-done
	if result.err != nil || result.report.Sources.MDS.Data == nil || result.report.Sources.MDS.Data.AAGUID != id {
		t.Fatalf("local result replaced concurrent metadata: %#v, %v", result.report.Sources.MDS, result.err)
	}

	if result.report.Attachment.USB.Product.Value != "Updated product" {
		t.Fatal("source result replaced newer USB observations")
	}

	if manager.State().Selected != selected {
		t.Fatal("report update replaced selected runtime")
	}
}

func TestSelectingTemporarySourceTargetWaitsForItsRelease(t *testing.T) {
	entered := make(chan struct{})
	temporaryClosed := make(chan struct{})
	opens := 0
	watcher := &fakeDeviceWatcher{snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{hidCandidate("a"), hidCandidate("b")}}, events: make(chan devicewatch.Event, 1)}
	manager := newTestDeviceManagerWithResolver(t, watcher, func(_ context.Context, _ transport.Mode, path string) (*rtauthenticator.Opened, error) {
		if path != "b" {
			return openedDevice(nil), nil
		}

		opens++
		if opens == 2 {
			return openedDevice(func() { close(temporaryClosed) }), nil
		}

		if opens == 3 {
			select {
			case <-temporaryClosed:
			default:
				t.Error("selection opened before temporary source handle closed")
			}
		}

		return openedDevice(nil), nil
	}, func(ctx context.Context, _ attachment, _ *rtauthenticator.Opened) (vendorSources, error) {
		close(entered)
		<-temporaryClosed

		return vendorSources{}, ctx.Err()
	})
	done := make(chan error, 1)

	go func() {
		_, err := manager.ReadEndpointSources(t.Context(), attachmentID(transport.ModeHID, "b"))
		done <- err
	}()

	<-entered

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	if err := manager.SelectEndpoint(ctx, attachmentID(transport.ModeHID, "b")); err != nil {
		t.Fatal(err)
	}

	if err := <-done; err == nil {
		t.Fatal("temporary read was not canceled")
	}

	if manager.State().Selected == nil || manager.State().Selected.Closed() {
		t.Fatal("replacement runtime unavailable")
	}
}

func TestSelectingPhysicalSiblingWaitsForSourceRelease(t *testing.T) {
	for _, physical := range []bool{false, true} {
		name := "endpoint"
		if physical {
			name = "physical-device"
		}

		t.Run(name, func(t *testing.T) {
			watcher := &fakeDeviceWatcher{
				snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{hidCandidate("hid-a"), hidCandidate("hid-b"), smartCardCandidate("reader-b", 1)}},
				events:   make(chan devicewatch.Event),
			}
			entered := make(chan struct{})
			temporaryClosed := make(chan struct{})

			var readerOpens, hidOpens atomic.Int32

			ctx, cancel := context.WithCancel(t.Context())
			manager := newDeviceManager(ctx, cancel, watcher, func(_ context.Context, _ transport.Mode, path string) (*rtauthenticator.Opened, error) {
				if path == "reader-b" && readerOpens.Add(1) == 2 {
					return openedDevice(func() { close(temporaryClosed) }), nil
				}

				if path == "hid-b" && hidOpens.Add(1) == 2 {
					select {
					case <-temporaryClosed:
					default:
						t.Error("replacement opened before its sibling's source handle closed")
					}
				}

				return openedDevice(nil), nil
			}, func(_ context.Context, target attachment, _ *rtauthenticator.Opened) (vendorSources, error) {
				return identitySources(report.DeviceIdentity{Vendor: report.VendorToken2, SerialNumber: target.path[len(target.path)-1:]}), nil
			}, nil)
			<-manager.ready
			t.Cleanup(func() { _ = manager.Close() })

			previous := manager.State().Selected
			manager.readSources = func(ctx context.Context, _ attachment, _ *rtauthenticator.Opened) (vendorSources, error) {
				close(entered)
				<-temporaryClosed

				return vendorSources{}, ctx.Err()
			}
			done := make(chan error, 1)

			go func() {
				_, err := manager.ReadEndpointSources(t.Context(), attachmentID(transport.ModeSmartCard, "reader-b"))
				done <- err
			}()

			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("sibling source read did not start")
			}

			selectCtx, stop := context.WithTimeout(t.Context(), time.Second)
			defer stop()

			var err error
			if physical {
				err = manager.Select(selectCtx, "token2:b")
			} else {
				err = manager.SelectEndpoint(selectCtx, attachmentID(transport.ModeHID, "hid-b"))
			}

			if err != nil {
				t.Fatal(err)
			}

			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("interrupted source read = %v, want cancellation", err)
				}
			case <-time.After(time.Second):
				t.Fatal("selection did not release the source read")
			}

			state := manager.State()
			if state.Snapshot.Selected != "token2:b" || state.Selected == nil || state.Selected.Closed() || !previous.Closed() {
				t.Fatalf("replacement selection = %#v", state.Snapshot)
			}

			if _, err := state.Selected.GetInfo(t.Context()); err != nil {
				t.Fatalf("replacement workflow: %v", err)
			}
		})
	}
}
