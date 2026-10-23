package ctapkit

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/telesma-app/ctap/protocol"
	rtauthenticator "github.com/telesma-app/kit/internal/authenticator"
	"github.com/telesma-app/kit/internal/devicewatch"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/report"
	"github.com/telesma-app/kit/transport"
	"github.com/telesma-app/mds"
	mdsmodel "github.com/telesma-app/mds/model"
)

type metadataRoundTrip func(*http.Request) (*http.Response, error)

func (f metadataRoundTrip) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type metadataCache struct {
	mu   sync.Mutex
	blob *mds.Blob
}

func (c *metadataCache) Get(string) (*mds.Blob, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.blob, c.blob != nil
}
func (c *metadataCache) Set(_ string, blob *mds.Blob) { c.mu.Lock(); c.blob = blob; c.mu.Unlock() }
func (c *metadataCache) Refresh(_ context.Context, _ string, fn func() (*mds.Blob, bool, error)) (*mds.Blob, bool, error) {
	return fn()
}

func metadataManager(t *testing.T, id uuid.UUID) *DeviceManager {
	return newTestDeviceManager(t, oneHIDWatcher(0xffff), func(context.Context, transport.Mode, string) (*rtauthenticator.Opened, error) {
		opened := openedDevice(nil)
		opened.Info = &sourceInfo{value: protocol.AuthenticatorGetInfoResponse{AAGUID: id}, cached: true}

		return opened, nil
	})
}

func TestMetadataReadsDoNotBlockRuntimeOrLoseRefreshFailures(t *testing.T) {
	aaguid := uuid.New()
	manager := metadataManager(t, aaguid)
	selected := manager.State().Selected
	id := manager.State().Snapshot.SelectedEndpoint
	checkedAt := time.Now().Add(-2 * time.Hour)
	cache := &metadataCache{blob: &mds.Blob{Number: 1, CheckedAt: checkedAt, Entries: map[uuid.UUID]*mdsmodel.PayloadEntry{aaguid: {AAGUID: aaguid}}}}
	entered := make(chan struct{})
	release := make(chan struct{})
	client := &mds.Client{
		Source: "https://metadata.invalid/", Cache: cache, CacheDir: t.TempDir(),
		HTTPClient: &http.Client{Transport: metadataRoundTrip(func(*http.Request) (*http.Response, error) {
			close(entered)
			<-release

			return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("unavailable"))}, nil
		})},
	}
	// Initial lookup uses the existing verified cache without a network request.
	cached, err := manager.RefreshMetadata(t.Context(), id, client, mds.LookupOptions{})
	if err != nil || cached.Sources.MDS.State != report.SourceAvailable {
		t.Fatalf("cached lookup: %#v, %v", cached.Sources.MDS, err)
	}

	result := make(chan reportReply, 1)

	go func() {
		value, err := manager.RefreshMetadata(t.Context(), id, client, mds.LookupOptions{Refresh: true})
		result <- reportReply{report: value, err: err}
	}()

	<-entered

	if manager.State().Snapshot.Endpoints[0].Sources.MDS.State != report.SourceLoading {
		t.Fatal("MDS loading was not published")
	}

	infoDone := make(chan error, 1)

	go func() { _, err := selected.GetInfo(t.Context()); infoDone <- err }()

	select {
	case err := <-infoDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("MDS network held workflow lock")
	}

	if err := manager.SelectEndpoint(t.Context(), id); err != nil {
		t.Fatal(err)
	}

	close(release)

	value := <-result

	source := value.report.Sources.MDS
	if value.err != nil || source.State != report.SourceFailed || source.Data == nil || !source.Data.Found {
		t.Fatalf("failed refresh = %#v, %v", source, value.err)
	}

	if source.Error.Code != failure.CodeMDSFetchFailed || source.Error.Params["httpStatus"] != "503" {
		t.Fatalf("MDS failure = %#v", source.Error)
	}

	if source.Data.CheckedAt != checkedAt {
		t.Fatalf("refresh provenance = %#v", source.Data)
	}

	raw, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Count(string(raw), `"error":`) != 1 || strings.Contains(string(raw), `"refresh"`) {
		t.Fatalf("metadata error must have one wire representation: %s", raw)
	}

	if manager.State().Selected != selected {
		t.Fatal("MDS enrichment changed selected instance")
	}

	throttled, err := manager.RefreshMetadata(t.Context(), id, client, mds.LookupOptions{Refresh: true})
	if err != nil || throttled.Sources.MDS.State != report.SourceFailed || throttled.Sources.MDS.Error.Code != failure.CodeMDSFetchFailed || throttled.Sources.MDS.Data.RefreshErr != source.Data.RefreshErr {
		t.Fatalf("throttled refresh = %#v, %v", throttled.Sources.MDS, err)
	}
}

func TestMetadataWithoutAAGUIDIsUnavailable(t *testing.T) {
	manager := metadataManager(t, uuid.Nil())
	client := &mds.Client{HTTPClient: &http.Client{Transport: metadataRoundTrip(func(*http.Request) (*http.Response, error) { t.Fatal("network without AAGUID"); return nil, nil })}}

	result, err := manager.RefreshMetadata(t.Context(), manager.State().Snapshot.SelectedEndpoint, client, mds.LookupOptions{})
	if err != nil || result.Sources.MDS.State != report.SourceUnavailable || result.Sources.MDS.Reason != report.ReasonAAGUIDMissing {
		t.Fatalf("MDS = %#v, %v", result.Sources.MDS, err)
	}
}

func TestMetadataResultDoesNotAttachToReconnectedEndpoint(t *testing.T) {
	manager := metadataManager(t, uuid.New())
	id := manager.State().Snapshot.SelectedEndpoint
	entered := make(chan struct{})
	release := make(chan struct{})
	client := &mds.Client{Cache: mds.NewCache(), CacheDir: t.TempDir(), HTTPClient: &http.Client{Transport: metadataRoundTrip(func(*http.Request) (*http.Response, error) {
		close(entered)
		<-release

		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}}
	result := make(chan error, 1)

	go func() { _, err := manager.RefreshMetadata(t.Context(), id, client, mds.LookupOptions{}); result <- err }()

	<-entered

	watcher := manager.watcher.(*fakeDeviceWatcher)

	candidate := watcher.snapshot.Candidates[0]
	watcher.events <- devicewatch.Event{Type: devicewatch.EventDisconnected, Candidate: candidate}

	waitForDevices(t, manager, 0)

	watcher.events <- devicewatch.Event{Type: devicewatch.EventConnected, Candidate: candidate}

	waitForDevices(t, manager, 1)
	close(release)

	if err := <-result; err == nil {
		t.Fatal("detached MDS request succeeded")
	}

	if manager.State().Snapshot.Endpoints[0].Sources.MDS.State != report.SourceNotRequested {
		t.Fatal("old MDS result attached to replacement")
	}
}

func TestMetadataCancellationPreservesRuntime(t *testing.T) {
	manager := metadataManager(t, uuid.New())
	selected := manager.State().Selected
	entered := make(chan struct{})
	client := &mds.Client{Cache: mds.NewCache(), CacheDir: t.TempDir(), HTTPClient: &http.Client{Transport: metadataRoundTrip(func(request *http.Request) (*http.Response, error) {
		close(entered)
		<-request.Context().Done()

		return nil, request.Context().Err()
	})}}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan reportReply, 1)

	go func() {
		value, err := manager.RefreshMetadata(ctx, manager.State().Snapshot.SelectedEndpoint, client, mds.LookupOptions{})
		done <- reportReply{report: value, err: err}
	}()

	<-entered
	cancel()

	result := <-done
	if result.err == nil || result.report.Sources.MDS.State != report.SourceFailed || manager.State().Selected != selected || selected.Closed() {
		t.Fatalf("cancellation = %#v, %v", result.report.Sources.MDS, result.err)
	}
}

func TestSupersededMetadataCancellationPreservesLatestResult(t *testing.T) {
	aaguid := uuid.New()
	manager := metadataManager(t, aaguid)
	selected := manager.State().Selected
	id := manager.State().Snapshot.SelectedEndpoint
	entered := make(chan struct{})
	cache := &metadataCache{blob: &mds.Blob{
		Number:    1,
		CheckedAt: time.Now().Add(-2 * time.Hour),
		Entries:   map[uuid.UUID]*mdsmodel.PayloadEntry{aaguid: {AAGUID: aaguid}},
	}}
	client := &mds.Client{
		Cache: cache,
		HTTPClient: &http.Client{Transport: metadataRoundTrip(func(request *http.Request) (*http.Response, error) {
			close(entered)
			<-request.Context().Done()

			return nil, request.Context().Err()
		})},
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	done := make(chan reportReply, 1)

	go func() {
		value, err := manager.RefreshMetadata(ctx, id, client, mds.LookupOptions{Refresh: true})
		done <- reportReply{report: value, err: err}
	}()

	<-entered

	latest, err := manager.RefreshMetadata(t.Context(), id, client, mds.LookupOptions{})
	if err != nil {
		t.Fatal(err)
	}

	cancel()

	result := <-done
	if !errors.Is(result.err, context.Canceled) {
		t.Fatalf("superseded refresh error = %v, want cancellation", result.err)
	}

	for _, source := range []report.MDSSource{result.report.Sources.MDS, manager.State().Snapshot.Endpoints[0].Sources.MDS} {
		if source.State != report.SourceAvailable || source.Error != nil || source.Data != latest.Sources.MDS.Data {
			t.Fatalf("superseded cancellation replaced the latest metadata: %#v", source)
		}
	}

	if manager.State().Selected != selected || selected.Closed() {
		t.Fatal("metadata cancellation replaced the selected runtime")
	}
}
