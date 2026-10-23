package ctapkit

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	ctapdevice "github.com/telesma-app/ctap/authenticator"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	rtauthenticator "github.com/telesma-app/kit/internal/authenticator"
	"github.com/telesma-app/kit/internal/devicewatch"
	"github.com/telesma-app/kit/model"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/report"
	"github.com/telesma-app/kit/transport"
	"github.com/telesma-app/pcsc"
)

func TestSmartCardSeriesSelectsOnceAndManagementDoesNotRestoreFIDO(t *testing.T) {
	card := &borrowedCard{}
	owner := &rtauthenticator.SmartCard{Card: card}

	t.Cleanup(func() { _ = owner.Close() })

	for _, command := range []protocol.Command{protocol.AuthenticatorGetAssertion, protocol.AuthenticatorGetNextAssertion} {
		if _, err := owner.CBOR(t.Context(), []byte{byte(command)}); err != nil {
			t.Fatal(err)
		}
	}

	sources, err := readSmartCardSources(t.Context(), newAttachment(smartCardCandidate("reader", 1)), &rtauthenticator.Opened{Card: owner})
	if err != nil || sources.yubico.Data == nil {
		t.Fatalf("management = %#v, %v", sources, err)
	}

	want := []string{"begin", "select-fido", "ctap:02", "ctap:08", "end-fido", "end", "begin"}
	if !slices.Equal(card.events[:len(want)], want) || card.active || countCardEvent(card, "select-fido") != 1 {
		t.Fatalf("FIDO to management = %v", card.events)
	}

	if _, err := owner.CBOR(t.Context(), []byte{byte(protocol.AuthenticatorGetInfo)}); err != nil {
		t.Fatal(err)
	}

	if err := owner.EndFIDO(t.Context()); err != nil {
		t.Fatal(err)
	}

	if countCardEvent(card, "select-fido") != 2 || card.active || card.closes != 0 {
		t.Fatalf("new FIDO series = %v, closes = %d", card.events, card.closes)
	}
}

func TestSmartCardInitializationFailureKeepsManagementAvailable(t *testing.T) {
	for _, name := range []string{"select", "get-info"} {
		t.Run(name, func(t *testing.T) {
			card := &borrowedCard{}
			if name == "select" {
				card.selectStatus = 0x6a
			} else {
				card.ctapStatus = byte(ctaptransport.CTAP1_ERR_INVALID_COMMAND)
			}

			owner := &rtauthenticator.SmartCard{Card: card}

			t.Cleanup(func() { _ = owner.Close() })

			_, err := ctapdevice.New(t.Context(), owner)
			if err == nil {
				t.Fatal("initialization succeeded")
			}

			if err := owner.EndFIDO(t.Context()); err != nil {
				t.Fatal(err)
			}

			sources, err := readSmartCardSources(t.Context(), newAttachment(smartCardCandidate("reader", 1)), &rtauthenticator.Opened{Card: owner})
			if err != nil || sources.yubico.Data == nil || card.closes != 0 || card.active {
				t.Fatalf("management after failed init = %#v, %v, closes = %d", sources, err, card.closes)
			}
		})
	}
}

func TestSmartCardReportSeparatesFIDOSelectionFromGetInfoFailure(t *testing.T) {
	for _, selectFails := range []bool{false, true} {
		name := "get-info"
		if selectFails {
			name = "select"
		}

		t.Run(name, func(t *testing.T) {
			card := &borrowedCard{ctapStatus: byte(ctaptransport.CTAP1_ERR_INVALID_COMMAND)}
			if selectFails {
				card.selectStatus = 0x6a
			}

			owner := &rtauthenticator.SmartCard{Card: card, Interface: pcsc.CardInterfaceContactless}

			t.Cleanup(func() { _ = owner.Close() })

			_, err := ctapdevice.New(t.Context(), owner)
			if err == nil {
				t.Fatal("initialization unexpectedly succeeded")
			}

			if cleanupErr := owner.EndFIDO(t.Context()); cleanupErr != nil {
				t.Fatal(cleanupErr)
			}

			target := newAttachment(smartCardCandidate("reader", 1))
			observeOpen(&target, &rtauthenticator.Opened{Lifecycle: owner, Card: owner}, err)

			want := report.SourceAvailable
			if selectFails {
				want = report.SourceAbsent
			}

			if got := target.report.Attachment.SmartCard; got.Interface != transport.SmartCardInterfaceContactless || got.FIDOApplication.State != want {
				t.Fatalf("card observations = %#v", got)
			}

			wantInfo := report.SourceUnsupported
			if selectFails {
				wantInfo = report.SourceAbsent
			}

			if target.report.Sources.GetInfo.State != wantInfo {
				t.Fatalf("GetInfo outcome = %#v", target.report.Sources.GetInfo.Outcome)
			}
		})
	}
}

func TestSmartCardFailedSessionEndInvalidatesAndClosesOnce(t *testing.T) {
	card := &borrowedCard{endStatus: 0x6d}

	owner := &rtauthenticator.SmartCard{Card: card}
	if _, err := owner.CBOR(t.Context(), []byte{byte(protocol.AuthenticatorGetInfo)}); err != nil {
		t.Fatal(err)
	}

	if _, invalid := errors.AsType[*ctaptransport.DeviceInvalidatedError](owner.EndFIDO(t.Context())); !invalid {
		t.Fatal("failed END did not invalidate the connection")
	}

	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}

	if card.closes != 1 {
		t.Fatalf("physical closes = %d", card.closes)
	}
}

func TestSmartCardCommandAndCleanupFailuresRemainObservable(t *testing.T) {
	cleanupErr := errors.New("transaction cleanup failed")
	card := &borrowedCard{ctapStatus: byte(ctaptransport.CTAP2_ERR_PIN_INVALID), endErr: cleanupErr}
	owner := &rtauthenticator.SmartCard{Card: card}
	device := &smartCardRejectedInfo{card: owner}
	opened := contractOpened(device)
	opened.Card, opened.Lifecycle = owner, owner
	selected := newAuthenticatorHandle(newContractDevice().report, opened)

	t.Cleanup(func() { _ = selected.Close() })

	result, err := selected.GetInfo(t.Context())
	if !failure.IsCode(err, failure.CodePINInvalid) || !errors.Is(err, cleanupErr) {
		t.Fatalf("GetInfo error = %v, want command and cleanup failures", err)
	}

	requireZero(t, result)

	if _, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err); !invalidated {
		t.Fatalf("GetInfo error lost transport invalidation: %v", err)
	}

	ctapErr, ok := errors.AsType[*ctaptransport.CTAPError](err)
	if !ok || ctapErr.Command != protocol.AuthenticatorGetInfo || ctapErr.StatusCode != ctaptransport.CTAP2_ERR_PIN_INVALID {
		t.Fatalf("command error = %#v", ctapErr)
	}

	if !selected.Closed() || card.closes != 1 {
		t.Fatalf("closed = %v, physical closes = %d", selected.Closed(), card.closes)
	}
}

type smartCardRejectedInfo struct {
	contractAuthenticator
	card *rtauthenticator.SmartCard
}

func (d *smartCardRejectedInfo) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return protocol.AuthenticatorGetInfoResponse{}, false
}

func (d *smartCardRejectedInfo) GetInfo(ctx context.Context) (protocol.AuthenticatorGetInfoResponse, error) {
	response, err := d.card.CBOR(ctx, []byte{byte(protocol.AuthenticatorGetInfo)})
	if err != nil {
		return protocol.AuthenticatorGetInfoResponse{}, err
	}

	_, err = ctaptransport.ValidateCBORResponse(protocol.AuthenticatorGetInfo, response)

	return protocol.AuthenticatorGetInfoResponse{}, err
}

type smartCardPINDevice struct {
	contractAuthenticator
	card *rtauthenticator.SmartCard
}

func (d *smartCardPINDevice) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return protocol.AuthenticatorGetInfoResponse{Options: map[protocol.Option]bool{
		protocol.OptionCredentialManagement: true,
		protocol.OptionClientPIN:            true,
		protocol.OptionPinUvAuthToken:       true,
	}}, true
}

func (d *smartCardPINDevice) GetPINRetries(ctx context.Context) (uint, *bool, error) {
	_, err := d.card.CBOR(ctx, []byte{byte(protocol.AuthenticatorClientPIN)})
	return 8, nil, err
}

func (d *smartCardPINDevice) GetPinUvAuthTokenUsingPIN(ctx context.Context, _ string, _ protocol.Permission, _ string) ([]byte, error) {
	_, err := d.card.CBOR(ctx, []byte{byte(protocol.AuthenticatorClientPIN)})
	return []byte("test-token"), err
}

func (d *smartCardPINDevice) GetCredsMetadata(ctx context.Context, _ []byte) (protocol.AuthenticatorCredentialManagementResponse, error) {
	_, err := d.card.CBOR(ctx, []byte{byte(protocol.AuthenticatorCredentialManagement)})

	return protocol.AuthenticatorCredentialManagementResponse{
		ExistingResidentCredentialsCount:             new(uint(0)),
		MaxPossibleRemainingResidentCredentialsCount: new(uint(8)),
	}, err
}

func TestSmartCardPINPromptReleasesTransactionAndKeepsRuntimeAndToken(t *testing.T) {
	card := &borrowedCard{}
	owner := &rtauthenticator.SmartCard{Card: card}
	device := &smartCardPINDevice{card: owner}
	watcher := &fakeDeviceWatcher{snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{smartCardCandidate("reader", 1)}}, events: make(chan devicewatch.Event)}
	manager := newTestDeviceManagerWithResolver(t, watcher, func(context.Context, transport.Mode, string) (*rtauthenticator.Opened, error) {
		opened := contractOpened(device)
		opened.Card, opened.Lifecycle = owner, owner

		return opened, nil
	}, readVendorSources)
	selected := manager.State().Selected
	prompts := 0

	handler := interactionHandlerFunc(func(request model.InteractionRequest) (model.InteractionResponse, error) {
		prompts++

		if request.Kind != model.InteractionKindPIN || card.active || card.events[len(card.events)-1] != "end" {
			t.Fatalf("PIN prompt while transaction active: %v", card.events)
		}

		return model.InteractionResponse{PIN: []byte("1234")}, nil
	})
	for attempt := range 2 {
		if _, err := selected.ListCredentials(t.Context(), WithInteractionHandler(handler)); err != nil {
			t.Fatal(err)
		}

		if card.active {
			t.Fatal("workflow retained native transaction")
		}

		if attempt == 0 {
			if _, err := manager.ReadEndpointSources(t.Context(), manager.State().Snapshot.SelectedEndpoint); err != nil {
				t.Fatal(err)
			}
		}
	}

	if prompts != 1 || countCardEvent(card, "select-fido") != 3 || manager.State().Selected != selected || selected.opened.Info != device || card.closes != 0 {
		t.Fatalf("runtime/cache changed: prompts = %d, events = %v, closes = %d", prompts, card.events, card.closes)
	}
}

func countCardEvent(card *borrowedCard, event string) int {
	count := 0

	for _, actual := range card.events {
		if actual == event {
			count++
		}
	}

	return count
}

type blockingSmartCard struct {
	borrowedCard
	started      chan struct{}
	closed       chan struct{}
	closes       atomic.Int32
	waitForClose bool
	polling      bool
}

func (c *blockingSmartCard) Transmit(ctx context.Context, command []byte) ([]byte, error) {
	if c.polling && command[1] == 0x11 {
		if command[2] == 0x11 {
			return []byte{byte(ctaptransport.CTAP2_ERR_KEEPALIVE_CANCEL), 0x90, 0x00}, nil
		}

		<-ctx.Done()

		return nil, ctx.Err()
	}

	if command[1] != 0x10 {
		return c.borrowedCard.Transmit(ctx, command)
	}

	close(c.started)

	if c.polling {
		return []byte{0x02, 0x91, 0x00}, nil
	}

	if c.waitForClose {
		<-c.closed
		return nil, errors.New("card closed")
	}

	<-ctx.Done()

	return nil, ctx.Err()
}

func (c *blockingSmartCard) Close() error {
	c.closes.Add(1)
	close(c.closed)

	return nil
}

type smartCardBlockingInfo struct {
	contractAuthenticator
	card   *rtauthenticator.SmartCard
	cached atomic.Bool
}

func (d *smartCardBlockingInfo) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return protocol.AuthenticatorGetInfoResponse{}, d.cached.Load()
}

func (d *smartCardBlockingInfo) GetInfo(ctx context.Context) (protocol.AuthenticatorGetInfoResponse, error) {
	_, err := d.card.CBOR(ctx, []byte{byte(protocol.AuthenticatorGetInfo)})
	return protocol.AuthenticatorGetInfoResponse{}, err
}

func TestSmartCardCancellationReleasesTransactionWithoutClosingRuntime(t *testing.T) {
	card := &blockingSmartCard{started: make(chan struct{}), closed: make(chan struct{}), polling: true}
	owner := &rtauthenticator.SmartCard{Card: card}
	device := &smartCardBlockingInfo{card: owner}
	opened := contractOpened(device)
	opened.Card, opened.Lifecycle = owner, owner
	selected := newAuthenticatorHandle(newContractDevice().report, opened)

	t.Cleanup(func() { _ = selected.Close() })
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)

	go func() { _, err := selected.GetInfo(ctx); done <- err }()

	<-card.started
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled GetInfo = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not finish the FIDO series")
	}

	if card.active || card.closes.Load() != 0 || selected.Closed() || !slices.Contains(card.events, "end-fido") {
		t.Fatalf("cancellation state: active = %v, closes = %d, events = %v", card.active, card.closes.Load(), card.events)
	}
}

func TestSmartCardManagerShutdownUnblocksWorkflowAndQueuedSources(t *testing.T) {
	for _, waitForClose := range []bool{false, true} {
		name := "context-cancellation"
		if waitForClose {
			name = "physical-close"
		}

		t.Run(name, func(t *testing.T) {
			card := &blockingSmartCard{started: make(chan struct{}), closed: make(chan struct{}), waitForClose: waitForClose}
			owner := &rtauthenticator.SmartCard{Card: card}
			device := &smartCardBlockingInfo{card: owner}
			device.cached.Store(true)

			watcher := &fakeDeviceWatcher{snapshot: devicewatch.Snapshot{Candidates: []devicewatch.Candidate{smartCardCandidate("reader", 1)}}, events: make(chan devicewatch.Event)}
			manager := newTestDeviceManagerWithResolver(t, watcher, func(context.Context, transport.Mode, string) (*rtauthenticator.Opened, error) {
				opened := contractOpened(device)
				opened.Card, opened.Lifecycle = owner, owner

				return opened, nil
			}, readVendorSources)

			device.cached.Store(false)

			selected := manager.State().Selected
			workflowDone := make(chan error, 1)

			go func() { _, err := selected.GetInfo(t.Context()); workflowDone <- err }()

			<-card.started

			sourcesDone := make(chan error, 1)

			go func() {
				_, err := manager.ReadEndpointSources(t.Context(), manager.State().Snapshot.SelectedEndpoint)
				sourcesDone <- err
			}()

			waitForDeviceManager(t, func() bool { return manager.State().Snapshot.Endpoints[0].Sources.Yubico.State == report.SourceLoading })

			closeDone := make(chan error, 2)

			for range 2 {
				go func() { closeDone <- manager.Close() }()
			}

			for range 2 {
				select {
				case err := <-closeDone:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("shutdown waited for the operation gate before closing the card")
				}
			}

			if err := <-workflowDone; err == nil {
				t.Fatal("blocked workflow succeeded")
			}

			if err := <-sourcesDone; err == nil {
				t.Fatal("queued source read succeeded")
			}

			if card.closes.Load() != 1 || manager.State().Selected != nil {
				t.Fatalf("physical closes = %d, selected = %p", card.closes.Load(), manager.State().Selected)
			}
		})
	}
}

func TestSmartCardInterruptedTransmitInvalidatesRuntime(t *testing.T) {
	card := &blockingSmartCard{started: make(chan struct{}), closed: make(chan struct{})}
	owner := &rtauthenticator.SmartCard{Card: card}
	device := &smartCardBlockingInfo{card: owner}
	opened := contractOpened(device)
	opened.Card, opened.Lifecycle = owner, owner
	selected := newAuthenticatorHandle(newContractDevice().report, opened)

	t.Cleanup(func() { _ = selected.Close() })

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	done := make(chan error, 1)

	go func() { _, err := selected.GetInfo(ctx); done <- err }()

	<-card.started
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled GetInfo = %v", err)
		}

		if _, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err); !invalidated {
			t.Fatalf("canceled transmit did not invalidate the connection: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled transmit did not return")
	}

	if card.closes.Load() != 1 || !selected.Closed() || slices.Contains(card.events, "end-fido") {
		t.Fatalf("cancellation state: closes = %d, closed = %v, events = %v", card.closes.Load(), selected.Closed(), card.events)
	}
}
