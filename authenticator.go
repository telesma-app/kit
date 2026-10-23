package ctapkit

import (
	"context"
	"sync"

	"github.com/telesma-app/kit/internal/authenticator"
	"github.com/telesma-app/kit/internal/logging"
	rtruntime "github.com/telesma-app/kit/internal/runtime"
	"github.com/telesma-app/kit/internal/workflow"
	"github.com/telesma-app/kit/model"
	"github.com/telesma-app/kit/model/failure"
	"github.com/telesma-app/kit/model/report"
	"github.com/telesma-app/kit/transport"
)

type authenticatorOpenFunc func(context.Context, transport.Mode, string) (*authenticator.Opened, error)

type AuthenticatorOption func(*authenticatorConfig)

type authenticatorConfig struct {
	journal *LogJournal
}

type OperationOption func(*operationConfig)

// EventSink receives progress events from one operation.
type EventSink interface {
	Emit(context.Context, model.OperationEvent)
}

// InteractionHandler answers user-interaction requests from one operation.
type InteractionHandler interface {
	RequestInteraction(context.Context, model.InteractionRequest) (model.InteractionResponse, error)
}

// VerificationFlow selects the preferred PIN or user-verification flow.
type VerificationFlow string

const (
	// VerificationFlowDefault prefers built-in user verification with PIN fallback.
	VerificationFlowDefault VerificationFlow = ""
	// VerificationFlowPIN requests PIN verification first.
	VerificationFlowPIN VerificationFlow = "pin"
)

type operationConfig struct {
	verificationFlow VerificationFlow
	events           EventSink
	handler          InteractionHandler
}

func WithEventSink(events EventSink) OperationOption {
	return func(config *operationConfig) {
		config.events = events
	}
}

func WithInteractionHandler(handler InteractionHandler) OperationOption {
	return func(config *operationConfig) {
		config.handler = handler
	}
}

func WithLogJournal(journal *LogJournal) AuthenticatorOption {
	return func(config *authenticatorConfig) {
		config.journal = journal
	}
}

func WithVerificationFlow(flow VerificationFlow) OperationOption {
	return func(config *operationConfig) {
		config.verificationFlow = flow
	}
}

// Authenticator is one opened authenticator channel. It owns transport
// lifecycle, operation serialization, and runtime token state until Close.
type Authenticator struct {
	selected       report.EndpointReport
	opened         *authenticator.Opened
	tokens         rtruntime.TokenStore
	largeBlobState workflow.LargeBlobState

	runGate chan struct{}
	stateMu sync.Mutex
	closed  bool
	cancel  context.CancelFunc

	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func newAuthenticatorHandle(selected report.EndpointReport, opened *authenticator.Opened) *Authenticator {
	return &Authenticator{
		selected: selected,
		opened:   opened,
		runGate:  make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
}

func (a *Authenticator) Close() error {
	a.stateMu.Lock()
	a.closed = true

	if a.cancel != nil {
		a.cancel()
	}
	a.stateMu.Unlock()

	a.closeOnce.Do(func() {
		defer close(a.done)
		// Close first: a blocked device read may ignore context cancellation.
		a.closeErr = a.opened.Lifecycle.Close()

		a.runGate <- struct{}{}
		defer func() { <-a.runGate }()

		a.tokens.InvalidateToken()
		a.largeBlobState.Clear()
	})

	if a.closeErr != nil {
		return NormalizeError(a.closeErr, failure.PhaseCleanup)
	}

	return nil
}

func (a *Authenticator) Endpoint() report.EndpointReport {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()

	return a.selected
}

func (a *Authenticator) Closed() bool {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()

	return a.closed
}

func (a *Authenticator) start(cancel context.CancelFunc) error {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()

	if a.closed {
		return failure.New(failure.CodeAuthenticatorClosed,
			failure.WithPhase(failure.PhaseAuthenticator),
		)
	}

	a.cancel = cancel

	return nil
}

func (a *Authenticator) finish() {
	a.stateMu.Lock()
	a.cancel = nil
	a.stateMu.Unlock()
}

func newOperationConfig(opts ...OperationOption) (operationConfig, error) {
	var config operationConfig
	for _, opt := range opts {
		opt(&config)
	}

	switch config.verificationFlow {
	case VerificationFlowDefault, VerificationFlowPIN:
		return config, nil
	default:
		return operationConfig{}, failure.New(failure.CodeVerificationFlowUnsupported,
			failure.WithPhase(failure.PhaseValidation),
		)
	}
}

func (a *Authenticator) setEndpoint(device report.EndpointReport) {
	a.stateMu.Lock()
	a.selected = device
	a.stateMu.Unlock()
}

func openDevice(ctx context.Context, target attachment, open authenticatorOpenFunc, opts ...AuthenticatorOption) (*authenticator.Opened, error) {
	var config authenticatorConfig
	for _, opt := range opts {
		opt(&config)
	}

	var recorder logging.Recorder
	if config.journal != nil {
		recorder = config.journal.journal
	}

	return open(logging.WithRecorder(ctx, recorder), target.mode, target.path)
}
