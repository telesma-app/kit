package authenticator

import (
	"context"
	"errors"
	"testing"

	"github.com/telesma-app/ctap/protocol"
)

func TestResolveInfoUsesValidCachedResponse(t *testing.T) {
	provider := &infoProviderStub{
		cached: protocol.AuthenticatorGetInfoResponse{Versions: protocol.Versions{protocol.FIDO_2_1}},
		valid:  true,
	}

	info, err := ResolveInfo(t.Context(), provider)
	if err != nil {
		t.Fatalf("ResolveInfo: %v", err)
	}

	if !info.Versions.Supports(protocol.FIDO_2_1) {
		t.Fatalf("versions = %v, want FIDO_2_1", info.Versions)
	}

	if provider.freshCalls != 0 {
		t.Fatalf("fresh GetInfo calls = %d, want 0", provider.freshCalls)
	}
}

func TestResolveInfoRefreshesInvalidCacheOnce(t *testing.T) {
	provider := &infoProviderStub{
		cached:  protocol.AuthenticatorGetInfoResponse{Versions: protocol.Versions{protocol.FIDO_2_1}},
		current: protocol.AuthenticatorGetInfoResponse{Versions: protocol.Versions{protocol.FIDO_2_3}},
	}

	for range 2 {
		info, err := ResolveInfo(t.Context(), provider)
		if err != nil {
			t.Fatalf("ResolveInfo: %v", err)
		}

		if !info.Versions.Supports(protocol.FIDO_2_3) {
			t.Fatalf("versions = %v, want FIDO_2_3", info.Versions)
		}
	}

	if provider.freshCalls != 1 {
		t.Fatalf("fresh GetInfo calls = %d, want 1", provider.freshCalls)
	}
}

func TestResolveInfoReturnsRefreshFailure(t *testing.T) {
	want := errors.New("getInfo failed")
	provider := &infoProviderStub{
		current:  protocol.AuthenticatorGetInfoResponse{Versions: protocol.Versions{protocol.FIDO_2_3}},
		freshErr: want,
	}

	info, err := ResolveInfo(t.Context(), provider)
	if !errors.Is(err, want) {
		t.Fatalf("ResolveInfo error = %v, want %v", err, want)
	}

	if len(info.Versions) != 0 {
		t.Fatalf("ResolveInfo response = %#v, want zero value", info)
	}
}

type infoProviderStub struct {
	cached     protocol.AuthenticatorGetInfoResponse
	current    protocol.AuthenticatorGetInfoResponse
	valid      bool
	freshErr   error
	freshCalls int
}

func (p *infoProviderStub) GetInfoCached() (protocol.AuthenticatorGetInfoResponse, bool) {
	return p.cached, p.valid
}

func (p *infoProviderStub) GetInfo(context.Context) (protocol.AuthenticatorGetInfoResponse, error) {
	p.freshCalls++
	if p.freshErr != nil {
		return p.current, p.freshErr
	}

	p.cached = p.current
	p.valid = true

	return p.current, nil
}
