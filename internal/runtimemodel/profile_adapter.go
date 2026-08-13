package runtimemodel

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ProfileAdapterConfig declares the complete finite profile-to-provider map
// installed in one model-role process. It deliberately accepts Adapter values
// only at process composition: Agent revisions can select a declared profile,
// but cannot choose an endpoint, credential source, or provider implementation.
type ProfileAdapterConfig struct {
	Profiles []ProviderProfile
}

// ProviderProfile associates one public Agent model profile with one private
// provider adapter. Provider is diagnostic-only safe metadata; it must never
// be an endpoint, account identifier, or credential reference.
type ProviderProfile struct {
	Profile  string
	Provider string
	Adapter  Adapter
}

// ProfileAdapter is the concrete model-selection boundary. It selects before
// both Invoke and Reconcile, so a recovery cannot silently move an operation
// to a different provider because deployment configuration changed.
type ProfileAdapter struct {
	profiles map[string]ProviderProfile
}

// NewProfileAdapter constructs a strict model-role-only profile catalog.
func NewProfileAdapter(config ProfileAdapterConfig) (*ProfileAdapter, error) {
	if len(config.Profiles) == 0 || len(config.Profiles) > 64 {
		return nil, errors.New("create model profile adapter: one to 64 profiles are required")
	}
	profiles := make(map[string]ProviderProfile, len(config.Profiles))
	for _, profile := range config.Profiles {
		if !validProfileName(profile.Profile) {
			return nil, errors.New("create model profile adapter: profile name is invalid")
		}
		if !validProviderName(profile.Provider) {
			return nil, errors.New("create model profile adapter: provider name is invalid")
		}
		if profile.Adapter == nil {
			return nil, errors.New("create model profile adapter: provider adapter is required")
		}
		if _, exists := profiles[profile.Profile]; exists {
			return nil, errors.New("create model profile adapter: duplicate profile")
		}
		profiles[profile.Profile] = profile
	}
	return &ProfileAdapter{profiles: profiles}, nil
}

// Profiles returns the configured public profile names in stable order. It
// intentionally does not expose adapter configuration or credentials.
func (adapter *ProfileAdapter) Profiles() []string {
	if adapter == nil {
		return nil
	}
	profiles := make([]string, 0, len(adapter.profiles))
	for profile := range adapter.profiles {
		profiles = append(profiles, profile)
	}
	sort.Strings(profiles)
	return profiles
}

// Invoke selects exactly the revision-pinned profile, then delegates one new
// provider effect. An unknown profile is rejected before any adapter call.
func (adapter *ProfileAdapter) Invoke(ctx context.Context, request Request) (Response, error) {
	selected, err := adapter.selectProfile(request.ModelProfile)
	if err != nil {
		return Response{}, err
	}
	return selected.Adapter.Invoke(ctx, request)
}

// Reconcile selects exactly the same revision-pinned profile before querying
// the provider's durable operation identity. It never falls back to Invoke.
func (adapter *ProfileAdapter) Reconcile(ctx context.Context, request Request) (Response, error) {
	selected, err := adapter.selectProfile(request.ModelProfile)
	if err != nil {
		return Response{}, err
	}
	return selected.Adapter.Reconcile(ctx, request)
}

func (adapter *ProfileAdapter) selectProfile(profile string) (ProviderProfile, error) {
	if adapter == nil {
		return ProviderProfile{}, errors.New("select model profile: adapter is not configured")
	}
	selected, found := adapter.profiles[profile]
	if !found {
		return ProviderProfile{}, fmt.Errorf("select model profile: declared profile %q is unavailable", safeProfileForError(profile))
	}
	return selected, nil
}

func validProfileName(value string) bool {
	return validModelIdentifier(value, 64)
}

func validProviderName(value string) bool {
	return validModelIdentifier(value, 64)
}

func validModelIdentifier(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' || character == '_' {
			if index == 0 && (character == '-' || character == '_') {
				return false
			}
			continue
		}
		return false
	}
	return true
}

func safeProfileForError(profile string) string {
	if validProfileName(profile) {
		return profile
	}
	return "invalid"
}
