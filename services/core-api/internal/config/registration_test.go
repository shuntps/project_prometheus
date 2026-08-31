package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/config"
)

// TestAnUnnamedTransportLeavesRegistrationOff keeps the surface closed by
// default: only a transport that can carry a message turns it on, so a value
// nobody implemented, or none at all, mounts no route and starts no dispatcher.
func TestAnUnnamedTransportLeavesRegistrationOff(t *testing.T) {
	for name, transport := range map[string]config.EmailTransport{
		"unset":    "",
		"declared": config.EmailTransportNone,
	} {
		t.Run(name, func(t *testing.T) {
			settings := config.RegistrationSettings{Transport: transport}
			if settings.Enabled() {
				t.Fatal("a transport that carries nothing enabled the surface")
			}
			if err := settings.Validate(); err != nil {
				t.Fatalf("a disabled surface was refused: %v", err)
			}
		})
	}

	unknown := config.RegistrationSettings{Transport: config.EmailTransport("sendmail")}
	if unknown.Enabled() {
		t.Error("a transport nobody implemented enabled the surface")
	}
	if err := unknown.Validate(); err == nil {
		t.Error("a transport nobody implemented was accepted")
	}
}

func TestTheTransportIsRequiredExplicitlyAwayFromDevelopment(t *testing.T) {
	for _, env := range []string{"staging", "production"} {
		t.Run(env, func(t *testing.T) {
			_, err := config.Load(lookupFrom(withEnvWithout(env, "EMAIL_TRANSPORT")))
			if err == nil || !strings.Contains(err.Error(), "EMAIL_TRANSPORT is required") {
				t.Fatalf("got %v, want the transport demanded explicitly", err)
			}
		})
	}
}

// TestTheDevelopmentTransportIsRefusedAwayFromDevelopment keeps an adapter that
// negotiates no transport security and no authentication out of a deployment.
func TestTheDevelopmentTransportIsRefusedAwayFromDevelopment(t *testing.T) {
	for _, env := range []string{"staging", "production"} {
		t.Run(env, func(t *testing.T) {
			_, err := config.Load(lookupFrom(withEnv(env, map[string]string{
				"EMAIL_TRANSPORT": string(config.EmailTransportSMTPDevelopment),
			})))
			if err == nil || !strings.Contains(err.Error(), "development transport") {
				t.Fatalf("got %v, want the development transport refused", err)
			}
		})
	}
}

func TestTheRegistrationSettingsAreLoadedWhenTheTransportCarriesMessages(t *testing.T) {
	cfg, err := config.Load(lookupFrom(withEnv("development", map[string]string{
		"EMAIL_TRANSPORT":                    string(config.EmailTransportSMTPDevelopment),
		"EMAIL_SMTP_ADDRESS":                 "127.0.0.1:1025",
		"EMAIL_FROM_ADDRESS":                 "no-reply@example.invalid",
		"EMAIL_VERIFICATION_LIFETIME":        "8h",
		"EMAIL_VERIFICATION_RESEND_INTERVAL": "1m",
		"PUBLIC_ORIGIN":                      "https://app.example.com",
	})))
	if err != nil {
		t.Fatalf("a usable posture was refused: %v", err)
	}
	if !cfg.Registration.Enabled() {
		t.Fatal("a transport that carries messages left the surface off")
	}
	if cfg.Registration.Verification.Lifetime != 8*time.Hour {
		t.Errorf("lifetime = %s, want 8h", cfg.Registration.Verification.Lifetime)
	}
	// The delivery policy is operational only. Where the browser goes is the
	// browser boundary's to say, not this one's.
	if cfg.Registration.Delivery.Batch < 1 || cfg.Registration.Delivery.MaxAttempts < 1 {
		t.Errorf("delivery policy = %+v, want a usable batch and attempt limit", cfg.Registration.Delivery)
	}
	// A lease shorter than the call it protects would produce duplicates by
	// construction, so the default posture must not be one.
	if cfg.Registration.Delivery.Lease <= cfg.Registration.Delivery.SendTimeout {
		t.Errorf("lease %s does not outlast the send timeout %s",
			cfg.Registration.Delivery.Lease, cfg.Registration.Delivery.SendTimeout)
	}
}

// withEnvWithout removes one key from an otherwise complete environment.
func withEnvWithout(env, key string) map[string]string {
	values := withEnv(env, map[string]string{"EMAIL_TRANSPORT": string(config.EmailTransportNone)})
	delete(values, key)
	return values
}
