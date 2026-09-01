package config

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/emailverification"
	"github.com/shuntps/project_prometheus/services/core-api/internal/ratelimit"
)

// EmailTransport names how a verification message leaves the service. There is
// no implicit value: a deployment states which transport it runs, or states that
// public registration is off.
type EmailTransport string

const (
	// EmailTransportNone leaves public registration unmounted. Nothing accepts a
	// registration when no transport can carry its message.
	EmailTransportNone EmailTransport = "none"
	// EmailTransportSMTPDevelopment reaches a local mail collector. It negotiates
	// no transport security and no authentication, and is refused outside
	// development.
	EmailTransportSMTPDevelopment EmailTransport = "smtp_development"
)

// Development values sit at the floor the domain permits. They are not a
// deployment posture: staging and production set every value explicitly.
const (
	devVerificationLifetime       = 8 * time.Hour
	devVerificationResendInterval = time.Minute
	devRegistrationClientAttempts = int64(5)
	devRegistrationIdentityLimit  = int64(3)
	devRegistrationWindow         = time.Hour
	devRegistrationCapacity       = int64(65_536)
	devVerifyClientAttempts       = int64(20)
	devVerifyWindow               = 15 * time.Minute
	devVerifyCapacity             = int64(65_536)
	devDeliveryInterval           = 5 * time.Second
	devDeliveryBatch              = int64(16)
	devDeliveryMaxAttempts        = int64(5)
	devDeliveryLease              = 2 * time.Minute
	devDeliverySendTimeout        = 30 * time.Second
	devDeliveryBackoff            = 30 * time.Second
	// The address is synthetic: .invalid is reserved for names that are plainly
	// not resolvable, and no public name is adopted.
	devFromAddress = "no-reply@example.invalid"
	devSMTPAddress = "127.0.0.1:1025"
)

const (
	transportKey            = "EMAIL_TRANSPORT"
	smtpAddressKey          = "EMAIL_SMTP_ADDRESS"
	fromAddressKey          = "EMAIL_FROM_ADDRESS"
	verificationLifetimeKey = "EMAIL_VERIFICATION_LIFETIME"
	resendIntervalKey       = "EMAIL_VERIFICATION_RESEND_INTERVAL"
)

// RegistrationSettings is every value public registration and its delivery run
// on. It is inert when the transport is none.
type RegistrationSettings struct {
	Transport    EmailTransport
	SMTPAddress  string
	FromAddress  string
	Verification emailverification.Lifetimes
	RateLimit    ratelimit.AuthPolicy
	Verify       ratelimit.ClientPolicy
	Delivery     emailverification.DeliveryPolicy
}

// Enabled names the transports that can carry a message rather than excluding
// the one that cannot, so an unset value is off and a transport nobody
// implemented can never turn the surface on.
func (r RegistrationSettings) Enabled() bool {
	switch r.Transport {
	case EmailTransportSMTPDevelopment:
		return true
	default:
		return false
	}
}

func (r RegistrationSettings) domainChecks() []domainCheck {
	return []domainCheck{
		{[]string{verificationLifetimeKey, resendIntervalKey}, r.Verification.Validate},
		{[]string{"REGISTRATION_RATE_LIMIT_*"}, r.RateLimit.Validate},
		{[]string{"EMAIL_VERIFICATION_RATE_LIMIT_*"}, r.Verify.Validate},
		{[]string{"EMAIL_DELIVERY_*"}, r.Delivery.Validate},
	}
}

// Validate delegates every rule to the package that owns it. A disabled
// registration carries no values to judge; a transport nobody implemented is
// refused rather than treated as one.
func (r RegistrationSettings) Validate() error {
	switch r.Transport {
	case "", EmailTransportNone:
		return nil
	case EmailTransportSMTPDevelopment:
	default:
		return fmt.Errorf("%w: %s %q is not one of none, smtp_development", ErrInvalid, transportKey, r.Transport)
	}
	var problems []string
	for _, domain := range r.domainChecks() {
		if err := domain.check(); err != nil {
			problems = append(problems, err.Error())
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalid, strings.Join(problems, "; "))
	}
	return nil
}

// loadRegistration reads the registration settings. The transport is required
// explicitly outside development, and the values that govern the capability are
// demanded only when it is on.
func loadRegistration(lookup Lookup, env Environment) (RegistrationSettings, []string) {
	explicit := env == EnvStaging || env == EnvProduction

	raw, present := trimmed(lookup, transportKey)
	switch {
	case !present && explicit:
		return RegistrationSettings{}, []string{fmt.Sprintf("%s is required in staging and production", transportKey)}
	case !present:
		raw = string(EmailTransportNone)
	}
	transport := EmailTransport(strings.ToLower(raw))
	switch transport {
	case EmailTransportNone:
		return RegistrationSettings{Transport: EmailTransportNone}, nil
	case EmailTransportSMTPDevelopment:
		if env != EnvDevelopment {
			return RegistrationSettings{}, []string{fmt.Sprintf("%s %q is a development transport and is refused outside development", transportKey, raw)}
		}
	default:
		return RegistrationSettings{}, []string{fmt.Sprintf("%s %q is not one of none, smtp_development", transportKey, raw)}
	}

	settings := RegistrationSettings{Transport: transport}
	var problems []string

	counts := []struct {
		key string
		def int64
		min int64
		max int64
		out *int64
	}{
		{"REGISTRATION_RATE_LIMIT_CLIENT_ATTEMPTS", devRegistrationClientAttempts, ratelimit.MinAuthAttempts, ratelimit.MaxAuthAttempts, new(int64)},
		{"REGISTRATION_RATE_LIMIT_IDENTITY_ATTEMPTS", devRegistrationIdentityLimit, ratelimit.MinAuthAttempts, ratelimit.MaxAuthAttempts, new(int64)},
		{"REGISTRATION_RATE_LIMIT_CAPACITY", devRegistrationCapacity, ratelimit.MinAuthCapacity, ratelimit.MaxAuthCapacity, new(int64)},
		{"EMAIL_VERIFICATION_RATE_LIMIT_CLIENT_ATTEMPTS", devVerifyClientAttempts, ratelimit.MinAuthAttempts, ratelimit.MaxAuthAttempts, new(int64)},
		{"EMAIL_VERIFICATION_RATE_LIMIT_CAPACITY", devVerifyCapacity, ratelimit.MinAuthCapacity, ratelimit.MaxAuthCapacity, new(int64)},
		{"EMAIL_DELIVERY_BATCH", devDeliveryBatch, 1, math.MaxInt32, new(int64)},
		{"EMAIL_DELIVERY_MAX_ATTEMPTS", devDeliveryMaxAttempts, 1, math.MaxInt32, new(int64)},
	}
	for _, c := range counts {
		value, found := trimmed(lookup, c.key)
		switch {
		case found:
			var parsed int64
			if _, err := fmt.Sscanf(value, "%d", &parsed); err != nil || value != fmt.Sprintf("%d", parsed) {
				problems = append(problems, fmt.Sprintf("%s %q is not an integer", c.key, value))
				continue
			}
			if parsed < c.min || parsed > c.max {
				problems = append(problems, fmt.Sprintf("%s must be between %d and %d", c.key, c.min, c.max))
				continue
			}
			*c.out = parsed
		case explicit:
			problems = append(problems, fmt.Sprintf("%s is required in staging and production", c.key))
		default:
			*c.out = c.def
		}
	}

	durations := []struct {
		key string
		def time.Duration
		out *time.Duration
	}{
		{verificationLifetimeKey, devVerificationLifetime, new(time.Duration)},
		{resendIntervalKey, devVerificationResendInterval, new(time.Duration)},
		{"REGISTRATION_RATE_LIMIT_WINDOW", devRegistrationWindow, new(time.Duration)},
		{"EMAIL_VERIFICATION_RATE_LIMIT_WINDOW", devVerifyWindow, new(time.Duration)},
		{"EMAIL_DELIVERY_INTERVAL", devDeliveryInterval, new(time.Duration)},
		{"EMAIL_DELIVERY_LEASE", devDeliveryLease, new(time.Duration)},
		{"EMAIL_DELIVERY_SEND_TIMEOUT", devDeliverySendTimeout, new(time.Duration)},
		{"EMAIL_DELIVERY_BACKOFF", devDeliveryBackoff, new(time.Duration)},
	}
	for _, d := range durations {
		if _, found := trimmed(lookup, d.key); !found && explicit {
			problems = append(problems, fmt.Sprintf("%s is required in staging and production", d.key))
			continue
		}
		value, err := durationValue(lookup, d.key, d.def)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		*d.out = value
	}

	settings.FromAddress = requiredText(lookup, fromAddressKey, devFromAddress, explicit, &problems)
	if transport == EmailTransportSMTPDevelopment {
		settings.SMTPAddress = requiredText(lookup, smtpAddressKey, devSMTPAddress, explicit, &problems)
	}
	if len(problems) > 0 {
		return RegistrationSettings{}, problems
	}

	settings.Verification = emailverification.Lifetimes{
		Lifetime:       *durations[0].out,
		ResendInterval: *durations[1].out,
	}
	settings.RateLimit = ratelimit.AuthPolicy{
		ClientAttempts:   int(*counts[0].out),
		IdentityAttempts: int(*counts[1].out),
		Window:           *durations[2].out,
		Capacity:         int(*counts[2].out),
	}
	settings.Verify = ratelimit.ClientPolicy{
		Attempts: int(*counts[3].out),
		Window:   *durations[3].out,
		Capacity: int(*counts[4].out),
	}
	settings.Delivery = emailverification.DeliveryPolicy{
		Interval:    *durations[4].out,
		Batch:       int(*counts[5].out),
		MaxAttempts: int(*counts[6].out),
		Lease:       *durations[5].out,
		SendTimeout: *durations[6].out,
		Backoff:     *durations[7].out,
	}

	for _, domain := range settings.domainChecks() {
		if err := domain.check(); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", strings.Join(domain.keys, ", "), err))
		}
	}
	if len(problems) > 0 {
		return RegistrationSettings{}, problems
	}
	return settings, nil
}

func requiredText(lookup Lookup, key, fallback string, explicit bool, problems *[]string) string {
	value, found := trimmed(lookup, key)
	switch {
	case found:
		return value
	case explicit:
		*problems = append(*problems, fmt.Sprintf("%s is required in staging and production", key))
		return ""
	default:
		return fallback
	}
}
