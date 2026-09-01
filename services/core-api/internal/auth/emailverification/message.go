package emailverification

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// DeliveryID identifies one outbox row. It is stable across every attempt, so a
// transport that supports an idempotency key has one that does not change.
type DeliveryID uuid.UUID

// NewDeliveryID draws an identifier from the package's CSPRNG-backed generator.
func NewDeliveryID() (DeliveryID, error) {
	value, err := uuid.NewRandom()
	if err != nil {
		return DeliveryID{}, fmt.Errorf("%w: no delivery identifier could be drawn", ErrInvalid)
	}
	return DeliveryID(value), nil
}

func (d DeliveryID) String() string { return uuid.UUID(d).String() }

func (d DeliveryID) IsZero() bool { return uuid.UUID(d) == uuid.Nil }

// Message is what a transport is asked to deliver. It redacts itself, so putting
// one in a record or an error discloses neither the address nor the link.
type Message struct {
	Delivery  DeliveryID
	To        iam.EmailAddress
	ExpiresAt time.Time
	// Link is the browser reference the recipient follows. It is built outside
	// this package: the authentication domain owns no web route.
	Link string
}

func (m Message) String() string { return iam.Redacted }

func (m Message) GoString() string { return iam.Redacted }

func (m Message) LogValue() slog.Value {
	return slog.GroupValue(slog.String("delivery_id", m.Delivery.String()))
}
