// Package smtp carries verification messages to a local mail collector. The
// standard library client it builds on is frozen, and this adapter negotiates no
// transport security and no authentication: it is never a production path.
package smtp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/emailverification"
)

// ErrDelivery reports that a message was not accepted. It names the stage that
// failed and nothing the server said, so no address can travel inside it.
var ErrDelivery = errors.New("the message was not accepted by the transport")

// Sender is one collector endpoint and the identity messages are sent under.
type Sender struct {
	address string
	from    string
	host    string
}

// New refuses an endpoint or an identity it could not use, rather than failing
// on the first message.
func New(address, from string) (*Sender, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil || host == "" || port == "" {
		return nil, errors.New("the mail transport requires a host and port")
	}
	parsed, err := mail.ParseAddress(strings.TrimSpace(from))
	if err != nil {
		return nil, errors.New("the mail transport requires a usable sender address")
	}
	return &Sender{address: net.JoinHostPort(host, port), from: parsed.Address, host: host}, nil
}

// Send delivers one message under the caller's bound. Every failure leaves by
// the same door, naming the stage and no server text.
func (s *Sender) Send(ctx context.Context, message emailverification.Message) error {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", s.address)
	if err != nil {
		return fmt.Errorf("%w: dial", ErrDelivery)
	}
	defer func() { _ = conn.Close() }()
	if deadline, held := ctx.Deadline(); held {
		_ = conn.SetDeadline(deadline)
	}

	client, err := smtp.NewClient(conn, s.host)
	if err != nil {
		return fmt.Errorf("%w: greeting", ErrDelivery)
	}
	defer func() { _ = client.Close() }()

	if err := client.Mail(s.from); err != nil {
		return fmt.Errorf("%w: sender", ErrDelivery)
	}
	if err := client.Rcpt(message.To.Reveal()); err != nil {
		return fmt.Errorf("%w: recipient", ErrDelivery)
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("%w: data", ErrDelivery)
	}
	if _, err := writer.Write([]byte(s.compose(message))); err != nil {
		return fmt.Errorf("%w: body", ErrDelivery)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("%w: body", ErrDelivery)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("%w: close", ErrDelivery)
	}
	return nil
}

// compose writes the message. It carries no product name, because none is
// adopted, and no value beyond the link and its expiry.
func (s *Sender) compose(message emailverification.Message) string {
	headers := []string{
		"From: " + s.from,
		"To: " + message.To.Reveal(),
		"Subject: Confirm your email address",
		"Date: " + time.Now().UTC().Format(time.RFC1123Z),
		"Message-ID: <" + message.Delivery.String() + "@" + s.host + ">",
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"Content-Transfer-Encoding: 8bit",
	}
	body := []string{
		"Confirm your email address to finish creating your account.",
		"",
		message.Link,
		"",
		"The link can be used once and expires on " + message.ExpiresAt.UTC().Format(time.RFC1123Z) + ".",
		"",
		"If you did not ask for an account, ignore this message.",
	}
	return strings.Join(headers, "\r\n") + "\r\n\r\n" + strings.Join(body, "\r\n") + "\r\n"
}
