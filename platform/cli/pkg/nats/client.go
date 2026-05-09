package nats

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"
	"time"

	natsclient "github.com/nats-io/nats.go"
)

type Client struct {
	conn *natsclient.Conn
}

func NewClient(url string) (*Client, error) {
	nc, err := natsclient.Connect(url,
		natsclient.RetryOnFailedConnect(true),
		natsclient.MaxReconnects(5),
		natsclient.Timeout(5*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("connecting to NATS at %s: %w", url, err)
	}
	return &Client{conn: nc}, nil
}

// Subscribe blocks until SIGINT/SIGTERM, forwarding messages to handler.
// For context-based cancellation, use SubscribeCtx instead.
func (c *Client) Subscribe(subject string, handler func(subject string, data []byte)) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return c.SubscribeCtx(ctx, subject, handler)
}

// SubscribeCtx subscribes to a NATS subject and blocks until the context
// is cancelled, then cleanly unsubscribes and drains the connection.
func (c *Client) SubscribeCtx(ctx context.Context, subject string, handler func(subject string, data []byte)) error {
	sub, err := c.conn.Subscribe(subject, func(msg *natsclient.Msg) {
		handler(msg.Subject, msg.Data)
	})
	if err != nil {
		return fmt.Errorf("subscribing to %s: %w", subject, err)
	}

	<-ctx.Done()

	sub.Unsubscribe()
	c.conn.Drain()
	return nil
}

func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Drain()
	}
}
