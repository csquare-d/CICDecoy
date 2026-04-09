package nats

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	natsclient "github.com/nats-io/nats.go"
)

type Client struct {
	conn *natsclient.Conn
}

func NewClient(url string) (*Client, error) {
	nc, err := natsclient.Connect(url,
		natsclient.RetryOnFailedConnect(true),
		natsclient.MaxReconnects(5),
	)
	if err != nil {
		return nil, fmt.Errorf("connecting to NATS at %s: %w", url, err)
	}
	return &Client{conn: nc}, nil
}

func (c *Client) Subscribe(subject string, handler func(subject string, data []byte)) error {
	sub, err := c.conn.Subscribe(subject, func(msg *natsclient.Msg) {
		handler(msg.Subject, msg.Data)
	})
	if err != nil {
		return fmt.Errorf("subscribing to %s: %w", subject, err)
	}

	// Block until SIGINT/SIGTERM
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	sub.Unsubscribe()
	c.conn.Drain()
	return nil
}

func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Drain()
	}
}
