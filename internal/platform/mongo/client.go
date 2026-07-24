// Package mongo owns the process-wide MongoDB client lifecycle. Business
// modules depend on their own repository interfaces and must not import this
// package directly.
package mongo

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	platformconfig "github.com/owndock/owndock/internal/platform/config"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

type Client struct {
	client           *drivermongo.Client
	database         *drivermongo.Database
	operationTimeout time.Duration
	closeOnce        sync.Once
	closeErr         error
}

func Open(ctx context.Context, cfg platformconfig.Mongo) (*Client, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("MongoDB is disabled")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate MongoDB config: %w", err)
	}
	uri, err := cfg.URI()
	if err != nil {
		return nil, err
	}
	connectTimeout, err := cfg.ConnectTimeoutDuration()
	if err != nil {
		return nil, fmt.Errorf("parse connect timeout: %w", err)
	}
	operationTimeout, err := cfg.OperationTimeoutDuration()
	if err != nil {
		return nil, fmt.Errorf("parse operation timeout: %w", err)
	}
	maxIdleTime, err := cfg.MaxIdleTimeDuration()
	if err != nil {
		return nil, fmt.Errorf("parse max idle time: %w", err)
	}

	clientOptions := options.Client().
		ApplyURI(uri).
		SetConnectTimeout(connectTimeout).
		SetServerSelectionTimeout(connectTimeout).
		SetTimeout(operationTimeout).
		SetMaxConnIdleTime(maxIdleTime).
		SetMinPoolSize(cfg.MinPoolSize).
		SetMaxPoolSize(cfg.MaxPoolSize)
	driverClient, err := drivermongo.Connect(clientOptions)
	if err != nil {
		return nil, fmt.Errorf("create MongoDB client: %w", err)
	}

	client := &Client{
		client:           driverClient,
		database:         driverClient.Database(cfg.Database),
		operationTimeout: operationTimeout,
	}
	pingContext, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	if err := client.Ping(pingContext); err != nil {
		closeContext, closeCancel := context.WithTimeout(context.Background(), connectTimeout)
		defer closeCancel()
		return nil, errors.Join(err, driverClient.Disconnect(closeContext))
	}
	return client, nil
}

func (c *Client) Database() *drivermongo.Database {
	return c.database
}

func (c *Client) WithinTransaction(ctx context.Context, fn func(context.Context) error) error {
	if c == nil || c.client == nil {
		return fmt.Errorf("MongoDB client is not initialized")
	}
	session, err := c.client.StartSession()
	if err != nil {
		return fmt.Errorf("start MongoDB session: %w", err)
	}
	defer session.EndSession(ctx)
	_, err = session.WithTransaction(ctx, func(transactionContext context.Context) (any, error) {
		if err := fn(transactionContext); err != nil {
			return nil, err
		}
		return nil, nil
	})
	if err != nil {
		return fmt.Errorf("run MongoDB transaction: %w", err)
	}
	return nil
}

func (c *Client) Ping(ctx context.Context) error {
	if c == nil || c.client == nil {
		return fmt.Errorf("MongoDB client is not initialized")
	}
	pingContext, cancel := context.WithTimeout(ctx, c.operationTimeout)
	defer cancel()
	if err := c.client.Ping(pingContext, readpref.Primary()); err != nil {
		return fmt.Errorf("ping MongoDB: %w", err)
	}
	return nil
}

func (c *Client) Close(ctx context.Context) error {
	if c == nil || c.client == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		c.closeErr = c.client.Disconnect(ctx)
	})
	return c.closeErr
}
