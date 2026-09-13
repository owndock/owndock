// Package mongotx defines the transaction durability contract shared by
// MongoDB infrastructure adapters. Keeping the options in one package prevents
// repositories that own internal atomic operations from silently falling back
// to driver defaults.
package mongotx

import (
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readconcern"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
	"go.mongodb.org/mongo-driver/v2/mongo/writeconcern"
)

func Options() *options.TransactionOptionsBuilder {
	return options.Transaction().
		SetReadConcern(readconcern.Snapshot()).
		SetReadPreference(readpref.Primary()).
		SetWriteConcern(writeconcern.Majority())
}
