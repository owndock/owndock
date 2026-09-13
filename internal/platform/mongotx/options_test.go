package mongotx

import (
	"testing"

	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

func TestOptionsRequireDurableReplicaSetSemantics(t *testing.T) {
	configured := &options.TransactionOptions{}
	for _, apply := range Options().List() {
		if err := apply(configured); err != nil {
			t.Fatalf("apply transaction option: %v", err)
		}
	}
	if configured.ReadConcern == nil || configured.ReadConcern.Level != "snapshot" {
		t.Fatalf("read concern = %+v, want snapshot", configured.ReadConcern)
	}
	if configured.ReadPreference == nil || configured.ReadPreference.Mode() != readpref.PrimaryMode {
		t.Fatalf("read preference = %+v, want primary", configured.ReadPreference)
	}
	if configured.WriteConcern == nil || configured.WriteConcern.W != "majority" {
		t.Fatalf("write concern = %+v, want majority", configured.WriteConcern)
	}
}
