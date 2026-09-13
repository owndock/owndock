package mongo

import (
	"context"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"
)

type bsonContractNestedDocument struct {
	State string `bson:"state"`
}

type bsonContractDocument struct {
	ID             string                     `bson:"_id"`
	RecordedAt     time.Time                  `bson:"recorded_at"`
	Signed         int64                      `bson:"signed"`
	Unsigned       uint64                     `bson:"unsigned"`
	Enabled        bool                       `bson:"enabled"`
	NilValues      []string                   `bson:"nil_values"`
	EmptyValues    []string                   `bson:"empty_values"`
	NilLabels      map[string]string          `bson:"nil_labels"`
	EmptyLabels    map[string]string          `bson:"empty_labels"`
	Optional       string                     `bson:"optional,omitempty"`
	NestedDocument bsonContractNestedDocument `bson:"nested_document"`
}

func assertMongoBSONStorageContract(
	t *testing.T,
	ctx context.Context,
	database *drivermongo.Database,
) {
	t.Helper()
	recordedAt := time.Date(2026, time.September, 13, 8, 9, 10, 987654321, time.FixedZone("fixture", 8*60*60))
	wantRecordedAt := time.UnixMilli(recordedAt.UnixMilli()).UTC()
	fixture := bsonContractDocument{
		ID:             "bson-contract",
		RecordedAt:     recordedAt,
		Signed:         -7,
		Unsigned:       7,
		Enabled:        true,
		EmptyValues:    []string{},
		EmptyLabels:    map[string]string{},
		NestedDocument: bsonContractNestedDocument{State: "explicit"},
	}
	collection := database.Collection("platform_bson_contract")
	if _, err := collection.InsertOne(ctx, fixture); err != nil {
		t.Fatalf("insert BSON contract fixture: %v", err)
	}

	var raw bson.Raw
	if err := collection.FindOne(ctx, bson.D{{Key: "_id", Value: fixture.ID}}).Decode(&raw); err != nil {
		t.Fatalf("read raw BSON contract fixture: %v", err)
	}
	wantTypes := map[string]bson.Type{
		"_id":             bson.TypeString,
		"recorded_at":     bson.TypeDateTime,
		"signed":          bson.TypeInt64,
		"unsigned":        bson.TypeInt64,
		"enabled":         bson.TypeBoolean,
		"nil_values":      bson.TypeNull,
		"empty_values":    bson.TypeArray,
		"nil_labels":      bson.TypeNull,
		"empty_labels":    bson.TypeEmbeddedDocument,
		"nested_document": bson.TypeEmbeddedDocument,
	}
	for field, wantType := range wantTypes {
		value, err := raw.LookupErr(field)
		if err != nil {
			t.Fatalf("BSON contract field %s is missing: %v", field, err)
		}
		if value.Type != wantType {
			t.Fatalf("BSON contract field %s type = %s, want %s", field, value.Type, wantType)
		}
	}
	if _, err := raw.LookupErr("optional"); err == nil {
		t.Fatal("omitempty BSON contract field was persisted")
	}
	if got := time.UnixMilli(raw.Lookup("recorded_at").DateTime()).UTC(); !got.Equal(wantRecordedAt) {
		t.Fatalf("BSON datetime = %s, want millisecond UTC value %s", got, wantRecordedAt)
	}

	var decoded bsonContractDocument
	if err := bson.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode BSON contract fixture: %v", err)
	}
	if decoded.ID != fixture.ID || !decoded.RecordedAt.Equal(wantRecordedAt) ||
		decoded.Signed != fixture.Signed || decoded.Unsigned != fixture.Unsigned || !decoded.Enabled ||
		decoded.NilValues != nil || decoded.EmptyValues == nil || len(decoded.EmptyValues) != 0 ||
		decoded.NilLabels != nil || decoded.EmptyLabels == nil || len(decoded.EmptyLabels) != 0 ||
		decoded.NestedDocument.State != fixture.NestedDocument.State {
		t.Fatalf("decoded BSON contract fixture = %+v", decoded)
	}
	if _, err := collection.InsertOne(ctx, bson.D{
		{Key: "_id", Value: "bson-contract-unsigned-overflow"},
		{Key: "unsigned", Value: uint64(1) << 63},
	}); err == nil {
		t.Fatal("MongoDB BSON encoder accepted an unsigned integer above int64")
	}
}
