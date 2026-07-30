package runtimeinventory

import (
	"encoding/json"
	"fmt"
)

type Chunk struct {
	SchemaVersion int        `json:"schema_version"`
	Index         int        `json:"index"`
	Resources     []Resource `json:"resources"`
}

// Split produces independently bounded JSON frames. maxBytes is checked
// against the exact encoded chunk, including the envelope and separators.
func Split(resources []Resource, maxBytes, maxItems int) ([]Chunk, error) {
	if len(resources) > MaxResources {
		return nil, ErrSnapshotTooLarge
	}
	if len(resources) == 0 {
		return []Chunk{}, nil
	}
	if maxBytes <= 0 || maxBytes > MaxChunkBytes ||
		maxItems <= 0 || maxItems > MaxResourcesPerChunk {
		return nil, ErrInvalidChunk
	}
	encoded := make([][]byte, len(resources))
	seen := make(map[string]struct{}, len(resources))
	totalEncodedBytes := 0
	for index, resource := range resources {
		if err := resource.Validate(); err != nil {
			return nil, err
		}
		key := string(resource.Kind) + "\x00" + resource.RuntimeID
		if _, exists := seen[key]; exists {
			return nil, ErrInvalidResource
		}
		seen[key] = struct{}{}
		value, err := json.Marshal(resource)
		if err != nil {
			return nil, fmt.Errorf("encode runtime inventory resource: %w", err)
		}
		encoded[index] = value
		totalEncodedBytes += len(value)
		if totalEncodedBytes > MaxSnapshotBytes {
			return nil, ErrSnapshotTooLarge
		}
	}

	chunks := make([]Chunk, 0, (len(resources)+maxItems-1)/maxItems)
	for first := 0; first < len(resources); {
		chunkIndex := len(chunks)
		last := first
		for last < len(resources) && last-first < maxItems {
			size := chunkEnvelopeBytes(chunkIndex)
			for itemIndex := first; itemIndex <= last; itemIndex++ {
				size += len(encoded[itemIndex])
				if itemIndex > first {
					size++
				}
			}
			if size > maxBytes {
				break
			}
			last++
		}
		if last == first {
			return nil, ErrSnapshotTooLarge
		}
		chunk := Chunk{
			SchemaVersion: SchemaVersion,
			Index:         chunkIndex,
			Resources:     append([]Resource{}, resources[first:last]...),
		}
		payload, err := json.Marshal(chunk)
		if err != nil {
			return nil, fmt.Errorf("encode runtime inventory chunk: %w", err)
		}
		if len(payload) > maxBytes {
			return nil, ErrSnapshotTooLarge
		}
		chunks = append(chunks, chunk)
		if len(chunks) > MaxChunks {
			return nil, ErrSnapshotTooLarge
		}
		first = last
	}
	return chunks, nil
}

func (c Chunk) Validate(maxBytes int) error {
	if c.SchemaVersion != SchemaVersion || c.Index < 0 ||
		len(c.Resources) == 0 || len(c.Resources) > MaxResourcesPerChunk ||
		maxBytes <= 0 || maxBytes > MaxChunkBytes {
		return ErrInvalidChunk
	}
	for _, resource := range c.Resources {
		if err := resource.Validate(); err != nil {
			return err
		}
	}
	payload, err := json.Marshal(c)
	if err != nil || len(payload) > maxBytes {
		return ErrInvalidChunk
	}
	return nil
}

func chunkEnvelopeBytes(index int) int {
	payload, _ := json.Marshal(Chunk{
		SchemaVersion: SchemaVersion,
		Index:         index,
		Resources:     []Resource{},
	})
	// Replace the encoded empty array with the resource bytes.
	return len(payload) - len("[]")
}
