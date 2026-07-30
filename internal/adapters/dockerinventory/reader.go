package dockerinventory

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/moby/moby/client"
	inventory "github.com/owndock/owndock/internal/shared/runtimeinventory"
)

type Engine interface {
	ContainerList(context.Context, client.ContainerListOptions) (client.ContainerListResult, error)
	ImageList(context.Context, client.ImageListOptions) (client.ImageListResult, error)
	NetworkList(context.Context, client.NetworkListOptions) (client.NetworkListResult, error)
	VolumeList(context.Context, client.VolumeListOptions) (client.VolumeListResult, error)
}

type Reader struct {
	engine Engine
	now    func() time.Time
}

func NewReader(engine Engine) *Reader {
	return &Reader{
		engine: engine,
		now:    func() time.Time { return time.Now().UTC() },
	}
}

// Collect reads one all-or-nothing snapshot. It uses only list endpoints and
// disables expensive size/manifest expansion; the caller supplies deadline
// and cancellation through ctx.
func (r *Reader) Collect(ctx context.Context) ([]inventory.Resource, error) {
	if r == nil || r.engine == nil {
		return nil, fmt.Errorf("collect Docker runtime inventory: engine is required")
	}
	observedAt := r.now().UTC()
	containers, err := r.engine.ContainerList(
		ctx,
		client.ContainerListOptions{All: true, Size: false},
	)
	if err != nil {
		return nil, fmt.Errorf("list Docker containers: %w", err)
	}
	images, err := r.engine.ImageList(
		ctx,
		client.ImageListOptions{
			All:        true,
			SharedSize: false,
			Manifests:  false,
			Identity:   false,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("list Docker images: %w", err)
	}
	networks, err := r.engine.NetworkList(ctx, client.NetworkListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list Docker networks: %w", err)
	}
	volumes, err := r.engine.VolumeList(ctx, client.VolumeListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list Docker volumes: %w", err)
	}

	total := len(containers.Items) + len(images.Items) +
		len(networks.Items) + len(volumes.Items)
	if total > inventory.MaxResources {
		return nil, inventory.ErrSnapshotTooLarge
	}
	result := make([]inventory.Resource, 0, total)
	for _, item := range containers.Items {
		resource, mapErr := Container(item, observedAt)
		if mapErr != nil {
			return nil, mapErr
		}
		result = append(result, resource)
	}
	for _, item := range images.Items {
		resource, mapErr := Image(item, observedAt)
		if mapErr != nil {
			return nil, mapErr
		}
		result = append(result, resource)
	}
	for _, item := range networks.Items {
		resource, mapErr := Network(item, observedAt)
		if mapErr != nil {
			return nil, mapErr
		}
		result = append(result, resource)
	}
	for _, item := range volumes.Items {
		resource, mapErr := Volume(item, observedAt)
		if mapErr != nil {
			return nil, mapErr
		}
		result = append(result, resource)
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].Kind != result[right].Kind {
			return result[left].Kind < result[right].Kind
		}
		if result[left].Name != result[right].Name {
			return result[left].Name < result[right].Name
		}
		return result[left].RuntimeID < result[right].RuntimeID
	})
	return result, nil
}

var _ Engine = (*client.Client)(nil)
