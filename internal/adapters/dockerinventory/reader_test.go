package dockerinventory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/image"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/api/types/volume"
	"github.com/moby/moby/client"
	runtimeinventory "github.com/owndock/owndock/internal/shared/runtimeinventory"
)

type fakeEngine struct {
	containerOptions client.ContainerListOptions
	imageOptions     client.ImageListOptions
	containers       client.ContainerListResult
	images           client.ImageListResult
	networks         client.NetworkListResult
	volumes          client.VolumeListResult
	networkError     error
	imageCalled      bool
	networkCalled    bool
	volumeCalled     bool
}

func (f *fakeEngine) ContainerList(
	_ context.Context,
	options client.ContainerListOptions,
) (client.ContainerListResult, error) {
	f.containerOptions = options
	return f.containers, nil
}

func (f *fakeEngine) ImageList(
	_ context.Context,
	options client.ImageListOptions,
) (client.ImageListResult, error) {
	f.imageCalled = true
	f.imageOptions = options
	return f.images, nil
}

func (f *fakeEngine) NetworkList(
	context.Context,
	client.NetworkListOptions,
) (client.NetworkListResult, error) {
	f.networkCalled = true
	return f.networks, f.networkError
}

func TestReaderRejectsOversizedSnapshotBeforeCallingMoreEndpoints(t *testing.T) {
	engine := &fakeEngine{containers: client.ContainerListResult{Items: []container.Summary{
		{ID: "container-1", Names: []string{"/one"}},
		{ID: "container-2", Names: []string{"/two"}},
		{ID: "container-3", Names: []string{"/three"}},
	}}}
	reader := NewReader(engine)
	reader.maximumResources = 2
	resources, err := reader.Collect(t.Context())
	if !errors.Is(err, runtimeinventory.ErrSnapshotTooLarge) || resources != nil {
		t.Fatalf("Collect() = %#v, %v", resources, err)
	}
	if engine.imageCalled || engine.networkCalled || engine.volumeCalled {
		t.Fatalf("oversized snapshot called later endpoints: %+v", engine)
	}
}

func TestResourceLimitUsesOverflowSafeCumulativeAccounting(t *testing.T) {
	for _, test := range []struct {
		maximum int
		counts  []int
		want    bool
	}{
		{maximum: 10, counts: []int{3, 7}, want: false},
		{maximum: 10, counts: []int{3, 8}, want: true},
		{maximum: runtimeinventory.MaxResources, counts: []int{runtimeinventory.MaxResources}, want: false},
		{maximum: runtimeinventory.MaxResources, counts: []int{runtimeinventory.MaxResources, 1}, want: true},
		{maximum: 10, counts: []int{-1}, want: true},
	} {
		if got := exceedsResourceLimit(test.maximum, test.counts...); got != test.want {
			t.Errorf("exceedsResourceLimit(%d, %v) = %t, want %t", test.maximum, test.counts, got, test.want)
		}
	}
}

func (f *fakeEngine) VolumeList(
	context.Context,
	client.VolumeListOptions,
) (client.VolumeListResult, error) {
	f.volumeCalled = true
	return f.volumes, nil
}

func TestReaderCollectsAndSortsSafeSnapshot(t *testing.T) {
	engine := &fakeEngine{
		containers: client.ContainerListResult{Items: []container.Summary{
			{ID: "container-b", Names: []string{"/b"}},
			{ID: "container-a", Names: []string{"/a"}},
		}},
		images: client.ImageListResult{Items: []image.Summary{{
			ID: "sha256:image-a", RepoTags: []string{"example/api:1"}, Size: 42,
		}}},
		networks: client.NetworkListResult{Items: []network.Summary{{
			Network: network.Network{ID: "network-a", Name: "app"},
		}}},
		volumes: client.VolumeListResult{Items: []volume.Volume{volumeFixture()}},
	}
	reader := NewReader(engine)
	reader.now = func() time.Time { return time.Unix(500, 0).UTC() }
	resources, err := reader.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 5 {
		t.Fatalf("resource count = %d, want 5", len(resources))
	}
	if resources[0].Name != "a" || resources[1].Name != "b" {
		t.Fatalf("container order = %q, %q", resources[0].Name, resources[1].Name)
	}
	if !engine.containerOptions.All || engine.containerOptions.Size ||
		engine.containerOptions.Latest || engine.containerOptions.Since != "" ||
		engine.containerOptions.Before != "" {
		t.Fatalf("unsafe/expensive container options = %#v", engine.containerOptions)
	}
	if engine.imageOptions.SharedSize || engine.imageOptions.Manifests ||
		engine.imageOptions.Identity {
		t.Fatalf("expensive image options = %#v", engine.imageOptions)
	}
	for _, resource := range resources {
		if !resource.ObservedAt.Equal(time.Unix(500, 0)) {
			t.Fatalf("observed_at = %v", resource.ObservedAt)
		}
	}
}

func TestReaderReturnsNoPartialSnapshot(t *testing.T) {
	engine := &fakeEngine{
		containers: client.ContainerListResult{Items: []container.Summary{{
			ID: "container-a", Names: []string{"/a"},
		}}},
		networkError: errors.New("daemon unavailable"),
	}
	resources, err := NewReader(engine).Collect(context.Background())
	if err == nil || resources != nil {
		t.Fatalf("resources/error = %#v/%v, want nil/error", resources, err)
	}
	if engine.volumeCalled {
		t.Fatal("collector must stop after a failed list call")
	}
}
