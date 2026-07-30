package dockerinventory

import "github.com/moby/moby/api/types/volume"

func volumeFixture() volume.Volume {
	return volume.Volume{
		Name:       "data",
		Driver:     "local",
		Scope:      "local",
		CreatedAt:  "2026-07-30T10:00:00Z",
		Mountpoint: "/var/lib/docker/volumes/data",
		Options: map[string]string{
			"device": "username=customer,password=hidden",
		},
		Status: map[string]any{"detail": "driver-private-state"},
		Labels: map[string]string{
			"org.opencontainers.image.title": "data",
		},
	}
}
