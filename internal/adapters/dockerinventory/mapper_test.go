package dockerinventory

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
)

func TestContainerProjectionDropsSecretsAndHostPaths(t *testing.T) {
	item := container.Summary{
		ID:      strings.Repeat("a", 64),
		Names:   []string{"/api"},
		Image:   "registry.example.com/team/api:1.0",
		ImageID: "sha256:image",
		State:   container.StateRunning,
		Labels: map[string]string{
			"net.owndock.deployment_id":                "deployment-1",
			"org.opencontainers.image.title":           "api",
			"com.example.password":                     "label-secret-value",
			"net.owndock.deployment_id.hidden_payload": "hidden-value",
			"net.owndock.project_id":                   "password=hidden",
		},
		Ports: []container.PortSummary{{
			IP:          netip.MustParseAddr("127.0.0.1"),
			PrivatePort: 8080, PublicPort: 18080, Type: "tcp",
		}},
		Mounts: []container.MountPoint{{
			Type: mount.TypeBind, Name: "source",
			Source: "/srv/private/customer", Destination: "/app/data", RW: false,
		}},
		NetworkSettings: &container.NetworkSettingsSummary{
			Networks: map[string]*network.EndpointSettings{
				"app": {
					NetworkID: "network-1",
					IPAddress: netip.MustParseAddr("172.20.0.2"),
					Gateway:   netip.MustParseAddr("172.20.0.1"),
				},
			},
		},
	}
	resource, err := Container(item, time.Unix(200, 0))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(resource)
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, forbidden := range []string{
		"/srv/private/customer",
		"label-secret-value",
		"hidden-value",
		"com.example.password",
		"password=hidden",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("projection leaked %q: %s", forbidden, text)
		}
	}
	if resource.Labels["net.owndock.deployment_id"] != "deployment-1" {
		t.Fatalf("deployment label = %q", resource.Labels["net.owndock.deployment_id"])
	}
	if len(resource.Mounts) != 1 ||
		resource.Mounts[0].Destination != "/app/data" ||
		!resource.Mounts[0].ReadOnly {
		t.Fatalf("safe mount = %#v", resource.Mounts)
	}
}

func TestVolumeProjectionDropsDriverOptionsAndMountpoint(t *testing.T) {
	item := volumeFixture()
	resource, err := Volume(item, time.Unix(300, 0))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(resource)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"/var/lib/docker/volumes/data",
		"username=customer,password=hidden",
		"driver-private-state",
	} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("volume projection leaked %q: %s", forbidden, payload)
		}
	}
	if resource.Volume.UsageKnown {
		t.Fatal("ordinary VolumeList response must not invent usage state")
	}
}
