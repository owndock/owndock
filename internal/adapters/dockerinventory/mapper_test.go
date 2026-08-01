package dockerinventory

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/image"
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

func TestImageProjectionDropsBuildMetadataAndUntrustedLabels(t *testing.T) {
	item := image.Summary{
		ID: "sha256:image-safe", RepoTags: []string{"example/api:1"},
		ParentID: "image-parent-private-sentinel",
		Labels: map[string]string{
			"com.example.build_secret": "image-label-private-sentinel",
			"net.owndock.project_id":   "project-1",
		},
	}
	resource, err := Image(item, time.Unix(400, 0))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(resource)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"image-parent-private-sentinel", "image-label-private-sentinel",
		"com.example.build_secret",
	} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("image projection leaked %q: %s", forbidden, payload)
		}
	}
	if resource.Labels["net.owndock.project_id"] != "project-1" {
		t.Fatalf("safe image candidate label = %#v", resource.Labels)
	}
}

func TestNetworkProjectionDropsDriverOptionsAndAuxiliaryMetadata(t *testing.T) {
	item := network.Summary{Network: network.Network{
		ID: "network-1", Name: "application", Driver: "bridge", Scope: "local",
		Options: map[string]string{
			"driver.private.option": "network-option-private-sentinel",
		},
		Labels: map[string]string{
			"com.example.secret":        "network-label-private-sentinel",
			"net.owndock.deployment_id": "deployment-1",
		},
		IPAM: network.IPAM{
			Driver: "default",
			Options: map[string]string{
				"ipam.private.option": "network-ipam-private-sentinel",
			},
			Config: []network.IPAMConfig{{
				Subnet:  netip.MustParsePrefix("172.30.0.0/24"),
				Gateway: netip.MustParseAddr("172.30.0.1"),
				AuxAddress: map[string]netip.Addr{
					"private-service": netip.MustParseAddr("172.30.0.2"),
				},
			}},
		},
	}}
	resource, err := Network(item, time.Unix(500, 0))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(resource)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"network-option-private-sentinel", "network-label-private-sentinel",
		"network-ipam-private-sentinel", "private-service",
		"driver.private.option", "ipam.private.option", "com.example.secret",
	} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("network projection leaked %q: %s", forbidden, payload)
		}
	}
	if resource.Labels["net.owndock.deployment_id"] != "deployment-1" ||
		len(resource.Network.IPAM) != 1 ||
		resource.Network.IPAM[0].Gateway != "172.30.0.1" {
		t.Fatalf("safe network projection = %#v", resource)
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
