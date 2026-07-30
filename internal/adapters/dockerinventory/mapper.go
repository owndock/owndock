// Package dockerinventory maps Moby API list responses to OwnDock's safe
// runtime-inventory transport contract.
package dockerinventory

import (
	"fmt"
	"net"
	"path"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/image"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/api/types/volume"
	inventory "github.com/owndock/owndock/internal/shared/runtimeinventory"
)

func Container(item container.Summary, observedAt time.Time) (inventory.Resource, error) {
	names := append([]string{}, item.Names...)
	sort.Strings(names)
	name := ""
	for _, candidate := range names {
		candidate = strings.TrimPrefix(strings.TrimSpace(candidate), "/")
		if safeText(candidate, 256) {
			name = candidate
			break
		}
	}
	if name == "" {
		name = displayID(item.ID)
	}
	resource := inventory.Resource{
		Kind:      inventory.KindContainer,
		RuntimeID: strings.TrimSpace(item.ID),
		Name:      name,
		Container: &inventory.ContainerSummary{
			ImageReference: safeOptional(item.Image, 512),
			ImageDigest:    safeOptional(item.ImageID, 512),
			State:          safeOptional(string(item.State), 64),
			CreatedAt:      unixTime(item.Created),
		},
		Labels:        filteredLabels(item.Labels),
		Ports:         ports(item.Ports),
		Mounts:        mounts(item.Mounts),
		ObservedAt:    observedAt.UTC(),
		SchemaVersion: inventory.SchemaVersion,
	}
	if item.Health != nil {
		resource.Container.Health = safeOptional(string(item.Health.Status), 64)
	}
	if item.NetworkSettings != nil {
		resource.Networks = networkAttachments(item.NetworkSettings.Networks)
	}
	if err := resource.Validate(); err != nil {
		return inventory.Resource{}, fmt.Errorf("map Docker container %q: %w", displayID(item.ID), err)
	}
	return resource, nil
}

func Image(item image.Summary, observedAt time.Time) (inventory.Resource, error) {
	tags := safeReferences(item.RepoTags)
	digests := safeReferences(item.RepoDigests)
	name := firstValue(tags, digests)
	if name == "" {
		name = displayID(item.ID)
	}
	size := item.Size
	if size < 0 {
		size = 0
	}
	resource := inventory.Resource{
		Kind:      inventory.KindImage,
		RuntimeID: strings.TrimSpace(item.ID),
		Name:      name,
		Image: &inventory.ImageSummary{
			RepoTags:    tags,
			RepoDigests: digests,
			SizeBytes:   size,
			CreatedAt:   unixTime(item.Created),
		},
		Labels:        filteredLabels(item.Labels),
		ObservedAt:    observedAt.UTC(),
		SchemaVersion: inventory.SchemaVersion,
	}
	if err := resource.Validate(); err != nil {
		return inventory.Resource{}, fmt.Errorf("map Docker image %q: %w", displayID(item.ID), err)
	}
	return resource, nil
}

func Network(item network.Summary, observedAt time.Time) (inventory.Resource, error) {
	name := strings.TrimSpace(item.Name)
	if !safeText(name, 256) {
		name = displayID(item.ID)
	}
	ipam := make([]inventory.IPAMConfig, 0, min(len(item.IPAM.Config), 64))
	for _, candidate := range item.IPAM.Config {
		value := inventory.IPAMConfig{}
		if candidate.Subnet.IsValid() {
			value.Subnet = candidate.Subnet.String()
		}
		if candidate.IPRange.IsValid() {
			value.IPRange = candidate.IPRange.String()
		}
		if candidate.Gateway.IsValid() {
			value.Gateway = candidate.Gateway.String()
		}
		if value != (inventory.IPAMConfig{}) {
			ipam = append(ipam, value)
			if len(ipam) == 64 {
				break
			}
		}
	}
	resource := inventory.Resource{
		Kind:      inventory.KindNetwork,
		RuntimeID: strings.TrimSpace(item.ID),
		Name:      name,
		Network: &inventory.NetworkSummary{
			Driver:     safeOptional(item.Driver, 128),
			Scope:      safeOptional(item.Scope, 64),
			Internal:   item.Internal,
			Attachable: item.Attachable,
			Ingress:    item.Ingress,
			EnableIPv4: item.EnableIPv4,
			EnableIPv6: item.EnableIPv6,
			IPAM:       ipam,
		},
		Labels:        filteredLabels(item.Labels),
		ObservedAt:    observedAt.UTC(),
		SchemaVersion: inventory.SchemaVersion,
	}
	if err := resource.Validate(); err != nil {
		return inventory.Resource{}, fmt.Errorf("map Docker network %q: %w", displayID(item.ID), err)
	}
	return resource, nil
}

func Volume(item volume.Volume, observedAt time.Time) (inventory.Resource, error) {
	name := strings.TrimSpace(item.Name)
	usageKnown := item.UsageData != nil && item.UsageData.RefCount >= 0
	resource := inventory.Resource{
		Kind:      inventory.KindVolume,
		RuntimeID: name,
		Name:      name,
		Volume: &inventory.VolumeSummary{
			Driver:     safeOptional(item.Driver, 128),
			Scope:      safeOptional(item.Scope, 64),
			InUse:      usageKnown && item.UsageData.RefCount > 0,
			UsageKnown: usageKnown,
			CreatedAt:  parseTime(item.CreatedAt),
		},
		Labels:        filteredLabels(item.Labels),
		ObservedAt:    observedAt.UTC(),
		SchemaVersion: inventory.SchemaVersion,
	}
	if err := resource.Validate(); err != nil {
		return inventory.Resource{}, fmt.Errorf("map Docker volume %q: %w", name, err)
	}
	return resource, nil
}

func filteredLabels(source map[string]string) map[string]string {
	result := make(map[string]string)
	for key, value := range source {
		value = strings.TrimSpace(value)
		if inventory.AllowedLabel(key) && ownershipID(value) {
			result[key] = value
		}
	}
	return result
}

func ownershipID(value string) bool {
	if value == "" || len(value) > 160 {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			index > 0 && (character == '.' || character == '_' ||
				character == ':' || character == '-') {
			continue
		}
		return false
	}
	return true
}

func ports(source []container.PortSummary) []inventory.Port {
	result := make([]inventory.Port, 0, min(len(source), 128))
	for _, item := range source {
		protocol := strings.ToLower(strings.TrimSpace(item.Type))
		if item.PrivatePort == 0 ||
			!slices.Contains([]string{"tcp", "udp", "sctp"}, protocol) {
			continue
		}
		hostIP := ""
		if item.IP.IsValid() {
			hostIP = item.IP.String()
		}
		result = append(result, inventory.Port{
			ContainerPort: item.PrivatePort,
			HostIP:        hostIP,
			HostPort:      item.PublicPort,
			Protocol:      protocol,
		})
		if len(result) == 128 {
			break
		}
	}
	return result
}

func mounts(source []container.MountPoint) []inventory.Mount {
	result := make([]inventory.Mount, 0, min(len(source), 128))
	for _, item := range source {
		mountType := string(item.Type)
		destination := strings.TrimSpace(item.Destination)
		if !slices.Contains([]string{"bind", "volume", "tmpfs"}, mountType) ||
			!strings.HasPrefix(destination, "/") ||
			path.Clean(destination) != destination ||
			len(destination) > 512 {
			continue
		}
		result = append(result, inventory.Mount{
			Name:        safeOptional(item.Name, 128),
			Type:        mountType,
			Destination: destination,
			ReadOnly:    !item.RW,
		})
		if len(result) == 128 {
			break
		}
	}
	return result
}

func networkAttachments(
	source map[string]*network.EndpointSettings,
) []inventory.NetworkAttachment {
	names := make([]string, 0, len(source))
	for name := range source {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]inventory.NetworkAttachment, 0, min(len(names), 64))
	for _, name := range names {
		item := source[name]
		if item == nil || !safeText(name, 256) {
			continue
		}
		attachment := inventory.NetworkAttachment{
			NetworkID: safeOptional(item.NetworkID, 256),
			Name:      name,
		}
		if item.IPAddress.IsValid() {
			attachment.IPAddress = item.IPAddress.String()
		}
		if item.Gateway.IsValid() {
			attachment.Gateway = item.Gateway.String()
		}
		if len(item.MacAddress) > 0 {
			value := item.MacAddress.String()
			if _, err := net.ParseMAC(value); err == nil {
				attachment.MAC = value
			}
		}
		result = append(result, attachment)
		if len(result) == 64 {
			break
		}
	}
	return result
}

func safeReferences(source []string) []string {
	sorted := append([]string{}, source...)
	sort.Strings(sorted)
	result := make([]string, 0, min(len(sorted), 128))
	for _, value := range sorted {
		value = strings.TrimSpace(value)
		if safeText(value, 512) && !strings.Contains(value, "://") {
			result = append(result, value)
			if len(result) == 128 {
				break
			}
		}
	}
	return result
}

func displayID(value string) string {
	value = strings.TrimSpace(strings.TrimPrefix(value, "sha256:"))
	if len(value) > 12 {
		value = value[:12]
	}
	if value == "" {
		return "unknown"
	}
	return value
}

func firstValue(groups ...[]string) string {
	for _, group := range groups {
		if len(group) > 0 {
			return group[0]
		}
	}
	return ""
}

func safeOptional(value string, maximum int) string {
	value = strings.TrimSpace(value)
	if !safeText(value, maximum) {
		return ""
	}
	return value
}

func safeText(value string, maximum int) bool {
	return len(value) <= maximum && !strings.ContainsRune(value, '\x00')
}

func unixTime(value int64) time.Time {
	if value <= 0 {
		return time.Time{}
	}
	return time.Unix(value, 0).UTC()
}

func parseTime(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(value))
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}
