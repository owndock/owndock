package data

import (
	"fmt"

	"github.com/owndock/owndock/internal/modules/runtimeinventory/biz"
	transport "github.com/owndock/owndock/internal/shared/runtimeinventory"
)

// ProjectResources converts the shared collector payload into domain objects.
// Ownership is intentionally not inferred from Docker labels. The current
// projection verifies container candidates against successful Deployments in
// bounded batches before setting Managed.
func ProjectResources(
	observation biz.Observation,
	source []transport.Resource,
) ([]biz.Resource, error) {
	resources := make([]biz.Resource, len(source))
	for index, item := range source {
		if err := item.Validate(); err != nil {
			return nil, fmt.Errorf("validate runtime inventory transport resource: %w", err)
		}
		resource, err := biz.NewResource(
			observation,
			projectKind(item.Kind),
			item.RuntimeID,
			item.Name,
			item.ObservedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("create runtime inventory resource: %w", err)
		}
		resource.Container = projectContainer(item.Container)
		resource.Image = projectImage(item.Image)
		resource.Network = projectNetwork(item.Network)
		resource.Volume = projectVolume(item.Volume)
		resource.Labels = cloneMap(item.Labels)
		resource.Ports = make([]biz.Port, len(item.Ports))
		for childIndex, value := range item.Ports {
			resource.Ports[childIndex] = biz.Port{
				ContainerPort: value.ContainerPort,
				HostIP:        value.HostIP,
				HostPort:      value.HostPort,
				Protocol:      value.Protocol,
			}
		}
		resource.Mounts = make([]biz.Mount, len(item.Mounts))
		for childIndex, value := range item.Mounts {
			resource.Mounts[childIndex] = biz.Mount{
				Name:        value.Name,
				Type:        value.Type,
				Destination: value.Destination,
				ReadOnly:    value.ReadOnly,
			}
		}
		resource.Networks = make([]biz.NetworkAttachment, len(item.Networks))
		for childIndex, value := range item.Networks {
			resource.Networks[childIndex] = biz.NetworkAttachment{
				NetworkID: value.NetworkID,
				Name:      value.Name,
				IPAddress: value.IPAddress,
				Gateway:   value.Gateway,
				MAC:       value.MAC,
			}
		}
		if err := resource.Validate(); err != nil {
			return nil, fmt.Errorf("validate projected runtime inventory resource: %w", err)
		}
		resources[index] = resource
	}
	return resources, nil
}

func projectKind(value transport.Kind) biz.Kind {
	switch value {
	case transport.KindContainer:
		return biz.KindContainer
	case transport.KindImage:
		return biz.KindImage
	case transport.KindNetwork:
		return biz.KindNetwork
	case transport.KindVolume:
		return biz.KindVolume
	default:
		return ""
	}
}

func projectContainer(value *transport.ContainerSummary) *biz.ContainerSummary {
	if value == nil {
		return nil
	}
	return &biz.ContainerSummary{
		ImageReference: value.ImageReference,
		ImageDigest:    value.ImageDigest,
		State:          value.State,
		Health:         value.Health,
		CreatedAt:      value.CreatedAt,
	}
}

func projectImage(value *transport.ImageSummary) *biz.ImageSummary {
	if value == nil {
		return nil
	}
	return &biz.ImageSummary{
		RepoTags:    append([]string{}, value.RepoTags...),
		RepoDigests: append([]string{}, value.RepoDigests...),
		SizeBytes:   value.SizeBytes,
		CreatedAt:   value.CreatedAt,
	}
}

func projectNetwork(value *transport.NetworkSummary) *biz.NetworkSummary {
	if value == nil {
		return nil
	}
	ipam := make([]biz.IPAMConfig, len(value.IPAM))
	for index, item := range value.IPAM {
		ipam[index] = biz.IPAMConfig{
			Subnet: item.Subnet, IPRange: item.IPRange, Gateway: item.Gateway,
		}
	}
	return &biz.NetworkSummary{
		Driver:     value.Driver,
		Scope:      value.Scope,
		Internal:   value.Internal,
		Attachable: value.Attachable,
		Ingress:    value.Ingress,
		EnableIPv4: value.EnableIPv4,
		EnableIPv6: value.EnableIPv6,
		IPAM:       ipam,
	}
}

func projectVolume(value *transport.VolumeSummary) *biz.VolumeSummary {
	if value == nil {
		return nil
	}
	return &biz.VolumeSummary{
		Driver:     value.Driver,
		Scope:      value.Scope,
		InUse:      value.InUse,
		UsageKnown: value.UsageKnown,
		CreatedAt:  value.CreatedAt,
	}
}
