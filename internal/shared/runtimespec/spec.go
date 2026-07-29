package runtimespec

import (
	"errors"
	"regexp"
	"strings"
)

const (
	DefaultCPUMilli    int64 = 500
	DefaultMemoryBytes int64 = 256 * 1024 * 1024
)

var (
	ErrInvalid          = errors.New("runtime specification is invalid")
	environmentNameRule = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	portNameRule        = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)
)

type Spec struct {
	Ports           []Port
	EnvironmentKeys []string
	Resources       Resources
	HealthCheck     *HealthCheck
}

type Port struct {
	Name          string
	ContainerPort uint16
	Protocol      string
}

type Resources struct {
	CPUMilli    int64
	MemoryBytes int64
}

type HealthCheck struct {
	Command            []string
	IntervalSeconds    int
	TimeoutSeconds     int
	Retries            int
	StartPeriodSeconds int
}

func Normalize(spec Spec) (Spec, error) {
	if len(spec.Ports) > 16 || len(spec.EnvironmentKeys) > 100 {
		return Spec{}, ErrInvalid
	}
	portNames := make(map[string]struct{}, len(spec.Ports))
	portNumbers := make(map[uint16]struct{}, len(spec.Ports))
	for i := range spec.Ports {
		port := &spec.Ports[i]
		port.Name = strings.TrimSpace(port.Name)
		port.Protocol = strings.ToLower(strings.TrimSpace(port.Protocol))
		if port.Protocol == "" {
			port.Protocol = "tcp"
		}
		if !portNameRule.MatchString(port.Name) || port.ContainerPort == 0 ||
			(port.Protocol != "tcp" && port.Protocol != "udp") {
			return Spec{}, ErrInvalid
		}
		if _, exists := portNames[port.Name]; exists {
			return Spec{}, ErrInvalid
		}
		if _, exists := portNumbers[port.ContainerPort]; exists {
			return Spec{}, ErrInvalid
		}
		portNames[port.Name] = struct{}{}
		portNumbers[port.ContainerPort] = struct{}{}
	}
	environmentNames := make(map[string]struct{}, len(spec.EnvironmentKeys))
	for i := range spec.EnvironmentKeys {
		name := strings.TrimSpace(spec.EnvironmentKeys[i])
		if !environmentNameRule.MatchString(name) {
			return Spec{}, ErrInvalid
		}
		if _, exists := environmentNames[name]; exists {
			return Spec{}, ErrInvalid
		}
		environmentNames[name] = struct{}{}
		spec.EnvironmentKeys[i] = name
	}
	if spec.Resources.CPUMilli == 0 {
		spec.Resources.CPUMilli = DefaultCPUMilli
	}
	if spec.Resources.MemoryBytes == 0 {
		spec.Resources.MemoryBytes = DefaultMemoryBytes
	}
	if spec.Resources.CPUMilli < 10 || spec.Resources.CPUMilli > 64_000 ||
		spec.Resources.MemoryBytes < 16*1024*1024 ||
		spec.Resources.MemoryBytes > 1024*1024*1024*1024 {
		return Spec{}, ErrInvalid
	}
	if spec.HealthCheck != nil {
		health := spec.HealthCheck
		if len(health.Command) == 0 || len(health.Command) > 32 {
			return Spec{}, ErrInvalid
		}
		for i := range health.Command {
			health.Command[i] = strings.TrimSpace(health.Command[i])
			if health.Command[i] == "" || len(health.Command[i]) > 1024 {
				return Spec{}, ErrInvalid
			}
		}
		if health.IntervalSeconds == 0 {
			health.IntervalSeconds = 30
		}
		if health.TimeoutSeconds == 0 {
			health.TimeoutSeconds = 5
		}
		if health.Retries == 0 {
			health.Retries = 3
		}
		if health.IntervalSeconds < 1 || health.IntervalSeconds > 300 ||
			health.TimeoutSeconds < 1 || health.TimeoutSeconds > 60 ||
			health.Retries < 1 || health.Retries > 10 ||
			health.StartPeriodSeconds < 0 || health.StartPeriodSeconds > 600 {
			return Spec{}, ErrInvalid
		}
	}
	return spec, nil
}

func ValidateBindings(spec Spec, variables map[string]string) ([]string, error) {
	result := make([]string, 0, len(spec.EnvironmentKeys))
	for _, name := range spec.EnvironmentKeys {
		value, exists := variables[name]
		if !exists {
			return nil, ErrInvalid
		}
		result = append(result, name+"="+value)
	}
	return result, nil
}

func NormalizeVariables(variables map[string]string) (map[string]string, error) {
	if len(variables) > 100 {
		return nil, ErrInvalid
	}
	normalized := make(map[string]string, len(variables))
	for name, value := range variables {
		name = strings.TrimSpace(name)
		if !environmentNameRule.MatchString(name) || len(value) > 4096 {
			return nil, ErrInvalid
		}
		if _, exists := normalized[name]; exists {
			return nil, ErrInvalid
		}
		normalized[name] = value
	}
	return normalized, nil
}
