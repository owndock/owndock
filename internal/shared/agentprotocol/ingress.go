package agentprotocol

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"regexp"
	"sort"
	"strings"
)

const MaxIngressRoutes = 128

const ManagedIngressNetwork = "owndock-ingress"

type IngressTLSMode string

const (
	IngressTLSAutomatic IngressTLSMode = "automatic"
	IngressTLSDisabled  IngressTLSMode = "disabled"
)

type IngressCommand struct {
	HostRevision uint64
	ConfigDigest string
	Routes       []IngressRoute
}

type IngressRoute struct {
	RouteID         string
	Revision        uint64
	DeploymentID    string
	CutoverSequence uint64
	RuntimeTargetID string
	Hostname        string
	BackendAlias    string
	BackendPort     uint16
	TLSMode         IngressTLSMode
}

type IngressResult struct {
	HostRevision uint64
	ConfigDigest string
}

var (
	ingressHostnameLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	ingressBackendAlias  = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)
	ingressDigest        = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

func validIngressCommand(command IngressCommand) bool {
	if command.HostRevision == 0 || len(command.Routes) > MaxIngressRoutes ||
		!ingressDigest.MatchString(command.ConfigDigest) {
		return false
	}
	previousID := ""
	hostnames := make(map[string]struct{}, len(command.Routes))
	for _, route := range command.Routes {
		if !validIngressRoute(route) || route.RouteID <= previousID {
			return false
		}
		if _, exists := hostnames[route.Hostname]; exists {
			return false
		}
		hostnames[route.Hostname] = struct{}{}
		previousID = route.RouteID
	}
	digest, err := IngressConfigDigest(command.HostRevision, command.Routes)
	return err == nil && digest == command.ConfigDigest
}

func (c IngressCommand) Validate() error {
	if !validIngressCommand(c) {
		return ErrCommandInvalid
	}
	return nil
}

func validIngressRoute(route IngressRoute) bool {
	return validIdentifier(route.RouteID) && route.Revision > 0 &&
		validIdentifier(route.DeploymentID) && route.CutoverSequence > 0 &&
		validIdentifier(route.RuntimeTargetID) && validIngressHostname(route.Hostname) &&
		ingressBackendAlias.MatchString(route.BackendAlias) && route.BackendPort > 0 &&
		(route.TLSMode == IngressTLSAutomatic || route.TLSMode == IngressTLSDisabled)
}

func validIngressHostname(value string) bool {
	if value == "" || len(value) > 253 || value != strings.ToLower(value) ||
		strings.HasSuffix(value, ".") || strings.Contains(value, ":") || net.ParseIP(value) != nil {
		return false
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 || value == "localhost" || strings.HasSuffix(value, ".localhost") ||
		strings.HasSuffix(value, ".local") || strings.HasSuffix(value, ".internal") ||
		strings.HasSuffix(value, ".home.arpa") {
		return false
	}
	for _, label := range labels {
		if !ingressHostnameLabel.MatchString(label) {
			return false
		}
	}
	return true
}

// IngressConfigDigest hashes the exact typed desired config. Input ordering is
// canonicalized for callers, while command validation still requires the wire
// routes to be sorted so equivalent payloads have one representation.
func IngressConfigDigest(hostRevision uint64, routes []IngressRoute) (string, error) {
	if hostRevision == 0 || len(routes) > MaxIngressRoutes {
		return "", ErrCommandInvalid
	}
	canonical := append([]IngressRoute(nil), routes...)
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].RouteID < canonical[j].RouteID })
	seen := make(map[string]struct{}, len(canonical))
	hasher := sha256.New()
	writeFingerprintString(hasher, "owndock-ingress-config-v1")
	writeFingerprintUint64(hasher, hostRevision)
	writeFingerprintUint64(hasher, uint64(len(canonical)))
	for _, route := range canonical {
		if !validIngressRoute(route) {
			return "", ErrCommandInvalid
		}
		if _, exists := seen[route.RouteID]; exists {
			return "", ErrCommandInvalid
		}
		seen[route.RouteID] = struct{}{}
		writeIngressRouteFingerprint(hasher, route)
	}
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), nil
}

func IngressRouteSpecDigest(route IngressRoute) (string, error) {
	if !validIngressRoute(route) {
		return "", ErrCommandInvalid
	}
	hasher := sha256.New()
	writeFingerprintString(hasher, "owndock-ingress-route-spec-v1")
	writeFingerprintString(hasher, route.RouteID)
	writeFingerprintString(hasher, route.RuntimeTargetID)
	writeFingerprintString(hasher, route.Hostname)
	writeFingerprintUint64(hasher, uint64(route.BackendPort))
	writeFingerprintString(hasher, string(route.TLSMode))
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), nil
}

func writeIngressRouteFingerprint(hasher fingerprintWriter, route IngressRoute) {
	writeFingerprintString(hasher, route.RouteID)
	writeFingerprintUint64(hasher, route.Revision)
	writeFingerprintString(hasher, route.DeploymentID)
	writeFingerprintUint64(hasher, route.CutoverSequence)
	writeFingerprintString(hasher, route.RuntimeTargetID)
	writeFingerprintString(hasher, route.Hostname)
	writeFingerprintString(hasher, route.BackendAlias)
	writeFingerprintUint64(hasher, uint64(route.BackendPort))
	writeFingerprintString(hasher, string(route.TLSMode))
}

// DeploymentBackendAlias returns the only DNS alias that managed ingress may
// use for a Deployment. It is derived rather than accepted from users or
// Server configuration so the Agent never joins a container under an
// arbitrary name.
func DeploymentBackendAlias(deploymentID string) (string, error) {
	if !validIdentifier(deploymentID) {
		return "", ErrCommandInvalid
	}
	digest := sha256.Sum256([]byte(deploymentID))
	return "deployment-" + hex.EncodeToString(digest[:12]), nil
}
