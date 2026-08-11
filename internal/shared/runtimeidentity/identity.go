// Package runtimeidentity defines stable names and labels shared by runtime
// writers and readers. These values are a compatibility contract.
package runtimeidentity

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
)

const (
	DeploymentIDLabel    = "net.owndock.deployment_id"
	FencingTokenLabel    = "net.owndock.fencing_token"
	CutoverSequenceLabel = "net.owndock.cutover_sequence"
	ProjectIDLabel       = "net.owndock.project_id"
	ApplicationIDLabel   = "net.owndock.application_id"
	EnvironmentIDLabel   = "net.owndock.environment_id"
)

var ErrInvalidSlot = errors.New("runtime slot identity is invalid")

// ContainerName returns the stable Docker name for one deployment slot. The
// zero-byte separator prevents ambiguous concatenation of adjacent IDs.
func ContainerName(projectID, applicationID, environmentID, runtimeTargetID string) (string, error) {
	values := []string{projectID, applicationID, environmentID, runtimeTargetID}
	for _, value := range values {
		if strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) ||
			len(value) > 160 || strings.ContainsRune(value, '\x00') {
			return "", ErrInvalidSlot
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	return fmt.Sprintf("owndock-%x", sum[:12]), nil
}
