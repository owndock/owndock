package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/managedhost/biz"
	"github.com/owndock/owndock/internal/shared/transaction"
)

type rotationRepositoryStub struct {
	*agentControlRepositoryStub
	rotation biz.AgentCertificateRotation
}

func (r *rotationRepositoryStub) CreateEnrollment(context.Context, biz.Enrollment) error {
	return nil
}

func (r *rotationRepositoryStub) FindAvailableEnrollment(
	context.Context, string, time.Time,
) (biz.Enrollment, error) {
	return biz.Enrollment{}, biz.ErrInvalidEnrollment
}

func (r *rotationRepositoryStub) ActivateAgent(
	context.Context, string, string, time.Time, biz.AgentIdentity,
) error {
	return biz.ErrInvalidEnrollment
}

func (r *rotationRepositoryStub) RotateAgentCertificate(
	_ context.Context,
	rotation biz.AgentCertificateRotation,
	_ time.Time,
) (biz.IssuedCertificate, bool, error) {
	r.rotation = rotation
	return rotation.Certificate, true, nil
}

func (r *rotationRepositoryStub) AuthenticateAgentCertificateRotation(
	ctx context.Context,
	certificate biz.AgentCertificateIdentity,
	_ string,
	_ string,
	now time.Time,
) (biz.AgentIdentity, error) {
	return r.AuthenticateAgent(ctx, certificate, now)
}

type rotationTokensStub struct{}

func (rotationTokensStub) New() (string, string, error) { return "token", "hash", nil }
func (rotationTokensStub) Hash(string) string           { return "hash" }

type rotationIssuerStub struct{}

func (rotationIssuerStub) Issue(
	_ context.Context,
	claim biz.AgentCertificateClaim,
	_ []byte,
	now time.Time,
) (biz.IssuedCertificate, error) {
	return biz.IssuedCertificate{
		CertificatePEM:   []byte("rotated-certificate"),
		CACertificatePEM: []byte("agent-ca"),
		Serial:           "new-serial", SHA256: "new-fingerprint",
		ExpiresAt: now.Add(24 * time.Hour),
	}, nil
}

func TestAgentCertificateRotationHTTPRequiresMTLSAndReturnsNoStoreCredentials(t *testing.T) {
	rawCertificate := []byte("rotation-client-certificate")
	fingerprint := sha256.Sum256(rawCertificate)
	now := time.Now().UTC()
	base := &agentControlRepositoryStub{identity: biz.AgentIdentity{
		ID: "identity-1", OrganizationID: "organization-1",
		ManagedHostID: "host-1", InstanceID: "instance-1",
		CertificateSerial: "2a", CertificateSHA256: hex.EncodeToString(fingerprint[:]),
		CertificateExpires: now.Add(time.Hour),
	}}
	repository := &rotationRepositoryStub{agentControlRepositoryStub: base}
	identifier := 0
	useCase := biz.NewUseCase(
		repository, transaction.Passthrough{}, &agentAuditStub{},
		func() (string, error) {
			identifier++
			return "generated-id", nil
		},
		func() time.Time { return now },
	).WithEnrollment(
		repository, rotationTokensStub{}, rotationIssuerStub{}, time.Minute,
	).WithAgentControl(repository, nil, []string{"v1"})
	handler := NewAgentCertificateRotationHTTP(useCase)
	body := []byte(`{"rotation_id":"rotation-1","csr_pem":"signed-csr"}`)
	request := httptest.NewRequest(
		http.MethodPost, "https://control.example.com/api/v1/agent/certificate:rotate",
		bytes.NewReader(body),
	)
	request.Header.Set("Content-Type", "application/json")
	request.TLS = testAgentTLSState(t, rawCertificate)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated || recorder.Header().Get("Cache-Control") != "no-store" ||
		!bytes.Contains(recorder.Body.Bytes(), []byte("rotated-certificate")) ||
		repository.rotation.ID != "rotation-1" {
		t.Fatalf("status=%d headers=%v body=%s rotation=%+v", recorder.Code, recorder.Header(), recorder.Body.String(), repository.rotation)
	}

	request = httptest.NewRequest(
		http.MethodPost, "https://control.example.com/api/v1/agent/certificate:rotate",
		bytes.NewReader(body),
	)
	request.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("rotation without mTLS status = %d", recorder.Code)
	}
}

var _ biz.AgentCertificateRotationRepository = (*rotationRepositoryStub)(nil)
