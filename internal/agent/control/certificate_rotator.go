package agentcontrol

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maximumRotationResponseBytes = 64 * 1024

type ReconnectRequester interface {
	Reconnect()
}

type CertificateRotatorConfig struct {
	ControlEndpoint string
	IdentityBundle  string
	CACertificate   string
	Identity        Identity
	RenewBefore     time.Duration
	RetryDelay      time.Duration
	RequestTimeout  time.Duration
}

type CertificateRotator struct {
	httpClient *http.Client
	reconnect  ReconnectRequester
	config     CertificateRotatorConfig
	now        func() time.Time
}

type pendingCertificateRotation struct {
	RotationID    string `json:"rotation_id"`
	CSRPEM        []byte `json:"csr_pem"`
	PrivateKeyPEM []byte `json:"private_key_pem"`
}

func NewCertificateRotator(
	httpClient *http.Client,
	reconnect ReconnectRequester,
	config CertificateRotatorConfig,
) (*CertificateRotator, error) {
	endpoint, err := url.Parse(strings.TrimSpace(config.ControlEndpoint))
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" ||
		endpoint.Path != "/api/v1/agent/connect" || endpoint.RawQuery != "" ||
		endpoint.Fragment != "" || reconnect == nil || httpClient == nil ||
		config.RenewBefore <= 0 || config.RetryDelay <= 0 ||
		config.RequestTimeout <= 0 || !filepath.IsAbs(config.IdentityBundle) ||
		!filepath.IsAbs(config.CACertificate) || !validBundleIdentity(config.Identity) {
		return nil, ErrConfigurationInvalid
	}
	endpoint.Path = "/api/v1/agent/certificate:rotate"
	config.ControlEndpoint = endpoint.String()
	return &CertificateRotator{
		httpClient: httpClient, reconnect: reconnect, config: config,
		now: time.Now,
	}, nil
}

func (r *CertificateRotator) Run(ctx context.Context) error {
	for {
		now := r.now().UTC()
		certificate, err := loadClientCertificate(
			r.config.IdentityBundle, r.config.IdentityBundle, now,
		)
		if err != nil || certificate.Leaf == nil {
			return fmt.Errorf("load Agent identity for rotation: %w", err)
		}
		delay := certificate.Leaf.NotAfter.Sub(now) - r.config.RenewBefore
		if delay > 0 {
			if !waitForReconnect(ctx, delay) {
				return nil
			}
		}
		requestContext, cancel := context.WithTimeout(ctx, r.config.RequestTimeout)
		err = r.RotateNow(requestContext)
		cancel()
		if err == nil {
			continue
		}
		if IsPermanent(err) {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
		if !waitForReconnect(ctx, r.config.RetryDelay) {
			return nil
		}
	}
}

func (r *CertificateRotator) RecoverPending(ctx context.Context) error {
	_, err := os.Lstat(r.pendingPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect pending Agent rotation: %w", err)
	}
	requestContext, cancel := context.WithTimeout(ctx, r.config.RequestTimeout)
	defer cancel()
	return r.RotateNow(requestContext)
}

func (r *CertificateRotator) RotateNow(ctx context.Context) error {
	pending, err := r.loadOrCreatePending()
	if err != nil {
		return err
	}
	defer clearTLSBytes(pending.PrivateKeyPEM)
	body, err := json.Marshal(struct {
		RotationID string `json:"rotation_id"`
		CSRPEM     string `json:"csr_pem"`
	}{RotationID: pending.RotationID, CSRPEM: string(pending.CSRPEM)})
	if err != nil {
		return ErrConfigurationInvalid
	}
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, r.config.ControlEndpoint, bytes.NewReader(body),
	)
	if err != nil {
		return ErrConfigurationInvalid
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := r.httpClient.Do(request)
	if err != nil {
		return ErrConnectionUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		if response.StatusCode >= 400 && response.StatusCode < 500 {
			return &PermanentError{Code: "certificate_rotation_rejected"}
		}
		return ErrConnectionUnavailable
	}
	var result struct {
		AgentIdentityID      string    `json:"agent_identity_id"`
		ManagedHostID        string    `json:"managed_host_id"`
		RotationID           string    `json:"rotation_id"`
		CertificatePEM       string    `json:"certificate_pem"`
		CACertificatePEM     string    `json:"ca_certificate_pem"`
		CertificateExpiresAt time.Time `json:"certificate_expires_at"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maximumRotationResponseBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return ErrProtocolViolation
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) ||
		result.AgentIdentityID != r.config.Identity.IdentityID ||
		result.ManagedHostID != r.config.Identity.ManagedHostID ||
		result.RotationID != pending.RotationID || !result.CertificateExpiresAt.After(r.now()) {
		return ErrProtocolViolation
	}
	localCA, err := readBoundedTLSFile(r.config.CACertificate)
	if err != nil {
		return fmt.Errorf("read Agent CA for rotation: %w", err)
	}
	if err := InstallClientIdentityBundle(
		r.config.IdentityBundle,
		[]byte(result.CertificatePEM), pending.PrivateKeyPEM, localCA,
		r.config.Identity, r.now().UTC(),
	); err != nil {
		return err
	}
	if err := r.removePending(); err != nil {
		return err
	}
	r.reconnect.Reconnect()
	return nil
}

func (r *CertificateRotator) pendingPath() string {
	return r.config.IdentityBundle + ".rotation-pending"
}

func (r *CertificateRotator) loadOrCreatePending() (pendingCertificateRotation, error) {
	path := r.pendingPath()
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm()&0o077 != 0 {
			return pendingCertificateRotation{}, ErrConfigurationInvalid
		}
		value, readErr := readBoundedTLSFile(path)
		if readErr != nil {
			return pendingCertificateRotation{}, readErr
		}
		defer clearTLSBytes(value)
		var pending pendingCertificateRotation
		decoder := json.NewDecoder(bytes.NewReader(value))
		decoder.DisallowUnknownFields()
		if decodeErr := decoder.Decode(&pending); decodeErr != nil {
			return pendingCertificateRotation{}, ErrConfigurationInvalid
		}
		if decodeErr := decoder.Decode(&struct{}{}); !errors.Is(decodeErr, io.EOF) ||
			!validPendingRotation(pending) {
			return pendingCertificateRotation{}, ErrConfigurationInvalid
		}
		return pending, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return pendingCertificateRotation{}, fmt.Errorf("inspect pending Agent rotation: %w", err)
	}
	rotationID, err := newRotationID()
	if err != nil {
		return pendingCertificateRotation{}, err
	}
	rotation, err := NewCertificateRotationRequest(r.config.Identity)
	if err != nil {
		return pendingCertificateRotation{}, err
	}
	defer clearTLSBytes(rotation.PrivateKeyPEM)
	pending := pendingCertificateRotation{
		RotationID: rotationID, CSRPEM: append([]byte(nil), rotation.CSRPEM...),
		PrivateKeyPEM: append([]byte(nil), rotation.PrivateKeyPEM...),
	}
	encoded, err := json.Marshal(pending)
	if err != nil {
		return pendingCertificateRotation{}, ErrConfigurationInvalid
	}
	defer clearTLSBytes(encoded)
	if err := replaceIdentityBundle(path, encoded); err != nil {
		return pendingCertificateRotation{}, err
	}
	return pending, nil
}

func validPendingRotation(pending pendingCertificateRotation) bool {
	if pending.RotationID == "" || len(pending.RotationID) > 128 ||
		len(pending.CSRPEM) == 0 || len(pending.PrivateKeyPEM) == 0 {
		return false
	}
	csrBlock, csrRest := pem.Decode(pending.CSRPEM)
	keyBlock, keyRest := pem.Decode(pending.PrivateKeyPEM)
	if csrBlock == nil || csrBlock.Type != "CERTIFICATE REQUEST" ||
		len(bytes.TrimSpace(csrRest)) != 0 || keyBlock == nil ||
		keyBlock.Type != "PRIVATE KEY" || len(bytes.TrimSpace(keyRest)) != 0 {
		return false
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return false
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return false
	}
	publicKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return false
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return false
	}
	privatePublicKey, err := x509.MarshalPKIXPublicKey(signer.Public())
	return err == nil && bytes.Equal(publicKey, privatePublicKey)
}

func (r *CertificateRotator) removePending() error {
	if err := os.Remove(r.pendingPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove pending Agent rotation: %w", err)
	}
	directory, err := os.Open(filepath.Dir(r.pendingPath()))
	if err != nil {
		return fmt.Errorf("open Agent identity directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync Agent identity directory: %w", err)
	}
	return nil
}

func newRotationID() (string, error) {
	value := make([]byte, 24)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate Agent rotation ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
