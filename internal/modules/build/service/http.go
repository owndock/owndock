package service

import (
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/modules/build/biz"
	"github.com/owndock/owndock/internal/platform/httpx"
	"github.com/owndock/owndock/internal/shared/runtimespec"
	"github.com/owndock/owndock/internal/shared/security"
)

type HTTP struct {
	useCase             *biz.UseCase
	webhookMaxBodyBytes int64
}

func NewHTTP(useCase *biz.UseCase) *HTTP {
	return &HTTP{useCase: useCase, webhookMaxBodyBytes: 1024 * 1024}
}

func (s *HTTP) WithWebhookMaxBodyBytes(value int64) *HTTP {
	if value > 0 {
		s.webhookMaxBodyBytes = value
	}
	return s
}

func (s *HTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(segments) == 5 && segments[0] == "api" && segments[1] == "v1" &&
		segments[2] == "build-hooks" && segments[3] != "" && segments[4] != "" {
		s.webhook(w, r, biz.WebhookProvider(segments[3]), segments[4])
		return
	}
	if len(segments) == 4 && segments[0] == "api" && segments[1] == "v1" &&
		segments[2] == "build-triggers" && segments[3] != "" {
		s.externalBuildTrigger(w, r, segments[3])
		return
	}
	principal, ok := security.PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, r, security.ErrUnauthenticated)
		return
	}
	if len(segments) < 5 || len(segments) > 10 || segments[0] != "api" ||
		segments[1] != "v1" || segments[2] != "projects" || segments[3] == "" {
		httpx.ErrorRequest(w, r, http.StatusNotFound, "not_found")
		return
	}
	projectID := segments[3]
	switch {
	case len(segments) == 5 && segments[4] == "repository-credentials":
		s.credentials(w, r, principal, projectID)
	case len(segments) == 5 && segments[4] == "source-repositories":
		s.sources(w, r, principal, projectID)
	case len(segments) == 6 && segments[4] == "source-repositories" && segments[5] != "":
		s.source(w, r, principal, projectID, segments[5])
	case len(segments) == 7 && segments[4] == "source-repositories" &&
		segments[5] != "" && segments[6] == "probe":
		s.probeSource(w, r, principal, projectID, segments[5])
	case len(segments) == 7 && segments[4] == "applications" &&
		segments[5] != "" && segments[6] == "build-configurations":
		s.buildConfigurations(w, r, principal, projectID, segments[5])
	case len(segments) == 8 && segments[4] == "applications" &&
		segments[5] != "" && segments[6] == "build-configurations" && segments[7] != "":
		s.buildConfiguration(w, r, principal, projectID, segments[5], segments[7])
	case len(segments) == 9 && segments[4] == "applications" && segments[5] != "" &&
		segments[6] == "build-configurations" && segments[7] != "" && segments[8] == "triggers":
		s.buildTriggers(w, r, principal, projectID, segments[5], segments[7])
	case len(segments) == 10 && segments[4] == "applications" && segments[5] != "" &&
		segments[6] == "build-configurations" && segments[7] != "" && segments[8] == "triggers" &&
		strings.HasSuffix(segments[9], ":revoke"):
		s.revokeBuildTrigger(w, r, principal, projectID, segments[5], segments[7], strings.TrimSuffix(segments[9], ":revoke"))
	case len(segments) == 9 && segments[4] == "applications" && segments[5] != "" &&
		segments[6] == "build-configurations" && segments[7] != "" && segments[8] == "hooks":
		s.buildHooks(w, r, principal, projectID, segments[5], segments[7])
	case len(segments) == 10 && segments[4] == "applications" && segments[5] != "" &&
		segments[6] == "build-configurations" && segments[7] != "" && segments[8] == "hooks" && strings.HasSuffix(segments[9], ":revoke"):
		s.revokeBuildHook(w, r, principal, projectID, segments[5], segments[7], strings.TrimSuffix(segments[9], ":revoke"))
	case len(segments) == 5 && segments[4] == "builds":
		s.builds(w, r, principal, projectID)
	case len(segments) == 6 && segments[4] == "builds" && strings.HasSuffix(segments[5], ":cancel"):
		s.cancelBuild(w, r, principal, projectID, strings.TrimSuffix(segments[5], ":cancel"))
	case len(segments) == 6 && segments[4] == "builds" && strings.HasSuffix(segments[5], ":retry"):
		s.retryBuild(w, r, principal, projectID, strings.TrimSuffix(segments[5], ":retry"))
	case len(segments) == 6 && segments[4] == "builds" && segments[5] != "":
		s.build(w, r, principal, projectID, segments[5])
	case len(segments) == 7 && segments[4] == "builds" && segments[5] != "" && segments[6] == "logs":
		s.buildLogs(w, r, principal, projectID, segments[5])
	case len(segments) == 5 && segments[4] == "artifacts":
		s.artifacts(w, r, principal, projectID)
	case len(segments) == 6 && segments[4] == "artifacts" && strings.HasSuffix(segments[5], ":create-release"):
		s.createArtifactRelease(w, r, principal, projectID, strings.TrimSuffix(segments[5], ":create-release"))
	case len(segments) == 6 && segments[4] == "artifacts" && segments[5] != "":
		s.artifact(w, r, principal, projectID, segments[5])
	default:
		httpx.ErrorRequest(w, r, http.StatusNotFound, "not_found")
	}
}

func (s *HTTP) buildLogs(w http.ResponseWriter, r *http.Request, principal security.Principal,
	projectID, buildID string) {
	if r.Method != http.MethodGet {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	values := r.URL.Query()
	for name, entries := range values {
		if (name != "cursor" && name != "limit") || len(entries) != 1 {
			httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_build_log_query")
			return
		}
	}
	after, err := decodeBuildLogCursor(buildID, values.Get("cursor"))
	if err != nil {
		httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_build_log_query")
		return
	}
	limit := 0
	if rawLimit := strings.TrimSpace(values.Get("limit")); rawLimit != "" {
		limit, err = strconv.Atoi(rawLimit)
		if err != nil {
			httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_build_log_query")
			return
		}
	}
	page, err := s.useCase.ReadBuildLogs(r.Context(), principal, projectID, buildID,
		biz.BuildLogQuery{AfterSequence: after, Limit: limit})
	if writeError(w, r, err) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.JSON(w, http.StatusOK, buildLogPageResponseFromDomain(buildID, page))
}

func (s *HTTP) artifacts(w http.ResponseWriter, r *http.Request, principal security.Principal, projectID string) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.useCase.ListArtifacts(r.Context(), principal, projectID)
		if writeError(w, r, err) {
			return
		}
		responses := make([]artifactResponse, len(items))
		for index, item := range items {
			responses[index] = artifactResponseFromDomain(item)
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"items": responses})
	case http.MethodPost:
		var request registerExternalArtifactRequest
		if !decodeRequest(w, r, &request) {
			return
		}
		item, err := s.useCase.RegisterExternalArtifact(r.Context(), principal, projectID,
			biz.ExternalArtifactInput{
				ApplicationID: request.ApplicationID, RegistryCredentialID: request.RegistryCredentialID,
				ImageDigest: request.ImageDigest, TargetPlatform: request.TargetPlatform,
				Producer: request.Producer, RegistrationKey: r.Header.Get("Idempotency-Key"),
				ReleaseRuntimeSpec: request.ReleaseRuntimeSpec.domain(),
			}, httpx.RequestIDFromContext(r.Context()))
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusCreated, artifactResponseFromDomain(item))
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *HTTP) artifact(w http.ResponseWriter, r *http.Request, principal security.Principal, projectID, artifactID string) {
	if r.Method != http.MethodGet {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	item, err := s.useCase.GetArtifact(r.Context(), principal, projectID, artifactID)
	if writeError(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, artifactResponseFromDomain(item))
}

func (s *HTTP) createArtifactRelease(w http.ResponseWriter, r *http.Request, principal security.Principal, projectID, artifactID string) {
	if r.Method != http.MethodPost {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	var request createArtifactReleaseRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	item, err := s.useCase.CreateReleaseFromArtifact(
		r.Context(), principal, projectID, artifactID,
		request.RuntimeSpec.domain(), httpx.RequestIDFromContext(r.Context()),
	)
	if writeError(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusCreated, artifactResponseFromDomain(item))
}

func (s *HTTP) cancelBuild(w http.ResponseWriter, r *http.Request, principal security.Principal, projectID, buildID string) {
	if r.Method != http.MethodPost {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	item, err := s.useCase.CancelBuild(r.Context(), principal, projectID, buildID, httpx.RequestIDFromContext(r.Context()))
	if writeError(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusAccepted, buildResponseFromDomain(item))
}

func (s *HTTP) retryBuild(w http.ResponseWriter, r *http.Request, principal security.Principal, projectID, buildID string) {
	if r.Method != http.MethodPost {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	var request retryBuildRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	item, err := s.useCase.RetryBuild(r.Context(), principal, projectID, buildID, request.IdempotencyKey, httpx.RequestIDFromContext(r.Context()))
	if writeError(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusAccepted, buildResponseFromDomain(item))
}

func (s *HTTP) webhook(w http.ResponseWriter, r *http.Request, provider biz.WebhookProvider, hookID string) {
	if r.Method != http.MethodPost {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		httpx.ErrorRequest(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.webhookMaxBodyBytes))
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			httpx.ErrorRequest(w, r, http.StatusRequestEntityTooLarge, "webhook_payload_too_large")
		} else {
			httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_webhook")
		}
		return
	}
	envelope := webhookEnvelope(provider, r, body)
	receipt, err := s.useCase.HandleWebhook(r.Context(), provider, hookID, envelope, httpx.RequestIDFromContext(r.Context()))
	if writeError(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusAccepted, webhookReceiptResponse{Status: receipt.Status, BuildID: receipt.BuildID})
}

func webhookEnvelope(provider biz.WebhookProvider, r *http.Request, body []byte) biz.WebhookEnvelope {
	envelope := biz.WebhookEnvelope{Body: body}
	switch provider {
	case biz.WebhookProviderGitHub:
		envelope.DeliveryID, envelope.Event = r.Header.Get("X-GitHub-Delivery"), r.Header.Get("X-GitHub-Event")
		envelope.Signature = r.Header.Get("X-Hub-Signature-256")
	case biz.WebhookProviderGitLab:
		envelope.DeliveryID, envelope.Event = r.Header.Get("Webhook-Id"), r.Header.Get("X-Gitlab-Event")
		envelope.Signature, envelope.Timestamp = r.Header.Get("Webhook-Signature"), r.Header.Get("Webhook-Timestamp")
	case biz.WebhookProviderGitea:
		envelope.DeliveryID, envelope.Event = r.Header.Get("X-Gitea-Delivery"), r.Header.Get("X-Gitea-Event")
		envelope.Signature = r.Header.Get("X-Gitea-Signature")
	case biz.WebhookProviderForgejo:
		envelope.DeliveryID, envelope.Event = r.Header.Get("X-Forgejo-Delivery"), r.Header.Get("X-Forgejo-Event")
		envelope.Signature = r.Header.Get("X-Forgejo-Signature")
	}
	return envelope
}

func (s *HTTP) buildHooks(w http.ResponseWriter, r *http.Request, principal security.Principal, projectID, applicationID, configurationID string) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.useCase.ListBuildHooks(r.Context(), principal, projectID, applicationID, configurationID)
		if writeError(w, r, err) {
			return
		}
		responses := make([]buildHookResponse, len(items))
		for index, item := range items {
			responses[index] = buildHookResponseFromDomain(item)
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"items": responses})
	case http.MethodPost:
		var request createBuildHookRequest
		if !decodeRequest(w, r, &request) {
			return
		}
		item, err := s.useCase.CreateBuildHook(r.Context(), principal, projectID, applicationID, configurationID,
			request.Name, request.Provider, request.AllowedRefs, request.SecretRef, httpx.RequestIDFromContext(r.Context()))
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusCreated, buildHookResponseFromDomain(item))
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *HTTP) revokeBuildHook(w http.ResponseWriter, r *http.Request, principal security.Principal,
	projectID, applicationID, configurationID, hookID string) {
	if r.Method != http.MethodPost {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	item, err := s.useCase.RevokeBuildHook(r.Context(), principal, projectID, applicationID, configurationID, hookID, httpx.RequestIDFromContext(r.Context()))
	if writeError(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, buildHookResponseFromDomain(item))
}

func (s *HTTP) externalBuildTrigger(w http.ResponseWriter, r *http.Request, triggerID string) {
	if r.Method != http.MethodPost {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	parts := strings.SplitN(authorization, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
		writeError(w, r, biz.ErrInvalidBuildTriggerToken)
		return
	}
	var request externalBuildTriggerRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	item, err := s.useCase.TriggerExternalBuild(r.Context(), triggerID, strings.TrimSpace(parts[1]),
		request.Ref, request.CommitSHA, r.Header.Get("Idempotency-Key"),
		httpx.RequestIDFromContext(r.Context()))
	if writeError(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusAccepted, buildResponseFromDomain(item))
}

func (s *HTTP) buildTriggers(w http.ResponseWriter, r *http.Request, principal security.Principal,
	projectID, applicationID, configurationID string) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.useCase.ListBuildTriggers(r.Context(), principal, projectID, applicationID, configurationID)
		if writeError(w, r, err) {
			return
		}
		responses := make([]buildTriggerResponse, len(items))
		for index, item := range items {
			responses[index] = buildTriggerResponseFromDomain(item)
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"items": responses})
	case http.MethodPost:
		var request createBuildTriggerRequest
		if !decodeRequest(w, r, &request) {
			return
		}
		credential, err := s.useCase.CreateBuildTrigger(r.Context(), principal, projectID, applicationID,
			configurationID, request.Name, request.AllowedRefs, httpx.RequestIDFromContext(r.Context()))
		if writeError(w, r, err) {
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		response := buildTriggerCredentialResponse{
			BuildTrigger: buildTriggerResponseFromDomain(credential.Trigger), Token: credential.Token,
		}
		httpx.JSON(w, http.StatusCreated, response)
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *HTTP) revokeBuildTrigger(w http.ResponseWriter, r *http.Request, principal security.Principal,
	projectID, applicationID, configurationID, triggerID string) {
	if r.Method != http.MethodPost {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	item, err := s.useCase.RevokeBuildTrigger(r.Context(), principal, projectID, applicationID,
		configurationID, triggerID, httpx.RequestIDFromContext(r.Context()))
	if writeError(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, buildTriggerResponseFromDomain(item))
}

func (s *HTTP) builds(
	w http.ResponseWriter,
	r *http.Request,
	principal security.Principal,
	projectID string,
) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.useCase.ListBuilds(r.Context(), principal, projectID)
		if writeError(w, r, err) {
			return
		}
		responses := make([]buildResponse, len(items))
		for index, item := range items {
			responses[index] = buildResponseFromDomain(item)
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"items": responses})
	case http.MethodPost:
		var request triggerManualBuildRequest
		if !decodeRequest(w, r, &request) {
			return
		}
		item, err := s.useCase.TriggerManualBuild(
			r.Context(), principal, projectID,
			request.ApplicationID, request.BuildConfigurationID,
			request.Ref, request.ExpectedCommitSHA, request.IdempotencyKey,
			httpx.RequestIDFromContext(r.Context()),
		)
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusAccepted, buildResponseFromDomain(item))
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *HTTP) build(
	w http.ResponseWriter,
	r *http.Request,
	principal security.Principal,
	projectID, buildID string,
) {
	if r.Method != http.MethodGet {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	item, err := s.useCase.GetBuild(r.Context(), principal, projectID, buildID)
	if writeError(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, buildResponseFromDomain(item))
}

func (s *HTTP) buildConfigurations(
	w http.ResponseWriter,
	r *http.Request,
	principal security.Principal,
	projectID, applicationID string,
) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.useCase.ListBuildConfigurations(
			r.Context(), principal, projectID, applicationID,
		)
		if writeError(w, r, err) {
			return
		}
		responses := make([]buildConfigurationResponse, len(items))
		for index, item := range items {
			responses[index] = buildConfigurationResponseFromDomain(item)
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"items": responses})
	case http.MethodPost:
		var request createBuildConfigurationRequest
		if !decodeRequest(w, r, &request) {
			return
		}
		item, err := s.useCase.CreateBuildConfigurationWithDeliverySpec(
			r.Context(), principal, projectID, applicationID,
			request.Name, request.SourceRepositoryID,
			request.DockerfilePath, request.ContextPath, request.AllowedRefs,
			request.RegistryCredentialID, request.ImageRepository,
			request.TargetPlatform, request.Resources.domain(),
			request.TimeoutSeconds, request.MaxConcurrency,
			request.autoCreateRelease(), request.ReleaseRuntimeSpec.domain(),
			automaticDeploymentPayloadsDomain(request.AutomaticDeployments),
			httpx.RequestIDFromContext(r.Context()),
		)
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusCreated, buildConfigurationResponseFromDomain(item))
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *HTTP) buildConfiguration(
	w http.ResponseWriter,
	r *http.Request,
	principal security.Principal,
	projectID, applicationID, configurationID string,
) {
	switch r.Method {
	case http.MethodGet:
		item, err := s.useCase.GetBuildConfiguration(
			r.Context(), principal, projectID, applicationID, configurationID,
		)
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusOK, buildConfigurationResponseFromDomain(item))
	case http.MethodPatch:
		var request patchBuildConfigurationRequest
		if !decodeRequest(w, r, &request) {
			return
		}
		item, err := s.useCase.UpdateBuildConfiguration(
			r.Context(), principal, projectID, applicationID, configurationID,
			request.ExpectedVersion, request.domain(),
			httpx.RequestIDFromContext(r.Context()),
		)
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusOK, buildConfigurationResponseFromDomain(item))
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *HTTP) probeSource(
	w http.ResponseWriter,
	r *http.Request,
	principal security.Principal,
	projectID, sourceID string,
) {
	if r.Method != http.MethodPost {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	item, err := s.useCase.ProbeSource(
		r.Context(), principal, projectID, sourceID,
		httpx.RequestIDFromContext(r.Context()),
	)
	if writeError(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, sourceResponseFromDomain(item))
}

func (s *HTTP) credentials(
	w http.ResponseWriter,
	r *http.Request,
	principal security.Principal,
	projectID string,
) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.useCase.ListCredentials(r.Context(), principal, projectID)
		if writeError(w, r, err) {
			return
		}
		responses := make([]credentialResponse, len(items))
		for index, item := range items {
			responses[index] = credentialResponseFromDomain(item)
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"items": responses})
	case http.MethodPost:
		var request struct {
			Name                 string             `json:"name"`
			Type                 biz.CredentialType `json:"type"`
			Username             string             `json:"username"`
			SecretRef            string             `json:"secret_ref"`
			PublicKeyFingerprint string             `json:"public_key_fingerprint"`
		}
		if !decodeRequest(w, r, &request) {
			return
		}
		item, err := s.useCase.CreateCredential(
			r.Context(), principal, projectID, request.Name, request.Type,
			request.Username, request.SecretRef, request.PublicKeyFingerprint,
			httpx.RequestIDFromContext(r.Context()),
		)
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusCreated, credentialResponseFromDomain(item))
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *HTTP) sources(
	w http.ResponseWriter,
	r *http.Request,
	principal security.Principal,
	projectID string,
) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.useCase.ListSources(r.Context(), principal, projectID)
		if writeError(w, r, err) {
			return
		}
		responses := make([]sourceResponse, len(items))
		for index, item := range items {
			responses[index] = sourceResponseFromDomain(item)
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"items": responses})
	case http.MethodPost:
		var request struct {
			Name                  string `json:"name"`
			RepositoryURL         string `json:"repository_url"`
			DefaultBranch         string `json:"default_branch"`
			CredentialID          string `json:"credential_id"`
			SSHHostKeyFingerprint string `json:"ssh_host_key_fingerprint"`
		}
		if !decodeRequest(w, r, &request) {
			return
		}
		item, err := s.useCase.CreateSource(
			r.Context(), principal, projectID, request.Name, request.RepositoryURL,
			request.DefaultBranch, request.CredentialID,
			request.SSHHostKeyFingerprint,
			httpx.RequestIDFromContext(r.Context()),
		)
		if writeError(w, r, err) {
			return
		}
		httpx.JSON(w, http.StatusCreated, sourceResponseFromDomain(item))
	default:
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

func (s *HTTP) source(
	w http.ResponseWriter,
	r *http.Request,
	principal security.Principal,
	projectID, sourceID string,
) {
	if r.Method != http.MethodGet {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	item, err := s.useCase.GetSource(r.Context(), principal, projectID, sourceID)
	if writeError(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, sourceResponseFromDomain(item))
}

func decodeRequest(w http.ResponseWriter, r *http.Request, target any) bool {
	if err := httpx.DecodeJSON(w, r, target); errors.Is(err, httpx.ErrUnsupportedMediaType) {
		httpx.ErrorRequest(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return false
	} else if err != nil {
		httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_json")
		return false
	}
	return true
}

func writeError(w http.ResponseWriter, r *http.Request, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, security.ErrUnauthenticated):
		w.Header().Set("WWW-Authenticate", "Bearer")
		httpx.ErrorRequest(w, r, http.StatusUnauthorized, "unauthenticated")
	case errors.Is(err, security.ErrForbidden):
		httpx.ErrorRequest(w, r, http.StatusForbidden, "forbidden")
	case errors.Is(err, biz.ErrNotFound):
		httpx.ErrorRequest(w, r, http.StatusNotFound, "not_found")
	case errors.Is(err, biz.ErrDuplicateName):
		httpx.ErrorRequest(w, r, http.StatusConflict, "name_conflict")
	case errors.Is(err, biz.ErrInvalidCredential):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_repository_credential")
	case errors.Is(err, biz.ErrInvalidSourceRepository):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_source_repository")
	case errors.Is(err, biz.ErrCredentialProtocolMismatch):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "repository_credential_protocol_mismatch")
	case errors.Is(err, biz.ErrSourceProbeUnavailable):
		httpx.ErrorRequest(w, r, http.StatusServiceUnavailable, "source_repository_probe_unavailable")
	case errors.Is(err, biz.ErrInvalidBuildConfiguration):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_build_configuration")
	case errors.Is(err, biz.ErrAutomaticDeploymentDenied):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "automatic_deployment_not_allowed")
	case errors.Is(err, biz.ErrRegistryMismatch):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "registry_credential_mismatch")
	case errors.Is(err, biz.ErrVersionConflict):
		httpx.ErrorRequest(w, r, http.StatusConflict, "version_conflict")
	case errors.Is(err, biz.ErrInvalidBuild):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_build")
	case errors.Is(err, biz.ErrInvalidArtifact):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_artifact")
	case errors.Is(err, biz.ErrArtifactAlreadyReleased), errors.Is(err, biz.ErrDuplicateArtifact):
		httpx.ErrorRequest(w, r, http.StatusConflict, "artifact_conflict")
	case errors.Is(err, biz.ErrArtifactReleaseUnavailable):
		httpx.ErrorRequest(w, r, http.StatusServiceUnavailable, "artifact_release_unavailable")
	case errors.Is(err, biz.ErrArtifactRegistrationUnavailable):
		httpx.ErrorRequest(w, r, http.StatusServiceUnavailable, "external_artifact_registration_unavailable")
	case errors.Is(err, biz.ErrArtifactRegistryAuthentication):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "artifact_registry_authentication_failed")
	case errors.Is(err, biz.ErrArtifactRegistryUnavailable):
		httpx.ErrorRequest(w, r, http.StatusServiceUnavailable, "artifact_registry_unavailable")
	case errors.Is(err, biz.ErrArtifactRegistryIntegrity):
		httpx.ErrorRequest(w, r, http.StatusBadGateway, "artifact_registry_integrity_failed")
	case errors.Is(err, biz.ErrInvalidBuildTransition), errors.Is(err, biz.ErrBuildRetryRequiresFailed):
		httpx.ErrorRequest(w, r, http.StatusConflict, "invalid_build_state")
	case errors.Is(err, biz.ErrRevisionNotFound):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "revision_not_found")
	case errors.Is(err, biz.ErrRevisionMismatch):
		httpx.ErrorRequest(w, r, http.StatusConflict, "revision_mismatch")
	case errors.Is(err, biz.ErrRevisionResolveUnavailable):
		httpx.ErrorRequest(w, r, http.StatusServiceUnavailable, "source_revision_unavailable")
	case errors.Is(err, biz.ErrDuplicateIdempotency), errors.Is(err, biz.ErrIdempotencyMismatch):
		httpx.ErrorRequest(w, r, http.StatusConflict, "idempotency_key_mismatch")
	case errors.Is(err, biz.ErrInvalidBuildTrigger):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_build_trigger")
	case errors.Is(err, biz.ErrInvalidBuildTriggerToken), errors.Is(err, biz.ErrBuildTriggerRevoked):
		w.Header().Set("WWW-Authenticate", "Bearer")
		httpx.ErrorRequest(w, r, http.StatusUnauthorized, "invalid_build_trigger_token")
	case errors.Is(err, biz.ErrBuildTriggerRateLimited):
		var rateLimit *biz.BuildTriggerRateLimitError
		if errors.As(err, &rateLimit) {
			seconds := int64((rateLimit.RetryAfter + time.Second - 1) / time.Second)
			w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
		}
		httpx.ErrorRequest(w, r, http.StatusTooManyRequests, "build_trigger_rate_limited")
	case errors.Is(err, biz.ErrWebhookRateLimited):
		var rateLimit *biz.WebhookRateLimitError
		if errors.As(err, &rateLimit) {
			seconds := int64((rateLimit.RetryAfter + time.Second - 1) / time.Second)
			w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
		}
		httpx.ErrorRequest(w, r, http.StatusTooManyRequests, "webhook_rate_limited")
	case errors.Is(err, biz.ErrInvalidBuildHook):
		httpx.ErrorRequest(w, r, http.StatusUnprocessableEntity, "invalid_build_hook")
	case errors.Is(err, biz.ErrInvalidBuildLogQuery), errors.Is(err, biz.ErrInvalidBuildLog):
		httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_build_log_query")
	case errors.Is(err, biz.ErrBuildLogsUnavailable):
		httpx.ErrorRequest(w, r, http.StatusServiceUnavailable, "build_logs_unavailable")
	case errors.Is(err, biz.ErrInvalidWebhookSignature):
		httpx.ErrorRequest(w, r, http.StatusUnauthorized, "invalid_webhook_signature")
	case errors.Is(err, biz.ErrInvalidWebhook):
		httpx.ErrorRequest(w, r, http.StatusBadRequest, "invalid_webhook")
	case errors.Is(err, biz.ErrWebhookSecretUnavailable):
		httpx.ErrorRequest(w, r, http.StatusServiceUnavailable, "webhook_secret_unavailable")
	default:
		httpx.ErrorRequest(w, r, http.StatusInternalServerError, "internal_error")
	}
	return true
}

type triggerManualBuildRequest struct {
	ApplicationID        string `json:"application_id"`
	BuildConfigurationID string `json:"build_configuration_id"`
	Ref                  string `json:"ref"`
	ExpectedCommitSHA    string `json:"expected_commit_sha"`
	IdempotencyKey       string `json:"idempotency_key"`
}

type retryBuildRequest struct {
	IdempotencyKey string `json:"idempotency_key"`
}

type createArtifactReleaseRequest struct {
	RuntimeSpec artifactRuntimeSpecPayload `json:"runtime_spec"`
}

type artifactRuntimeSpecPayload struct {
	Ports           []artifactRuntimePortPayload `json:"ports"`
	EnvironmentKeys []string                     `json:"environment_keys"`
	Resources       artifactRuntimeResources     `json:"resources"`
	HealthCheck     *artifactHealthCheckPayload  `json:"health_check,omitempty"`
}

type artifactRuntimePortPayload struct {
	Name          string `json:"name"`
	ContainerPort uint16 `json:"container_port"`
	Protocol      string `json:"protocol"`
}

type artifactRuntimeResources struct {
	CPUMilli    int64 `json:"cpu_milli"`
	MemoryBytes int64 `json:"memory_bytes"`
}

type artifactHealthCheckPayload struct {
	Command            []string `json:"command"`
	IntervalSeconds    int      `json:"interval_seconds"`
	TimeoutSeconds     int      `json:"timeout_seconds"`
	Retries            int      `json:"retries"`
	StartPeriodSeconds int      `json:"start_period_seconds"`
}

func (p artifactRuntimeSpecPayload) domain() runtimespec.Spec {
	ports := make([]runtimespec.Port, len(p.Ports))
	for index, port := range p.Ports {
		ports[index] = runtimespec.Port{Name: port.Name, ContainerPort: port.ContainerPort, Protocol: port.Protocol}
	}
	result := runtimespec.Spec{
		Ports: ports, EnvironmentKeys: append([]string(nil), p.EnvironmentKeys...),
		Resources: runtimespec.Resources{CPUMilli: p.Resources.CPUMilli, MemoryBytes: p.Resources.MemoryBytes},
	}
	if p.HealthCheck != nil {
		result.HealthCheck = &runtimespec.HealthCheck{
			Command:         append([]string(nil), p.HealthCheck.Command...),
			IntervalSeconds: p.HealthCheck.IntervalSeconds, TimeoutSeconds: p.HealthCheck.TimeoutSeconds,
			Retries: p.HealthCheck.Retries, StartPeriodSeconds: p.HealthCheck.StartPeriodSeconds,
		}
	}
	return result
}

func artifactRuntimeSpecPayloadFromDomain(spec runtimespec.Spec) artifactRuntimeSpecPayload {
	if normalized, err := runtimespec.Normalize(spec); err == nil {
		spec = normalized
	}
	ports := make([]artifactRuntimePortPayload, len(spec.Ports))
	for index, port := range spec.Ports {
		ports[index] = artifactRuntimePortPayload{
			Name: port.Name, ContainerPort: port.ContainerPort, Protocol: port.Protocol,
		}
	}
	result := artifactRuntimeSpecPayload{
		Ports:           ports,
		EnvironmentKeys: append([]string{}, spec.EnvironmentKeys...),
		Resources: artifactRuntimeResources{
			CPUMilli: spec.Resources.CPUMilli, MemoryBytes: spec.Resources.MemoryBytes,
		},
	}
	if spec.HealthCheck != nil {
		result.HealthCheck = &artifactHealthCheckPayload{
			Command:            append([]string(nil), spec.HealthCheck.Command...),
			IntervalSeconds:    spec.HealthCheck.IntervalSeconds,
			TimeoutSeconds:     spec.HealthCheck.TimeoutSeconds,
			Retries:            spec.HealthCheck.Retries,
			StartPeriodSeconds: spec.HealthCheck.StartPeriodSeconds,
		}
	}
	return result
}

type externalBuildTriggerRequest struct {
	CommitSHA string `json:"commit_sha"`
	Ref       string `json:"ref"`
}

type createBuildHookRequest struct {
	Name        string              `json:"name"`
	Provider    biz.WebhookProvider `json:"provider"`
	AllowedRefs []string            `json:"allowed_refs"`
	SecretRef   string              `json:"secret_ref"`
}
type webhookReceiptResponse struct {
	Status  biz.WebhookDeliveryStatus `json:"status"`
	BuildID string                    `json:"build_id,omitempty"`
}
type buildHookResponse struct {
	ID                   string              `json:"id"`
	ProjectID            string              `json:"project_id"`
	ApplicationID        string              `json:"application_id"`
	BuildConfigurationID string              `json:"build_configuration_id"`
	Name                 string              `json:"name"`
	Provider             biz.WebhookProvider `json:"provider"`
	AllowedRefs          []string            `json:"allowed_refs"`
	SecretConfigured     bool                `json:"secret_configured"`
	Status               biz.BuildHookStatus `json:"status"`
	Version              uint64              `json:"version"`
	CreatedBy            string              `json:"created_by"`
	CreatedAt            time.Time           `json:"created_at"`
	RevokedBy            string              `json:"revoked_by,omitempty"`
	RevokedAt            *time.Time          `json:"revoked_at,omitempty"`
}

func buildHookResponseFromDomain(item biz.BuildHookSummary) buildHookResponse {
	response := buildHookResponse{ID: item.ID, ProjectID: item.ProjectID, ApplicationID: item.ApplicationID, BuildConfigurationID: item.BuildConfigurationID,
		Name: item.Name, Provider: item.Provider, AllowedRefs: append([]string(nil), item.AllowedRefs...), SecretConfigured: item.SecretConfigured,
		Status: item.Status, Version: item.Version, CreatedBy: item.CreatedBy, CreatedAt: item.CreatedAt, RevokedBy: item.RevokedBy}
	if !item.RevokedAt.IsZero() {
		value := item.RevokedAt
		response.RevokedAt = &value
	}
	return response
}

type createBuildTriggerRequest struct {
	Name        string   `json:"name"`
	AllowedRefs []string `json:"allowed_refs"`
}

type buildTriggerResponse struct {
	ID                   string                 `json:"id"`
	ProjectID            string                 `json:"project_id"`
	ApplicationID        string                 `json:"application_id"`
	BuildConfigurationID string                 `json:"build_configuration_id"`
	Name                 string                 `json:"name"`
	AllowedRefs          []string               `json:"allowed_refs"`
	Status               biz.BuildTriggerStatus `json:"status"`
	Version              uint64                 `json:"version"`
	CreatedBy            string                 `json:"created_by"`
	CreatedAt            time.Time              `json:"created_at"`
	RevokedBy            string                 `json:"revoked_by,omitempty"`
	RevokedAt            *time.Time             `json:"revoked_at,omitempty"`
}

type buildTriggerCredentialResponse struct {
	BuildTrigger buildTriggerResponse `json:"build_trigger"`
	Token        string               `json:"token"`
}

func buildTriggerResponseFromDomain(item biz.BuildTrigger) buildTriggerResponse {
	response := buildTriggerResponse{
		ID: item.ID, ProjectID: item.ProjectID, ApplicationID: item.ApplicationID,
		BuildConfigurationID: item.BuildConfigurationID, Name: item.Name,
		AllowedRefs: append([]string(nil), item.AllowedRefs...), Status: item.Status,
		Version: item.Version, CreatedBy: item.CreatedBy, CreatedAt: item.CreatedAt,
		RevokedBy: item.RevokedBy,
	}
	if !item.RevokedAt.IsZero() {
		revokedAt := item.RevokedAt
		response.RevokedAt = &revokedAt
	}
	return response
}

type sourceRevisionResponse struct {
	SourceRepositoryID string `json:"source_repository_id"`
	Ref                string `json:"ref"`
	CommitSHA          string `json:"commit_sha"`
}

type buildConfigurationSnapshotResponse struct {
	ConfigurationID      string                       `json:"configuration_id"`
	ConfigurationVersion uint64                       `json:"configuration_version"`
	SourceRepositoryID   string                       `json:"source_repository_id"`
	DockerfilePath       string                       `json:"dockerfile_path"`
	ContextPath          string                       `json:"context_path"`
	AllowedRefs          []string                     `json:"allowed_refs"`
	RegistryCredentialID string                       `json:"registry_credential_id"`
	ImageRepository      string                       `json:"image_repository"`
	TargetPlatform       biz.BuildPlatform            `json:"target_platform"`
	Resources            buildResourcesResponse       `json:"resources"`
	TimeoutSeconds       int64                        `json:"timeout_seconds"`
	MaxConcurrency       int                          `json:"max_concurrency"`
	AutoCreateRelease    bool                         `json:"auto_create_release"`
	ReleaseRuntimeSpec   artifactRuntimeSpecPayload   `json:"release_runtime_spec"`
	AutomaticDeployments []automaticDeploymentPayload `json:"automatic_deployments"`
}

type buildLogEntryResponse struct {
	Sequence  uint64            `json:"sequence"`
	Stage     biz.BuildLogStage `json:"stage"`
	Message   string            `json:"message"`
	CreatedAt time.Time         `json:"created_at"`
}

type buildLogPageResponse struct {
	Items      []buildLogEntryResponse `json:"items"`
	NextCursor string                  `json:"next_cursor"`
	Truncated  bool                    `json:"truncated"`
	Complete   bool                    `json:"complete"`
	ExpiresAt  *time.Time              `json:"expires_at,omitempty"`
}

func buildLogPageResponseFromDomain(buildID string, page biz.BuildLogPage) buildLogPageResponse {
	items := make([]buildLogEntryResponse, len(page.Entries))
	for index, item := range page.Entries {
		items[index] = buildLogEntryResponse{
			Sequence: item.Sequence, Stage: item.Stage, Message: item.Message, CreatedAt: item.CreatedAt,
		}
	}
	response := buildLogPageResponse{
		Items: items, NextCursor: encodeBuildLogCursor(buildID, page.NextSequence),
		Truncated: page.Truncated, Complete: page.Complete,
	}
	if !page.ExpiresAt.IsZero() {
		expiresAt := page.ExpiresAt
		response.ExpiresAt = &expiresAt
	}
	return response
}

func encodeBuildLogCursor(buildID string, sequence uint64) string {
	payload := "v1\n" + buildID + "\n" + strconv.FormatUint(sequence, 10)
	return base64.RawURLEncoding.EncodeToString([]byte(payload))
}

func decodeBuildLogCursor(buildID, cursor string) (uint64, error) {
	cursor = strings.TrimSpace(cursor)
	if cursor == "" {
		return 0, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil || len(payload) > 1024 {
		return 0, biz.ErrInvalidBuildLogQuery
	}
	parts := strings.Split(string(payload), "\n")
	if len(parts) != 3 || parts[0] != "v1" || parts[1] != buildID {
		return 0, biz.ErrInvalidBuildLogQuery
	}
	sequence, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil {
		return 0, biz.ErrInvalidBuildLogQuery
	}
	return sequence, nil
}

type buildResponse struct {
	ID                   string                             `json:"id"`
	ProjectID            string                             `json:"project_id"`
	ApplicationID        string                             `json:"application_id"`
	BuildConfigurationID string                             `json:"build_configuration_id"`
	Revision             sourceRevisionResponse             `json:"revision"`
	Configuration        buildConfigurationSnapshotResponse `json:"configuration_snapshot"`
	TriggerSource        biz.BuildTriggerSource             `json:"trigger_source"`
	TriggerID            string                             `json:"trigger_id,omitempty"`
	IdempotencyKey       string                             `json:"idempotency_key"`
	Status               biz.BuildStatus                    `json:"status"`
	FailureCategory      biz.BuildFailureCategory           `json:"failure_category,omitempty"`
	Version              uint64                             `json:"version"`
	TriggeredBy          string                             `json:"triggered_by"`
	SourceBuildID        string                             `json:"source_build_id,omitempty"`
	ArtifactID           string                             `json:"artifact_id,omitempty"`
	CreatedAt            time.Time                          `json:"created_at"`
	UpdatedAt            time.Time                          `json:"updated_at"`
	StartedAt            *time.Time                         `json:"started_at,omitempty"`
	FinishedAt           *time.Time                         `json:"finished_at,omitempty"`
}

func buildResponseFromDomain(item biz.Build) buildResponse {
	response := buildResponse{
		ID: item.ID, ProjectID: item.ProjectID, ApplicationID: item.ApplicationID,
		BuildConfigurationID: item.BuildConfigurationID,
		Revision: sourceRevisionResponse{
			SourceRepositoryID: item.Revision.SourceRepositoryID,
			Ref:                item.Revision.Ref, CommitSHA: item.Revision.CommitSHA,
		},
		Configuration: buildConfigurationSnapshotResponse{
			ConfigurationID:      item.Configuration.ConfigurationID,
			ConfigurationVersion: item.Configuration.ConfigurationVersion,
			SourceRepositoryID:   item.Configuration.SourceRepositoryID,
			DockerfilePath:       item.Configuration.DockerfilePath,
			ContextPath:          item.Configuration.ContextPath,
			AllowedRefs:          append([]string(nil), item.Configuration.AllowedRefs...),
			RegistryCredentialID: item.Configuration.RegistryCredentialID,
			ImageRepository:      item.Configuration.ImageRepository,
			TargetPlatform:       item.Configuration.TargetPlatform,
			Resources: buildResourcesResponse{
				CPUMilli:    item.Configuration.Resources.CPUMilli,
				MemoryBytes: item.Configuration.Resources.MemoryBytes,
				DiskBytes:   item.Configuration.Resources.DiskBytes,
			},
			TimeoutSeconds:       item.Configuration.TimeoutSeconds,
			MaxConcurrency:       item.Configuration.MaxConcurrency,
			AutoCreateRelease:    item.Configuration.AutoCreateRelease,
			ReleaseRuntimeSpec:   artifactRuntimeSpecPayloadFromDomain(item.Configuration.ReleaseRuntimeSpec),
			AutomaticDeployments: automaticDeploymentPayloadsFromDomain(item.Configuration.AutomaticDeployments),
		},
		TriggerSource: item.TriggerSource, TriggerID: item.TriggerID, IdempotencyKey: item.IdempotencyKey,
		Status: item.Status, FailureCategory: item.FailureCategory, Version: item.Version,
		TriggeredBy: item.TriggeredBy, SourceBuildID: item.SourceBuildID, ArtifactID: item.ArtifactID,
		CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt,
	}
	if !item.StartedAt.IsZero() {
		value := item.StartedAt
		response.StartedAt = &value
	}
	if !item.FinishedAt.IsZero() {
		value := item.FinishedAt
		response.FinishedAt = &value
	}
	return response
}

type artifactResponse struct {
	ID                   string                           `json:"id"`
	ProjectID            string                           `json:"project_id"`
	ApplicationID        string                           `json:"application_id"`
	Origin               biz.ArtifactOrigin               `json:"origin"`
	Producer             string                           `json:"producer"`
	ProducerVerification biz.ArtifactProducerVerification `json:"producer_verification"`
	BuildID              string                           `json:"build_id,omitempty"`
	BuildConfigurationID string                           `json:"build_configuration_id,omitempty"`
	RegistryCredentialID string                           `json:"registry_credential_id"`
	ImageRepository      string                           `json:"image_repository"`
	ImageDigest          string                           `json:"image_digest"`
	TargetPlatform       biz.BuildPlatform                `json:"target_platform"`
	ReleaseRuntimeSpec   artifactRuntimeSpecPayload       `json:"release_runtime_spec"`
	AutomaticDeployments []automaticDeploymentPayload     `json:"automatic_deployments"`
	ReleaseStatus        biz.ArtifactReleaseStatus        `json:"release_status"`
	ReleaseID            string                           `json:"release_id,omitempty"`
	Version              uint64                           `json:"version"`
	CreatedAt            time.Time                        `json:"created_at"`
	ReleasedAt           *time.Time                       `json:"released_at,omitempty"`
}

func artifactResponseFromDomain(item biz.Artifact) artifactResponse {
	response := artifactResponse{
		ID: item.ID, ProjectID: item.ProjectID, ApplicationID: item.ApplicationID,
		Origin: item.Origin, Producer: item.Producer, ProducerVerification: item.ProducerVerification,
		BuildID: item.BuildID, BuildConfigurationID: item.BuildConfigurationID,
		RegistryCredentialID: item.RegistryCredentialID,
		ImageRepository:      item.ImageRepository, ImageDigest: item.ImageDigest,
		TargetPlatform: item.TargetPlatform, ReleaseStatus: item.ReleaseStatus,
		ReleaseRuntimeSpec:   artifactRuntimeSpecPayloadFromDomain(item.ReleaseRuntimeSpec),
		AutomaticDeployments: automaticDeploymentPayloadsFromDomain(item.AutomaticDeployments),
		ReleaseID:            item.ReleaseID, Version: item.Version, CreatedAt: item.CreatedAt,
	}
	if !item.ReleasedAt.IsZero() {
		value := item.ReleasedAt
		response.ReleasedAt = &value
	}
	return response
}

type registerExternalArtifactRequest struct {
	ApplicationID        string                     `json:"application_id"`
	RegistryCredentialID string                     `json:"registry_credential_id"`
	ImageDigest          string                     `json:"image_digest"`
	TargetPlatform       biz.BuildPlatform          `json:"target_platform"`
	Producer             string                     `json:"producer"`
	ReleaseRuntimeSpec   artifactRuntimeSpecPayload `json:"release_runtime_spec"`
}

type buildResourcesRequest struct {
	CPUMilli    int64 `json:"cpu_milli"`
	MemoryBytes int64 `json:"memory_bytes"`
	DiskBytes   int64 `json:"disk_bytes"`
}

type automaticDeploymentPayload struct {
	EnvironmentID   string `json:"environment_id"`
	RuntimeTargetID string `json:"runtime_target_id"`
}

func (p automaticDeploymentPayload) domain() biz.AutomaticDeploymentRule {
	return biz.AutomaticDeploymentRule{
		EnvironmentID: p.EnvironmentID, RuntimeTargetID: p.RuntimeTargetID,
	}
}

func automaticDeploymentPayloadsDomain(values []automaticDeploymentPayload) []biz.AutomaticDeploymentRule {
	result := make([]biz.AutomaticDeploymentRule, len(values))
	for index, value := range values {
		result[index] = value.domain()
	}
	return result
}

func automaticDeploymentPayloadsFromDomain(values []biz.AutomaticDeploymentRule) []automaticDeploymentPayload {
	result := make([]automaticDeploymentPayload, len(values))
	for index, value := range values {
		result[index] = automaticDeploymentPayload{
			EnvironmentID: value.EnvironmentID, RuntimeTargetID: value.RuntimeTargetID,
		}
	}
	return result
}

func (r buildResourcesRequest) domain() biz.BuildResources {
	return biz.BuildResources{
		CPUMilli: r.CPUMilli, MemoryBytes: r.MemoryBytes, DiskBytes: r.DiskBytes,
	}
}

type createBuildConfigurationRequest struct {
	Name                 string                       `json:"name"`
	SourceRepositoryID   string                       `json:"source_repository_id"`
	DockerfilePath       string                       `json:"dockerfile_path"`
	ContextPath          string                       `json:"context_path"`
	AllowedRefs          []string                     `json:"allowed_refs"`
	RegistryCredentialID string                       `json:"registry_credential_id"`
	ImageRepository      string                       `json:"image_repository"`
	TargetPlatform       biz.BuildPlatform            `json:"target_platform"`
	Resources            buildResourcesRequest        `json:"resources"`
	TimeoutSeconds       int64                        `json:"timeout_seconds"`
	MaxConcurrency       int                          `json:"max_concurrency"`
	AutoCreateRelease    *bool                        `json:"auto_create_release"`
	ReleaseRuntimeSpec   artifactRuntimeSpecPayload   `json:"release_runtime_spec"`
	AutomaticDeployments []automaticDeploymentPayload `json:"automatic_deployments"`
}

func (r createBuildConfigurationRequest) autoCreateRelease() bool {
	if r.AutoCreateRelease == nil {
		return biz.DefaultAutoCreateRelease
	}
	return *r.AutoCreateRelease
}

type patchBuildConfigurationRequest struct {
	ExpectedVersion      uint64                        `json:"expected_version"`
	Name                 *string                       `json:"name"`
	SourceRepositoryID   *string                       `json:"source_repository_id"`
	DockerfilePath       *string                       `json:"dockerfile_path"`
	ContextPath          *string                       `json:"context_path"`
	AllowedRefs          *[]string                     `json:"allowed_refs"`
	RegistryCredentialID *string                       `json:"registry_credential_id"`
	ImageRepository      *string                       `json:"image_repository"`
	TargetPlatform       *biz.BuildPlatform            `json:"target_platform"`
	Resources            *buildResourcesRequest        `json:"resources"`
	TimeoutSeconds       *int64                        `json:"timeout_seconds"`
	MaxConcurrency       *int                          `json:"max_concurrency"`
	AutoCreateRelease    *bool                         `json:"auto_create_release"`
	ReleaseRuntimeSpec   *artifactRuntimeSpecPayload   `json:"release_runtime_spec"`
	AutomaticDeployments *[]automaticDeploymentPayload `json:"automatic_deployments"`
}

func (r patchBuildConfigurationRequest) domain() biz.BuildConfigurationPatch {
	patch := biz.BuildConfigurationPatch{
		Name: r.Name, SourceRepositoryID: r.SourceRepositoryID,
		DockerfilePath: r.DockerfilePath, ContextPath: r.ContextPath,
		AllowedRefs: r.AllowedRefs, RegistryCredentialID: r.RegistryCredentialID,
		ImageRepository: r.ImageRepository, TargetPlatform: r.TargetPlatform,
		TimeoutSeconds: r.TimeoutSeconds, MaxConcurrency: r.MaxConcurrency,
		AutoCreateRelease: r.AutoCreateRelease,
	}
	if r.Resources != nil {
		resources := r.Resources.domain()
		patch.Resources = &resources
	}
	if r.ReleaseRuntimeSpec != nil {
		runtimeSpec := r.ReleaseRuntimeSpec.domain()
		patch.ReleaseRuntimeSpec = &runtimeSpec
	}
	if r.AutomaticDeployments != nil {
		values := automaticDeploymentPayloadsDomain(*r.AutomaticDeployments)
		patch.AutomaticDeployments = &values
	}
	return patch
}

type buildResourcesResponse struct {
	CPUMilli    int64 `json:"cpu_milli"`
	MemoryBytes int64 `json:"memory_bytes"`
	DiskBytes   int64 `json:"disk_bytes"`
}

type buildConfigurationResponse struct {
	ID                   string                       `json:"id"`
	ProjectID            string                       `json:"project_id"`
	ApplicationID        string                       `json:"application_id"`
	Name                 string                       `json:"name"`
	SourceRepositoryID   string                       `json:"source_repository_id"`
	DockerfilePath       string                       `json:"dockerfile_path"`
	ContextPath          string                       `json:"context_path"`
	AllowedRefs          []string                     `json:"allowed_refs"`
	RegistryCredentialID string                       `json:"registry_credential_id"`
	ImageRepository      string                       `json:"image_repository"`
	TargetPlatform       biz.BuildPlatform            `json:"target_platform"`
	Resources            buildResourcesResponse       `json:"resources"`
	TimeoutSeconds       int64                        `json:"timeout_seconds"`
	MaxConcurrency       int                          `json:"max_concurrency"`
	AutoCreateRelease    bool                         `json:"auto_create_release"`
	ReleaseRuntimeSpec   artifactRuntimeSpecPayload   `json:"release_runtime_spec"`
	AutomaticDeployments []automaticDeploymentPayload `json:"automatic_deployments"`
	Version              uint64                       `json:"version"`
	CreatedBy            string                       `json:"created_by"`
	UpdatedBy            string                       `json:"updated_by"`
	CreatedAt            time.Time                    `json:"created_at"`
	UpdatedAt            time.Time                    `json:"updated_at"`
}

func buildConfigurationResponseFromDomain(item biz.BuildConfiguration) buildConfigurationResponse {
	return buildConfigurationResponse{
		ID: item.ID, ProjectID: item.ProjectID, ApplicationID: item.ApplicationID,
		Name: item.Name, SourceRepositoryID: item.SourceRepositoryID,
		DockerfilePath: item.DockerfilePath, ContextPath: item.ContextPath,
		AllowedRefs:          append([]string(nil), item.AllowedRefs...),
		RegistryCredentialID: item.RegistryCredentialID,
		ImageRepository:      item.ImageRepository, TargetPlatform: item.TargetPlatform,
		Resources: buildResourcesResponse{
			CPUMilli:    item.Resources.CPUMilli,
			MemoryBytes: item.Resources.MemoryBytes,
			DiskBytes:   item.Resources.DiskBytes,
		},
		TimeoutSeconds: item.TimeoutSeconds, MaxConcurrency: item.MaxConcurrency,
		AutoCreateRelease: item.AutoCreateRelease, Version: item.Version,
		ReleaseRuntimeSpec:   artifactRuntimeSpecPayloadFromDomain(item.ReleaseRuntimeSpec),
		AutomaticDeployments: automaticDeploymentPayloadsFromDomain(item.AutomaticDeployments),
		CreatedBy:            item.CreatedBy, UpdatedBy: item.UpdatedBy,
		CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt,
	}
}

type credentialResponse struct {
	ID                   string             `json:"id"`
	ProjectID            string             `json:"project_id"`
	Name                 string             `json:"name"`
	Type                 biz.CredentialType `json:"type"`
	Username             string             `json:"username,omitempty"`
	SecretConfigured     bool               `json:"secret_configured"`
	PublicKeyFingerprint string             `json:"public_key_fingerprint,omitempty"`
	Version              uint64             `json:"version"`
	CreatedBy            string             `json:"created_by"`
	CreatedAt            time.Time          `json:"created_at"`
}

func credentialResponseFromDomain(item biz.CredentialSummary) credentialResponse {
	return credentialResponse{
		ID: item.ID, ProjectID: item.ProjectID, Name: item.Name, Type: item.Type,
		Username: item.Username, SecretConfigured: item.SecretConfigured,
		PublicKeyFingerprint: item.PublicKeyFingerprint,
		Version:              item.Version, CreatedBy: item.CreatedBy, CreatedAt: item.CreatedAt,
	}
}

type sourceResponse struct {
	ID                    string                     `json:"id"`
	ProjectID             string                     `json:"project_id"`
	Name                  string                     `json:"name"`
	RepositoryURL         string                     `json:"repository_url"`
	Protocol              biz.RepositoryProtocol     `json:"protocol"`
	DefaultBranch         string                     `json:"default_branch"`
	CredentialID          string                     `json:"credential_id,omitempty"`
	SSHHostKeyFingerprint string                     `json:"ssh_host_key_fingerprint,omitempty"`
	Status                biz.SourceRepositoryStatus `json:"status"`
	LastProbedAt          *time.Time                 `json:"last_probed_at,omitempty"`
	CreatedBy             string                     `json:"created_by"`
	CreatedAt             time.Time                  `json:"created_at"`
	UpdatedAt             time.Time                  `json:"updated_at"`
}

func sourceResponseFromDomain(item biz.SourceRepository) sourceResponse {
	response := sourceResponse{
		ID: item.ID, ProjectID: item.ProjectID, Name: item.Name,
		RepositoryURL: item.RepositoryURL, Protocol: item.Protocol,
		DefaultBranch: item.DefaultBranch, CredentialID: item.CredentialID,
		SSHHostKeyFingerprint: item.SSHHostKeyFingerprint,
		Status:                item.Status, CreatedBy: item.CreatedBy,
		CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt,
	}
	if !item.LastProbedAt.IsZero() {
		lastProbedAt := item.LastProbedAt
		response.LastProbedAt = &lastProbedAt
	}
	return response
}
