package data

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/owndock/owndock/internal/modules/supplychain/biz"
	"oras.land/oras-go/v2/registry/remote/errcode"
)

func TestSBOMImageManifestValidationBoundsLayersAndIndexes(t *testing.T) {
	layerDigest := "sha256:" + strings.Repeat("a", 64)
	childDigest := "sha256:" + strings.Repeat("b", 64)
	validManifest := fmt.Sprintf(
		`{"schemaVersion":2,"mediaType":%q,"layers":[{"digest":%q,"size":1024}]}`,
		mediaTypeOCIManifest, layerDigest,
	)
	children, err := validateSBOMImageManifest([]byte(validManifest), mediaTypeOCIManifest, 1024, 0)
	if err != nil || len(children) != 0 {
		t.Fatalf("valid image manifest = %+v, %v", children, err)
	}
	oversized := strings.Replace(validManifest, `"size":1024`, `"size":1025`, 1)
	if _, err := validateSBOMImageManifest(
		[]byte(oversized), mediaTypeOCIManifest, 1024, 0,
	); !errors.Is(err, biz.ErrSBOMImageTooLarge) {
		t.Fatalf("oversized layer error = %v", err)
	}
	index := fmt.Sprintf(
		`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"digest":%q,"size":512}]}`,
		mediaTypeOCIIndex, mediaTypeOCIManifest, childDigest,
	)
	children, err = validateSBOMImageManifest([]byte(index), mediaTypeOCIIndex, 1024, 0)
	if err != nil || len(children) != 1 || children[0].digest.String() != childDigest ||
		children[0].mediaType != mediaTypeOCIManifest || children[0].size != 512 {
		t.Fatalf("valid image index = %+v, %v", children, err)
	}

	for name, testCase := range map[string]struct {
		content   string
		mediaType string
		depth     int
	}{
		"invalid JSON":       {content: `{`, mediaType: mediaTypeOCIManifest},
		"wrong schema":       {content: `{"schemaVersion":1,"mediaType":"` + mediaTypeOCIManifest + `"}`, mediaType: mediaTypeOCIManifest},
		"media mismatch":     {content: validManifest, mediaType: mediaTypeDockerManifest},
		"invalid layer":      {content: strings.Replace(validManifest, layerDigest, "bad", 1), mediaType: mediaTypeOCIManifest},
		"negative layer":     {content: strings.Replace(validManifest, `"size":1024`, `"size":-1`, 1), mediaType: mediaTypeOCIManifest},
		"empty index":        {content: `{"schemaVersion":2,"mediaType":"` + mediaTypeOCIIndex + `","manifests":[]}`, mediaType: mediaTypeOCIIndex},
		"nested index":       {content: index, mediaType: mediaTypeOCIIndex, depth: 1},
		"nested child type":  {content: strings.Replace(index, mediaTypeOCIManifest, mediaTypeOCIIndex, 1), mediaType: mediaTypeOCIIndex},
		"invalid child size": {content: strings.Replace(index, `"size":512`, `"size":0`, 1), mediaType: mediaTypeOCIIndex},
		"unsupported type":   {content: `{"schemaVersion":2,"mediaType":"application/json"}`, mediaType: "application/json"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := validateSBOMImageManifest(
				[]byte(testCase.content), testCase.mediaType, 1024, testCase.depth,
			); !errors.Is(err, biz.ErrSBOMGeneration) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestOCIImageGuardRejectsUnsafeConfigurationAndInput(t *testing.T) {
	if _, err := NewOCIImageGuard(OCIImageGuardOptions{
		RegistryHTTPSProxy: "http://user:secret@proxy.internal:3128",
	}); !errors.Is(err, biz.ErrGeneratorVersion) {
		t.Fatalf("unsafe proxy error = %v", err)
	}
	guard, err := NewOCIImageGuard(OCIImageGuardOptions{})
	if err != nil {
		t.Fatal(err)
	}
	credential := biz.RegistryCredential{AuthenticationMode: "anonymous"}
	if err := guard.ValidateSBOMImage(t.Context(), biz.SBOMRequest{}, 256*1024*1024,
		credential); !errors.Is(err, biz.ErrInvalidEvidenceJob) {
		t.Fatalf("invalid request error = %v", err)
	}
	if err := guard.ValidateSBOMImage(t.Context(), syftRequest(), 1,
		credential); !errors.Is(err, biz.ErrInvalidEvidenceJob) {
		t.Fatalf("invalid layer limit error = %v", err)
	}
	if err := guard.ValidateSBOMImage(t.Context(), syftRequest(), 256*1024*1024,
		biz.RegistryCredential{}); !errors.Is(err, biz.ErrInvalidEvidenceJob) {
		t.Fatalf("invalid credential error = %v", err)
	}
	var nilGuard *OCIImageGuard
	if err := nilGuard.ValidateSBOMImage(t.Context(), syftRequest(), 256*1024*1024,
		credential); !errors.Is(err, biz.ErrInvalidEvidenceJob) {
		t.Fatalf("nil guard error = %v", err)
	}
}

func TestReadSBOMImageManifestFailsClosed(t *testing.T) {
	for name, stream := range map[string]io.ReadCloser{
		"nil stream":     nil,
		"empty manifest": io.NopCloser(strings.NewReader("")),
		"large manifest": io.NopCloser(strings.NewReader(strings.Repeat("x", int(maximumArtifactManifestBytes+1)))),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readSBOMImageManifest(stream); !errors.Is(err, biz.ErrSBOMGeneration) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	content, err := readSBOMImageManifest(io.NopCloser(strings.NewReader("{}")))
	if err != nil || string(content) != "{}" {
		t.Fatalf("content = %q, error = %v", content, err)
	}
}

func TestSBOMImageRegistryErrorCategories(t *testing.T) {
	if !errors.Is(sbomImageRegistryError(context.Canceled), context.Canceled) {
		t.Fatal("canceled context was not preserved")
	}
	if !errors.Is(sbomImageRegistryError(context.DeadlineExceeded), context.DeadlineExceeded) {
		t.Fatal("deadline was not preserved")
	}
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		err := &errcode.ErrorResponse{StatusCode: status}
		if !errors.Is(sbomImageRegistryError(err), biz.ErrRegistryAuthentication) {
			t.Fatalf("status %d was not categorized as authentication", status)
		}
	}
	if !errors.Is(sbomImageRegistryError(errors.New("registry unavailable")), biz.ErrSBOMGeneration) {
		t.Fatal("generic error was not categorized as generation")
	}
}

func TestOCIImageGuardRejectsTraversalBoundsBeforeFetching(t *testing.T) {
	guard := &OCIImageGuard{}
	validDigest := digest.FromString("manifest")
	for name, testCase := range map[string]struct {
		digest string
		depth  int
		seen   map[digest.Digest]bool
	}{
		"depth":     {digest: validDigest.String(), depth: 2, seen: map[digest.Digest]bool{}},
		"invalid":   {digest: "bad", seen: map[digest.Digest]bool{}},
		"duplicate": {digest: validDigest.String(), seen: map[digest.Digest]bool{validDigest: true}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := guard.inspectManifest(t.Context(), nil, testCase.digest, 1024, testCase.depth,
				-1, "", testCase.seen); !errors.Is(err, biz.ErrSBOMGeneration) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	seen := make(map[digest.Digest]bool, maximumSBOMImageManifests)
	for i := 0; i < maximumSBOMImageManifests; i++ {
		seen[digest.FromString(fmt.Sprintf("manifest-%d", i))] = true
	}
	if err := guard.inspectManifest(t.Context(), nil, validDigest.String(), 1024, 0,
		-1, "", seen); !errors.Is(err, biz.ErrSBOMGeneration) {
		t.Fatalf("manifest count error = %v", err)
	}
}
