package data

import (
	"context"
	"strings"

	"github.com/owndock/owndock/internal/modules/controlplane/biz"
	"github.com/owndock/owndock/internal/shared/runtimespec"
)

// BuiltInTemplateCatalog is immutable for the lifetime of a Server release.
// Changing a preset requires incrementing its version; Applications retain a
// detached copy of the version they selected.
type BuiltInTemplateCatalog struct {
	items []biz.Template
}

func NewBuiltInTemplateCatalog() *BuiltInTemplateCatalog {
	return &BuiltInTemplateCatalog{items: []biz.Template{
		{
			ID: "http-service", Version: 1,
			Name: biz.LocalizedText{
				English: "HTTP service", SimplifiedChinese: "HTTP 服务",
			},
			Description: biz.LocalizedText{
				English:           "A web service listening on container port 8080.",
				SimplifiedChinese: "监听容器 8080 端口的 Web 服务。",
			},
			Preset: biz.TemplatePreset{
				DockerfilePath: "Dockerfile", ContextPath: ".",
				RuntimeSpec: runtimespec.Spec{Ports: []runtimespec.Port{{
					Name: "http", ContainerPort: 8080, Protocol: "tcp",
				}}},
			},
		},
		{
			ID: "background-worker", Version: 1,
			Name: biz.LocalizedText{
				English: "Background worker", SimplifiedChinese: "后台任务",
			},
			Description: biz.LocalizedText{
				English:           "A long-running process without an exposed port.",
				SimplifiedChinese: "不暴露端口的常驻后台进程。",
			},
			Preset: biz.TemplatePreset{
				DockerfilePath: "Dockerfile", ContextPath: ".",
				RuntimeSpec: runtimespec.Spec{},
			},
		},
	}}
}

func (c *BuiltInTemplateCatalog) ListTemplates(
	context.Context,
) ([]biz.Template, error) {
	items := make([]biz.Template, 0, len(c.items))
	for _, item := range c.items {
		normalized, err := biz.NormalizeTemplate(cloneTemplate(item))
		if err != nil {
			return nil, err
		}
		items = append(items, normalized)
	}
	return items, nil
}

func (c *BuiltInTemplateCatalog) GetTemplate(
	_ context.Context,
	id string,
) (biz.Template, error) {
	id = strings.TrimSpace(id)
	for _, item := range c.items {
		if item.ID == id {
			return biz.NormalizeTemplate(cloneTemplate(item))
		}
	}
	return biz.Template{}, biz.ErrNotFound
}

func cloneTemplate(item biz.Template) biz.Template {
	item.Preset.RuntimeSpec.Ports = append(
		[]runtimespec.Port(nil), item.Preset.RuntimeSpec.Ports...,
	)
	item.Preset.RuntimeSpec.EnvironmentKeys = append(
		[]string(nil), item.Preset.RuntimeSpec.EnvironmentKeys...,
	)
	if item.Preset.RuntimeSpec.HealthCheck != nil {
		health := *item.Preset.RuntimeSpec.HealthCheck
		health.Command = append(
			[]string(nil), item.Preset.RuntimeSpec.HealthCheck.Command...,
		)
		item.Preset.RuntimeSpec.HealthCheck = &health
	}
	return item
}
