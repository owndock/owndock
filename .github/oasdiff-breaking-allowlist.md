# Approved OpenAPI breaking changes

This allowlist is intentionally endpoint-specific. It records the one-time removal of the unauthenticated, in-memory engineering sample API after the authenticated Project-scoped product API replaced it. New product API changes must not be added here without an explicit migration decision.

- GET /api/v1/applications api path removed without deprecation
- POST /api/v1/applications api path removed without deprecation
- GET /api/v1/environments api path removed without deprecation
- POST /api/v1/environments api path removed without deprecation
- GET /api/v1/deployments api path removed without deprecation
- POST /api/v1/deployments api path removed without deprecation
