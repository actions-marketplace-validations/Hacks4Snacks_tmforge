# Threat Model Analysis Rules

This project supplies the built-in rule set that ships with Threat Model Forge. The rules run
against any threat model and are grouped into selectable **rule packs**:

| Pack id | Focus |
| --- | --- |
| `core-hygiene` | Structural completeness and diagram hygiene (connectivity, naming, size). |
| `stride-completeness` | Trust boundaries, boundary crossings, external interactors, and flow metadata. |
| `input-validation` | Inputs/outputs sanitized across trust boundaries; process isolation. |
| `data-protection` | Data-at-rest protection: encryption, access control, integrity, retention. |
| `transport-security` | Data-in-transit protection across trust boundaries. |
| `identity-access` | Authentication, least privilege, and shared-identity checks. |
| `availability` | Recoverability of credential and audit/log stores through declared backups. |

`RulePackCatalog` is the single source of truth for pack ids, display names, and ordering; hosts
(the CLI, the engine API's `GET /v1/rule-packs`, and Studio) consume it so names never drift.
Each rule reads typed custom properties (`Protocol`, `Port`, `AuthenticationScheme`, encryption
flags, ...) whose schema is published via `GET /v1/property-schema` and `tmforge properties`.
