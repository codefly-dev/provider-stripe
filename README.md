# provider-stripe

The Codefly **Stripe reference provider** — a `codefly:provider` leaf agent that
manages Stripe billing setup (the account observation and the signed billing
lifecycle webhook endpoint) through Codefly's provider lifecycle, and projects
the generic `billing@1` configuration contract consumed by application services.

It is the first of the three reference providers (Stripe, Sentry, Resend) that
establish the `codefly.provider/v0` protocol baseline.

## Security model

The provider is treated as **untrusted code**. It never holds Stripe
credentials and never sees the webhook signing secret:

- Stripe API calls go through the **host broker** (the `ProviderHost`
  `ExecuteRequest` callback), never a direct socket — the sandbox declares
  `network: deny`.
- Credentials are **opaque handles**; the raw key bytes stay in the host.
- The webhook `secret` is declared `CAPTURE_TO_SINK` in the manifest, so the
  broker captures it directly to a durable sink and the provider only ever
  receives an opaque reference / presence, never the bytes.
- Test-vs-live **mode is host-attested**: the host classifies the credential
  (`sk_test_`/`rk_test_`/`sk_live_`/`rk_live_`) and attests mode; the provider
  never classifies a raw secret. v0.1 refuses any account policy other than
  `sandbox`/`test` and does not mutate production.
- The **management** credential is never projected into `billing@1`; only the
  runtime key reference and the webhook-verification reference are.

## What this agent does

- **Observe** `stripe.account` (safe subset + host-attested mode) and
  `stripe.webhook-endpoint` (Codefly-owned fields only).
- **Plan** the webhook endpoint lifecycle from desired state + observation:
  `CREATE` / `UPDATE` / `REPLACE` / `IMPORT` / `DELETE` / `NO_OP` / `BLOCKED`,
  plus a `PROJECT_OUTPUT` that emits `billing@1`.
  - Changing the endpoint **API version is a `REPLACE`**, not an update: Stripe
    does not expose `api_version` in update parameters and the replacement mints
    a new signing secret.
  - A same-URL endpoint that Codefly does not own is **never adopted by URL** —
    the plan blocks and requires import by exact id.
  - `local-forwarded` mode creates **no remote endpoint** (the Stripe CLI
    listener supplies the verification secret through host input).

## Protocol status (v0.1)

This repository is bootstrapped **ahead of** the host broker (core#134),
coordinator (cli#196), and conformance harness (cli#197). It pins an
**unreleased `core` main** pseudo-version because no published `core` tag yet
exports the provider protocol.

| Surface | State |
|---|---|
| `GetProviderInformation`, `Validate`, `Plan`, `UpgradeState` (offline) | **Implemented + tested** |
| Manifest (`provider.codefly.yaml`), runtime catalog, artifact packaging | **Implemented + validated against core** |
| `billing@1` projection planning | **Implemented + tested** |
| Error / rate / quota → diagnostic mapping | **Implemented + tested** |
| `Observe`, `ApplyAction`, `Doctor` (broker-driven) | **Pending** — need the host broker/coordinator; not yet implemented |
| Tier 1 cassettes, Tier 3 live sandbox, Tier 4 dogfood | **Pending** — need the running host and a dedicated Stripe sandbox |

The broker-driven methods currently return `Unimplemented` from the embedded
`sdk.Base`. The offline surface is complete and deterministic.

## Layout

```
provider.codefly.yaml     capability manifest (the security-load-bearing ceiling)
agent.codefly.yaml        agent identity (kind: codefly:provider)
main.go                   agents.Serve entrypoint; discovers verified identity
internal/provider/        the Provider service implementation
cmd/package/              produces the verified artifact layout (binary + manifest + descriptor)
```

## Develop

```bash
make test      # go test ./...
make vet
make build     # -> ./provider-stripe
make package   # -> ./dist/{provider-stripe, provider.codefly.yaml, provider.artifact.json}
```

`core` and `cli` are public modules, so `go` fetches them through the module
proxy with no extra configuration.
