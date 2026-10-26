# keycloak-sas-otp-authenticator

Keycloak authenticator by **Südwestfalen-IT (SIT)**: an OTP form whose one-time passcode is
validated by **Thales SafeNet Authentication Service (SAS PCE)** instead of a Keycloak OTP
credential. Built with Claude.

| Provider ID | Display Name | Type |
|---|---|---|
| `sit-auth-otp-form-sas` | SIT: OTP Form (SAS PCE / Thales) | Browser Flow |

## Why not the Thales agent

The *SafeNet Agent for Keycloak* ships its own flow, its own theme and a server-wide
login-forms override, and targets Keycloak 24. This authenticator keeps only the Thales
**TokenValidator library** (request XML, agent key file, AES-GCM crypto) and replaces the rest:

- renders Keycloak's **standard `login-otp.ftl`**, so every theme based on `keycloak.v2` works
  unchanged – no Thales theme, no template overlay
- validates over the same request as the original agent (`verifycredentials` /
  `TokenValidation`); `SitTokenValidatorWrapper` extends the vendor's
  `TokenValidatorWrapperImpl` and replaces **only the HTTP transport** with `java.net.http`
  (HTTP/1.1, 10 s connect / 15 s request, Keycloak's trust store). No Apache HttpClient,
  no failover, no push/307 handling
- proxy from `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` (upper or lower case), like Keycloak
  itself; without them a direct connection. The detected proxy is logged once
  (`SAS TokenValidator proxy from environment`)
- no self-enrolment, `configuredFor()` is always true – SAS decides
- the agent key file may be given as a **path or Base64 content**. The vendor's path
  detection only recognises Windows paths; the wrapper resolves Linux paths itself
- only `SasTokenValidatorClient` / `SitTokenValidatorWrapper` reference Thales classes and
  are loaded lazily: without the Thales JARs Keycloak still starts, the login then shows the
  "unavailable" page

Not needed any more: Thales' `sas-authenticator…jar`, `sas-services.jar`, the Thales theme.

## Configuration

In the browser flow, put the execution **SIT: OTP Form (SAS PCE / Thales)** where the OTP
form would be (`REQUIRED`). Do not put "Condition – user configured" / "Condition –
credential" in front of it: SAS users have no Keycloak credential.

Execution config (gear icon) – same keys and labels as the original agent, so an existing
Thales execution config can be copied over:

| Key | Label | Value |
|---|---|---|
| `tokenvalidator.url` | Token Validator URL | `https://<sas>/TokenValidator/TokenValidator.asmx?orgCode=<code>` |
| `agent.bsidkey` | Agent BSID Key | path inside the container (key file from the SAS console: *Comms → Authentication Processing → Download Agent Key File*, mounted as a secret) or its Base64 content |
| `user.id.mapper` | User Id Mapper | user attribute sent to SAS as user id; empty = Keycloak username |

`otp.autotrigger.enabled` of the original is not offered (push/SMS/GrIDsure only).

| Situation | Result |
|---|---|
| OTP accepted | login continues |
| SAS rejects | `Invalid authenticator code.` on the OTP page, `LOGIN_ERROR` event, brute-force counter |
| SAS wants challenge / PIN change / push | message `sasOtpUnsupportedResponse` (not implemented on purpose) |
| SAS unreachable, proxy/TLS problem, broken key file | 503 page `sasOtpUnavailable` |
| execution not configured | 500 page `sasOtpNotConfigured` |

Messages are shipped in English and German (`theme-resources/messages`).

## Installation

Into Keycloak's `providers/`:

- `keycloak-sas-otp-authenticator-<version>-kc<keycloak>.jar` (this repository)
- `commons.jar` and `token-validator-adapter-jar-with-dependencies.jar` (Thales, patched – see
  [thales/README.md](thales/README.md))

then `kc.sh build`. Add `scripts/sas-probe.sh` as `/opt/keycloak/bin/sas-probe.sh` for the dry run.

## Dry run against the production SAS

`SasProbe` runs the same code path as the authenticator (vendor crypto, our transport, proxy
from the environment, trust store from `KC_TRUSTSTORE_PATHS`) without Keycloak, realm or flow –
e.g. from inside the running Keycloak container before the browser flow is switched:

```bash
/opt/keycloak/bin/sas-probe.sh '<Token Validator URL>' <agent key file> <sas user> <otp>
```

| Output / exit code | Meaning |
|---|---|
| `ACCEPTED` / 0 | OTP valid, everything works |
| `REJECTED` / 1 | SAS reachable, key file valid, OTP or user rejected. With a deliberately wrong OTP the expected result: the whole chain (proxy, TLS, key file, crypto) works |
| `UNSUPPORTED` / 2 | SAS wants a challenge, PIN change or push |
| `ERROR` / 3 | network, proxy, TLS or key file – details in the output |

The first lines show the proxy that will be used and how many certificates came from
`KC_TRUSTSTORE_PATHS`. **A wrong OTP counts as a failed attempt in SAS** (lockout policy), so
use a test account or a real OTP. Without the wrapper script:
`java -cp "/opt/keycloak/providers/*:/opt/keycloak/lib/lib/main/*:/opt/keycloak/lib/lib/boot/*" nrw.sit.keycloak.authenticator.sas.SasProbe …`

## Build

```bash
export THALES_JARS_PASSPHRASE=...
thales/decrypt.sh && thales/install.sh      # Thales JARs -> thales/lib and ~/.m2
mvn package                                 # target/keycloak-sas-otp-authenticator-<v>-kc<kc>.jar
mvn package -Dkeycloak.version=26.x.y       # against another Keycloak version
```

Java 17 bytecode; Keycloak 26 itself runs on Java 21+.

## Tests

| What | Where | Needs |
|---|---|---|
| Unit tests | `mvn test` | Thales JARs in `~/.m2` |
| End-to-end | `ci/sas-e2e/run.sh [kc-version] [jar]` | Java 21, Python 3, curl, `thales/lib` |

- `EnvProxySelectorTest` – proxy selection from the environment (case, `host:port`,
  `NO_PROXY` exact / suffix / `*.suffix` / `*`)
- `SitTokenValidatorWrapperTest` – transport against an in-JVM SOAP mock: envelope and
  headers (`SOAPAction`, `AgentInfo`, `Content-Type`, `Accept`) identical to the vendor client,
  HTTP errors, missing result, host down
- `SasEndToEndTest` – **real vendor crypto on both ends**: `SasMockServer` generates an agent
  key file in the original format and decrypts requests / encrypts replies with the vendor class
- `ci/sas-e2e` – the official Keycloak distribution with this jar and the Thales JARs,
  `SasMockServer` as SAS, a browser flow built through the admin API, the login played with
  curl: OTP page after the password, empty / wrong / right OTP, key file as path and as
  content, User Id Mapper, SAS unreachable (en/de message), unconfigured execution

Manual test against a local Keycloak:

```bash
java -cp "target/test-classes:target/classes:thales/lib/*:<KC>/lib/lib/main/*:<KC>/lib/lib/boot/*" \
  nrw.sit.keycloak.authenticator.sas.SasMockServer 9999 /tmp/test.bsidkey
# execution config: http://<host>:9999/TokenValidator/TokenValidator.asmx, /tmp/test.bsidkey; OTP 123456
```

## CI

| Workflow | When | What |
|---|---|---|
| `tests.yml` | push, PR | `mvn verify` (unit tests) |
| `sas-e2e.yml` | push, PR, manual (optional Keycloak version) | `ci/sas-e2e/run.sh` |
| `keycloak-compat.yml` | daily, manual | newest Keycloak release from Maven Central newer than `keycloak.version` in `pom.xml` → build + unit tests + e2e against it, result as issue `[kc-compat] Keycloak <version> – compatibility check` |

All three need the repository secret **`THALES_JARS_PASSPHRASE`** (decrypts
`thales/thales-jars.tar.gpg`). Pull requests from forks get no secrets and fail at that step.

After a green compatibility issue: bump `keycloak.version` in `pom.xml`.
