# Thales SafeNet Agent JARs

The authenticator compiles against, and at runtime needs, two library JARs from the
**SafeNet Agent for Keycloak 1.5.0** package (Thales, proprietary):

| File | Content |
|---|---|
| `commons.jar` | agent key file handling, AES-GCM crypto |
| `token-validator-adapter-jar-with-dependencies.jar` | TokenValidator request/response DTOs, `TokenValidatorWrapperImpl` |

They are **not** redistributable, so this public repository only carries them encrypted:
`thales-jars.tar.gpg` (GPG symmetric, AES256). The passphrase is the repository secret
`THALES_JARS_PASSPHRASE`; outside GitHub ask the maintainers.

```bash
export THALES_JARS_PASSPHRASE=...      # or leave unset and type it when gpg asks
thales/decrypt.sh                      # -> thales/lib/*.jar (git-ignored), checksums verified
thales/install.sh                      # -> ~/.m2 as com.safenet.keycloak.agent:*:1.5.0
```

Both JARs also go into Keycloak's `providers/` next to the authenticator JAR.

## Why patched

Agent 1.5.0 targets Keycloak 24.0.5 and bundles commons-lang3 3.11 and JAXB/activation.
Keycloak 26 ships newer versions of these, and the bundled copies cause
`NoSuchMethodError` at server start. `repack.sh` removes them from the fat JAR; the
authenticator then uses Keycloak's own copies (unit tests get them as test dependencies,
see `pom.xml`).

## New Thales package

```bash
thales/repack.sh <package>/Installer/SafenetKeycloakAgentPackage/customization /tmp/thales
(cd /tmp/thales && sha256sum *.jar > SHA256SUMS \
  && tar --sort=name --owner=0 --group=0 --mtime=2026-01-01 -cf thales-jars.tar *.jar SHA256SUMS)
gpg --symmetric --cipher-algo AES256 -o thales/thales-jars.tar.gpg /tmp/thales/thales-jars.tar
```

Use the existing passphrase, or update the `THALES_JARS_PASSPHRASE` secret. If the version
changes, adjust `safenet.version` in `pom.xml` and `VERSION` in `install.sh`.
