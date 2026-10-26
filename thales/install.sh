#!/usr/bin/env bash
# =====================================================================
# install.sh - put the Thales JARs into the local Maven repository
#
#   thales/install.sh [jar-dir]           (default: thales/lib, see decrypt.sh)
#
# Installs com.safenet.keycloak.agent:{commons,token-validator-adapter}:1.5.0,
# which pom.xml references with scope "provided". Each JAR gets a minimal POM:
# commons.jar embeds a POM whose Thales-internal parent
# (common-parent:1.0.0-SNAPSHOT) Maven would otherwise try to download.
# =====================================================================
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${1:-$HERE/lib}"
VERSION=1.5.0
MVN="${MVN:-mvn -B -q}"

for f in commons.jar token-validator-adapter-jar-with-dependencies.jar; do
  [ -f "$SRC/$f" ] || { echo "[thales] $SRC/$f missing (thales/decrypt.sh)" >&2; exit 1; }
done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

install_jar() {
  local artifact="$1" jar="$2"
  printf '<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion><groupId>com.safenet.keycloak.agent</groupId><artifactId>%s</artifactId><version>%s</version><packaging>jar</packaging></project>\n' \
    "$artifact" "$VERSION" > "$TMP/$artifact.pom"
  $MVN install:install-file -Dfile="$jar" -DpomFile="$TMP/$artifact.pom"
}

install_jar commons "$SRC/commons.jar"
install_jar token-validator-adapter "$SRC/token-validator-adapter-jar-with-dependencies.jar"
echo "[thales] installed com.safenet.keycloak.agent:*:$VERSION into the local Maven repository"
