#!/usr/bin/env bash
# =====================================================================
# repack.sh - build the two library JARs from the Thales SafeNet Agent package
#
#   thales/repack.sh <package>/Installer/SafenetKeycloakAgentPackage/customization <target-dir>
#
# Agent 1.5.0 (built for Keycloak 24.0.5) bundles libraries that Keycloak 26
# ships itself in newer versions (commons-lang3, JAXB, activation); with the
# bundled copies Keycloak fails at start with NoSuchMethodError. This script
# copies only commons.jar and token-validator-adapter-jar-with-dependencies.jar
# (sas-authenticator / sas-services with the Thales flow and its server-wide
# login-forms override stay out) and strips those libraries.
#
# After a new Thales package: run this, then re-encrypt (thales/README.md).
# =====================================================================
set -euo pipefail
SRC="$1"; DST="$2"; mkdir -p "$DST"
cp "$SRC"/commons.jar "$SRC"/token-validator-adapter-jar-with-dependencies.jar "$DST"/
cd "$DST"
zip -q -d token-validator-adapter-jar-with-dependencies.jar \
  'org/apache/commons/lang3/*' 'jakarta/xml/bind/*' 'jakarta/activation/*' 'com/sun/activation/*' \
  'META-INF/versions/9/*' 'module-info.class' \
  'META-INF/maven/org.apache.commons/*' 'META-INF/maven/jakarta.*' 'META-INF/maven/com.sun.activation/*'
