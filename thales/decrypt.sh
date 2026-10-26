#!/usr/bin/env bash
# =====================================================================
# decrypt.sh - unpack the Thales SafeNet Agent JARs from thales-jars.tar.gpg
#
#   thales/decrypt.sh [target-dir]        (default: thales/lib)
#
# The JARs are proprietary Thales code and must not be published in clear
# text, so the public repository only carries them GPG-encrypted
# (AES256, symmetric). The passphrase comes from $THALES_JARS_PASSPHRASE
# (GitHub Actions secret of the same name); without it gpg asks for it.
#
# Contents (already patched with thales/repack.sh, see thales/README.md):
#   commons.jar
#   token-validator-adapter-jar-with-dependencies.jar
#   SHA256SUMS
# =====================================================================
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DST="${1:-$HERE/lib}"
mkdir -p "$DST"

GPG=(gpg --batch --quiet --yes --decrypt)
if [ -n "${THALES_JARS_PASSPHRASE:-}" ]; then
  GPG=(gpg --batch --quiet --yes --pinentry-mode loopback --passphrase-fd 3 --decrypt)
  exec 3<<<"$THALES_JARS_PASSPHRASE"
elif [ ! -t 0 ]; then
  echo "[thales] THALES_JARS_PASSPHRASE is not set (GitHub: repository secret of the same name)" >&2
  exit 1
fi

"${GPG[@]}" "$HERE/thales-jars.tar.gpg" | tar -xf - -C "$DST"
(cd "$DST" && sha256sum --quiet -c SHA256SUMS)
rm -f "$DST/SHA256SUMS"
echo "[thales] JARs in $DST"
