#!/bin/bash
# =====================================================================
# sas-probe.sh - dry run against the real SAS PCE from inside the
# Keycloak container (installed as /opt/keycloak/bin/sas-probe.sh).
#
#   sas-probe.sh <tokenValidatorUrl> <agentKeyFile> <sasUserId> <otp> [clientIp]
#
# Same code path as the authenticator (vendor crypto, our HTTP transport,
# proxy from HTTPS_PROXY/NO_PROXY, trust store from KC_TRUSTSTORE_PATHS),
# but without Keycloak, realm or browser flow.
#
#   ACCEPTED    (exit 0) OTP valid - everything works
#   REJECTED    (exit 1) SAS reachable, key file valid, OTP/user rejected
#                        -> the whole chain works; with a deliberately wrong OTP
#                           this is the expected dry-run result
#   UNSUPPORTED (exit 2) SAS wants challenge/PIN change/push (not implemented)
#   ERROR       (exit 3) network, proxy, TLS or key file problem - see output
#
# A wrong OTP counts as a failed attempt in SAS (lockout policy!), so use a
# test account or a real OTP.
# =====================================================================
KC_HOME="${KC_HOME:-/opt/keycloak}"
exec java -cp "$KC_HOME/providers/*:$KC_HOME/lib/lib/main/*:$KC_HOME/lib/lib/boot/*" \
  nrw.sit.keycloak.authenticator.sas.SasProbe "$@"
