#!/usr/bin/env python3
"""
End-to-end test for sit-auth-otp-form-sas against a running Keycloak and the SAS mock
(SasMockServer: real vendor crypto, accepts OTP 123456 for every user).

Browser flow built through the admin API:

  sas-browser
    ├─ Cookie                                   ALTERNATIVE
    └─ forms (sub-flow)                         ALTERNATIVE
       ├─ Username Password Form                REQUIRED
       └─ SIT: OTP Form (SAS PCE / Thales)      REQUIRED   (config: TokenValidator URL, key file)

Checks:
  S1  after the password the standard OTP page (login-otp.ftl) is shown
  S2  an empty OTP re-renders the page with "Please specify authenticator code."
  S3  a wrong OTP re-renders the page with "Invalid authenticator code." (SAS answered 0)
  S4  the right OTP logs alice in (302 with code, token for alice; SAS saw alice/123456)
  S5  agent key file given as Base64 content instead of a path works as well
  S6  "User Id Mapper": the value of a user attribute is sent to SAS as user id
  S7  SAS unreachable: 503 error page with the shipped message, in German for de
  S8  execution without configuration: error page with the shipped message

Usage: sas_e2e.py <keycloak-url> <tv-url> <key-file-path> <key-file-content-file> [mock-log]
  tv-url and key-file-path as Keycloak sees them; key-file-content-file and mock-log are
  read locally (mock-log optional: without it the SAS-side assertions are skipped).
"""
import base64
import html
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

BASE = sys.argv[1].rstrip("/")
TV_URL = sys.argv[2]
KEY_PATH = sys.argv[3]
KEY_CONTENT = open(sys.argv[4]).read().strip()
MOCK_LOG = sys.argv[5] if len(sys.argv) > 5 and sys.argv[5] else None
DEAD_URL = "http://127.0.0.1:9/TokenValidator/TokenValidator.asmx"  # discard port, nothing listens

REALM = "sas"
CLIENT_ID = "sas-client"
REDIRECT_URI = BASE + "/sas/callback"
PROVIDER = "sit-auth-otp-form-sas"
FLOW = "sas-browser"
VALID_OTP = "123456"

failures = []
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def check(label, fn):
    try:
        detail = fn()
        print("OK    %s%s" % (label, (" - " + detail) if detail else ""))
        return True
    except Exception as e:  # noqa: BLE001 - every deviation is a finding
        failures.append(label)
        print("FAIL  %s - %s" % (label, e))
        return False


def api(method, path, body=None, token=None, form=None, expect=(200, 201, 204)):
    url = path if path.startswith("http") else BASE + path
    headers = {}
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with opener.open(req, timeout=60) as resp:
            raw, status = resp.read(), resp.status
    except urllib.error.HTTPError as e:
        raw, status = e.read(), e.code
    if status not in expect:
        raise RuntimeError("%s %s -> HTTP %d: %s" % (method, path, status, raw[:300].decode("utf-8", "replace")))
    if raw:
        try:
            return json.loads(raw)
        except ValueError:
            return raw.decode("utf-8", "replace")
    return None


def admin_token():
    return api("POST", "/realms/master/protocol/openid-connect/token", form={
        "grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": "admin"})["access_token"]


class Browser:
    """curl with a cookie jar and no automatic redirects."""

    def __init__(self, lang="en"):
        self.dir = tempfile.mkdtemp(prefix="sas-")
        self.jar = os.path.join(self.dir, "cookies")
        self.lang = lang

    def request(self, method, url, data=None):
        hdr = os.path.join(self.dir, "headers")
        cmd = ["curl", "-s", "--noproxy", "*", "-c", self.jar, "-b", self.jar, "-D", hdr,
               "-o", "-", "-w", "\n%{http_code}", "-X", method, "-H", "Accept-Language: " + self.lang]
        if data is not None:
            cmd += ["--data", urllib.parse.urlencode(data)]
        cmd.append(url)
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if out.returncode != 0:
            raise RuntimeError("curl failed (%d): %s" % (out.returncode, out.stderr.strip()[:300]))
        body, _, status = out.stdout.rpartition("\n")
        headers = {}
        with open(hdr) as fh:
            for line in fh.read().splitlines()[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
        return int(status), headers, body


def form_action(body, form_id):
    m = re.search(r'<form[^>]*id="%s"[^>]*action="([^"]+)"' % re.escape(form_id), body)
    if not m:
        raise RuntimeError("form '%s' not in page: %s" % (form_id, snippet(body)))
    return html.unescape(m.group(1))


def snippet(body):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body))[:300]


def auth_url():
    return BASE + "/realms/%s/protocol/openid-connect/auth?" % REALM + urllib.parse.urlencode({
        "client_id": CLIENT_ID, "response_type": "code", "redirect_uri": REDIRECT_URI, "scope": "openid"})


def mock_log():
    if not MOCK_LOG:
        return None
    with open(MOCK_LOG) as fh:
        return fh.read()


# ── setup ───────────────────────────────────────────────────────────────────

def setup(t):
    r = "/admin/realms/" + REALM
    api("DELETE", r, token=t, expect=(204, 404))
    api("POST", "/admin/realms", {"realm": REALM, "enabled": True, "defaultLocale": "en",
                                   "internationalizationEnabled": True, "supportedLocales": ["en", "de"]}, token=t)
    api("POST", r + "/clients", {"clientId": CLIENT_ID, "publicClient": True, "standardFlowEnabled": True,
                                  "redirectUris": [REDIRECT_URI], "enabled": True}, token=t)
    # allow the free-form attribute used by the "User Id Mapper" check
    profile = api("GET", r + "/users/profile", token=t)
    profile["unmanagedAttributePolicy"] = "ADMIN_EDIT"
    api("PUT", r + "/users/profile", profile, token=t)
    for name, attrs in (("alice", {}), ("carol", {"sasid": ["carol-in-sas"]})):
        api("POST", r + "/users", {
            "username": name, "enabled": True, "email": name + "@example.test", "emailVerified": True,
            "firstName": name.capitalize(), "lastName": "Example", "attributes": attrs,
            "credentials": [{"type": "password", "value": name + "pw", "temporary": False}]}, token=t)

    q = urllib.parse.quote
    api("POST", r + "/authentication/flows",
        {"alias": FLOW, "providerId": "basic-flow", "topLevel": True, "builtIn": False, "description": ""}, token=t)
    add_execution(t, FLOW, "auth-cookie", "ALTERNATIVE")
    forms = FLOW + " forms"
    api("POST", r + "/authentication/flows/%s/executions/flow" % q(FLOW),
        {"alias": forms, "type": "basic-flow", "provider": "registration-page-form", "description": ""}, token=t)
    set_requirement(t, FLOW, [e for e in top(t, FLOW) if e.get("displayName") == forms][-1], "ALTERNATIVE")
    add_execution(t, forms, "auth-username-password-form", "REQUIRED")
    ex = add_execution(t, forms, PROVIDER, "REQUIRED")
    api("POST", r + "/authentication/executions/%s/config" % ex,
        {"alias": "sas-otp", "config": {"tokenvalidator.url": TV_URL, "agent.bsidkey": KEY_PATH}}, token=t)
    api("PUT", r, {"browserFlow": FLOW}, token=t)
    return forms


def top(t, alias):
    execs = api("GET", "/admin/realms/%s/authentication/flows/%s/executions" % (REALM, urllib.parse.quote(alias)), token=t)
    return [e for e in execs if e.get("level", 0) == 0]


def set_requirement(t, alias, execution, requirement):
    rep = dict(execution)
    rep["requirement"] = requirement
    api("PUT", "/admin/realms/%s/authentication/flows/%s/executions" % (REALM, urllib.parse.quote(alias)), rep, token=t)


def add_execution(t, alias, provider, requirement):
    api("POST", "/admin/realms/%s/authentication/flows/%s/executions/execution" % (REALM, urllib.parse.quote(alias)),
        {"provider": provider}, token=t)
    ex = [e for e in top(t, alias) if e.get("providerId") == provider][-1]
    set_requirement(t, alias, ex, requirement)
    return ex["id"]


def sas_config(t, forms):
    ex = [e for e in top(t, forms) if e.get("providerId") == PROVIDER][0]
    return api("GET", "/admin/realms/%s/authentication/config/%s" % (REALM, ex["authenticationConfig"]), token=t)


def update_config(t, forms, **values):
    cfg = sas_config(t, forms)
    cfg["config"].update(values)
    api("PUT", "/admin/realms/%s/authentication/config/%s" % (REALM, cfg["id"]), cfg, token=t)


# ── scenarios ───────────────────────────────────────────────────────────────

def password_step(b, username):
    status, _, body = b.request("GET", auth_url())
    if status != 200 or 'id="kc-form-login"' not in body:
        raise RuntimeError("login form expected, got HTTP %d: %s" % (status, snippet(body)))
    return b.request("POST", form_action(body, "kc-form-login"), data={"username": username, "password": username + "pw"})


def otp_page(b, username):
    status, _, body = password_step(b, username)
    if status != 200 or 'id="kc-otp-login-form"' not in body:
        raise RuntimeError("OTP page expected, got HTTP %d: %s" % (status, snippet(body)))
    return body


def submit_otp(b, page, otp):
    return b.request("POST", form_action(page, "kc-otp-login-form"), data={"otp": otp})


def token_user(location):
    code = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)["code"][0]
    tok = api("POST", "/realms/%s/protocol/openid-connect/token" % REALM, form={
        "grant_type": "authorization_code", "client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI, "code": code})
    payload = tok["access_token"].split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload)).get("preferred_username")


def full_login(username):
    b = Browser()
    status, headers, body = submit_otp(b, otp_page(b, username), VALID_OTP)
    loc = headers.get("location", "")
    if status != 302 or not loc.startswith(REDIRECT_URI) or "code=" not in loc:
        raise RuntimeError("HTTP %d %s: %s" % (status, loc, snippet(body)))
    user = token_user(loc)
    if user != username:
        raise RuntimeError("token for %r" % user)


def expect_page_error(status, body, want_status, text):
    if status != want_status:
        raise RuntimeError("HTTP %d instead of %d: %s" % (status, want_status, snippet(body)))
    if text not in body:
        raise RuntimeError("'%s' missing: %s" % (text, snippet(body)))
    if re.search(r"\bsasOtp[A-Z]\w+", body):
        raise RuntimeError("raw message key on the page, messages not loaded")


def main():
    t = admin_token()
    forms = setup(t)
    print("realm %s configured, TokenValidator %s, key file %s" % (REALM, TV_URL, KEY_PATH))
    state = {}

    def s1():
        b = Browser()
        state["b"], state["page"] = b, otp_page(b, "alice")
        return "login-otp.ftl after the password form"
    if not check("S1 the OTP page follows the password", s1):
        return finish()

    def s2():
        status, _, body = submit_otp(state["b"], state["page"], "")
        if status != 200 or 'id="kc-otp-login-form"' not in body or "Please specify authenticator code." not in body:
            raise RuntimeError("HTTP %d: %s" % (status, snippet(body)))
        state["page"] = body
        return "page again with 'Please specify authenticator code.'"
    check("S2 an empty OTP is rejected without asking SAS", s2)

    def s3():
        status, _, body = submit_otp(state["b"], state["page"], "999999")
        if status != 200 or 'id="kc-otp-login-form"' not in body or "Invalid authenticator code." not in body:
            raise RuntimeError("HTTP %d: %s" % (status, snippet(body)))
        log = mock_log()
        if log is not None and "user=alice passcode=999999 -> return_value=0" not in log:
            raise RuntimeError("SAS mock did not see alice/999999: %s" % log[-300:])
        return "page again with 'Invalid authenticator code.'"
    check("S3 a wrong OTP is rejected by SAS", s3)

    def s4():
        full_login("alice")
        log = mock_log()
        if log is not None and "user=alice passcode=%s -> return_value=1" % VALID_OTP not in log:
            raise RuntimeError("SAS mock did not see alice/%s" % VALID_OTP)
        return "302 with code, token for alice"
    check("S4 the right OTP logs alice in", s4)

    def s5():
        update_config(t, forms, **{"agent.bsidkey": KEY_CONTENT})
        try:
            full_login("alice")
        finally:
            update_config(t, forms, **{"agent.bsidkey": KEY_PATH})
        return "login with the key file content in the execution config"
    check("S5 agent key file as Base64 content", s5)

    def s6():
        update_config(t, forms, **{"user.id.mapper": "sasid"})
        try:
            full_login("carol")
        finally:
            update_config(t, forms, **{"user.id.mapper": ""})
        log = mock_log()
        if log is not None and "user=carol-in-sas passcode=" not in log:
            raise RuntimeError("SAS mock did not get the mapped user id")
        return "SAS got 'carol-in-sas' for carol"
    check("S6 User Id Mapper sends the attribute value", s6)

    def s7():
        update_config(t, forms, **{"tokenvalidator.url": DEAD_URL})
        try:
            b = Browser()
            status, _, body = submit_otp(b, otp_page(b, "alice"), VALID_OTP)
            expect_page_error(status, body, 503, "currently unavailable")
            b = Browser("de")
            status, _, body = submit_otp(b, otp_page(b, "alice"), VALID_OTP)
            expect_page_error(status, body, 503, "derzeit nicht erreichbar")
        finally:
            update_config(t, forms, **{"tokenvalidator.url": TV_URL})
        return "HTTP 503 with the shipped message (en, de)"
    check("S7 SAS unreachable gives the 'unavailable' page", s7)

    def s8():
        cfg = sas_config(t, forms)
        api("DELETE", "/admin/realms/%s/authentication/config/%s" % (REALM, cfg["id"]), token=t)
        b = Browser()
        status, _, body = password_step(b, "alice")
        expect_page_error(status, body, 500, "not configured")
        return "HTTP 500 with the shipped message"
    check("S8 an unconfigured execution gives the 'not configured' page", s8)

    return finish()


def finish():
    print()
    print("%d check(s) failed" % len(failures) if failures else "all checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
