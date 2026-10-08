# VM test: the real binary, a stub Falcon, and the assertions only a booted
# machine can make: the unit comes up hardened, the client secret is
# delivered by systemd and reaches the token endpoint, the startup probe hides
# a refused scope, a 429 is waited out, a triage write carries its reason,
# and neither the secret nor the bearer ever lands in the journal, even with
# DEBUG and SWAGGER_DEBUG set (gofalcon, which this client replaced, logs the
# secret under them; see docs/adr/0001).
#
# Not covered: real Falcon payload shapes, token expiry, cloud autodiscovery
# (unit-tested only). Those need a live tenant.
{ pkgs, self }:

let
  stubPort = 9443;
  mcpPort = 8235;

  clientId = "vm-test-client";
  clientSecret = "s3cr3t-falcon-client-secret";
  accessToken = "issued-falcon-access-token";
  httpToken = "mcp-http-bearer";
  alertId = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:ind:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:1";
  reason = "vm test: confirmed benign";

  # Records every secret, bearer and alert comment it sees under /tmp/stub-*,
  # so the test can prove each one made it onto the wire.
  stub = pkgs.writers.writePython3Bin "stub-falcon" { flakeIgnore = [ "E501" ]; } ''
    import http.server
    import json
    import time
    import urllib.parse

    CLIENT_ID = ${builtins.toJSON clientId}
    SECRET = ${builtins.toJSON clientSecret}
    TOKEN = ${builtins.toJSON accessToken}
    ALERT = ${builtins.toJSON alertId}
    throttled = False


    def record(name, value):
        with open("/tmp/stub-" + name, "a") as fh:
            fh.write(value + "\n")


    class Handler(http.server.BaseHTTPRequestHandler):
        def reply(self, status, payload, headers=None):
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Cs-Region", "us-1")
            self.send_header("X-Ratelimit-Limit", "1000")
            self.send_header("X-Ratelimit-Remaining", "999")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def error(self, code, message, headers=None):
            self.reply(code, {"errors": [{"code": code, "message": message}]}, headers)

        def ok(self, resources, **meta):
            self.reply(200, {"meta": {"trace_id": "stub-trace", **meta},
                             "resources": resources, "errors": []})

        def body(self):
            n = int(self.headers.get("Content-Length", "0"))
            return self.rfile.read(n).decode()

        def handle_any(self):
            global throttled
            url = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(url.query)
            if self.command == "POST" and url.path == "/oauth2/token":
                form = urllib.parse.parse_qs(self.body())
                secret = form.get("client_secret", [""])[0]
                record("secrets", secret)
                if form.get("client_id", [""])[0] != CLIENT_ID or secret != SECRET:
                    return self.error(401, "access denied, invalid client")
                return self.reply(201, {"access_token": TOKEN, "expires_in": 1799,
                                        "token_type": "bearer"})

            bearer = self.headers.get("Authorization", "")
            record("bearers", bearer)
            if bearer != "Bearer " + TOKEN:
                return self.error(401, "access denied, invalid bearer token")

            if url.path.startswith("/spotlight/"):
                return self.error(403, "access denied, scope not permitted")

            if url.path == "/alerts/queries/alerts/v2":
                # The startup probe asks for limit=1; throttle the first real search.
                if query.get("limit") != ["1"] and not throttled:
                    throttled = True
                    record("throttled", "429")
                    return self.error(429, "API rate limit exceeded.",
                                      {"X-RateLimit-RetryAfter": str(int(time.time()) + 1)})
                return self.ok([ALERT], pagination={"offset": 0, "limit": 50, "total": 1})

            if url.path == "/alerts/entities/alerts/v2" and self.command == "POST":
                ids = json.loads(self.body() or "{}").get("composite_ids", [])
                return self.ok([{"composite_id": i, "status": "new", "severity_name": "High",
                                 "display_name": "stub alert"} for i in ids])

            if url.path == "/alerts/entities/alerts/v3" and self.command == "PATCH":
                sent = json.loads(self.body() or "{}")
                for p in sent.get("action_parameters", []):
                    if p.get("name") == "append_comment":
                        record("comments", p.get("value", ""))
                return self.ok([])

            # Every other probe route and read: an empty, successful page.
            return self.ok([], pagination={"offset": 0, "limit": 1, "total": 0})

        do_GET = do_POST = do_PATCH = do_PUT = do_DELETE = handle_any

        def log_message(self, *args):
            pass


    addr = ("127.0.0.1", ${toString stubPort})
    http.server.ThreadingHTTPServer(addr, Handler).serve_forever()
  '';

  # A full MCP session over streamable HTTP. Streamable HTTP may answer as
  # JSON or as an SSE frame; accept both.
  session = pkgs.writers.writePython3Bin "mcp-session" { flakeIgnore = [ "E501" ]; } ''
    import json
    import urllib.request

    URL = "http://127.0.0.1:${toString mcpPort}/mcp"
    BEARER = ${builtins.toJSON httpToken}
    ALERT = ${builtins.toJSON alertId}
    REASON = ${builtins.toJSON reason}
    ids = iter(range(1, 100))


    def post(payload, session=None):
        req = urllib.request.Request(URL, data=json.dumps(payload).encode(), method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json, text/event-stream")
        req.add_header("Authorization", "Bearer " + BEARER)
        if session:
            req.add_header("Mcp-Session-Id", session)
        resp = urllib.request.urlopen(req, timeout=30)
        raw = resp.read().decode()
        for line in raw.splitlines():
            if line.startswith("data:"):
                raw = line[5:].strip()
                break
        return resp.headers.get("Mcp-Session-Id"), json.loads(raw) if raw.strip() else {}


    session, init = post({
        "jsonrpc": "2.0", "id": next(ids), "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "vm-test", "version": "0"}},
    })
    assert init["result"]["serverInfo"]["name"] == "falcon-mcp", init
    post({"jsonrpc": "2.0", "method": "notifications/initialized"}, session)


    def call(name, args):
        _, out = post({"jsonrpc": "2.0", "id": next(ids), "method": "tools/call",
                       "params": {"name": name, "arguments": args}}, session)
        res = out["result"]
        assert not res.get("isError"), f"{name} {args}: {res}"
        return res["structuredContent"]


    _, listed = post({"jsonrpc": "2.0", "id": next(ids), "method": "tools/list"}, session)
    tools = {t["name"]: t for t in listed["result"]["tools"]}
    actions = {n: t["inputSchema"]["properties"].get("action", {}).get("enum", []) for n, t in tools.items()}

    # Vulnerabilities:read was refused, so its action is gone; the serverless
    # search on the same tool needs another scope and stays.
    assert "search" not in actions.get("falcon_vulnerability", []), actions.get("falcon_vulnerability")
    assert "search_serverless" in actions["falcon_vulnerability"], actions["falcon_vulnerability"]

    # Only triage is enabled: a tool loses readOnlyHint as soon as one write
    # action is visible, so every other typed tool must stay read-only.
    # falcon_api is writable with any capability on and names the enabled ones.
    writable = sorted(n for n, t in tools.items() if not t.get("annotations", {}).get("readOnlyHint"))
    assert writable == ["falcon_alert", "falcon_api", "falcon_case"], f"writable tools: {writable}"
    assert "capability is enabled (triage)" in tools["falcon_api"]["description"], tools["falcon_api"]["description"]
    assert "update" in actions["falcon_alert"], actions["falcon_alert"]
    assert "contain" not in actions["falcon_host"], actions["falcon_host"]
    # Capability-gated reads (rtr-read, rtr-respond) don't flip readOnlyHint.
    gated = {"init_session", "run_command", "list_files", "check_command_status", "check_responder_status"}
    assert not gated & set(actions.get("falcon_rtr", [])), actions.get("falcon_rtr")

    status = call("falcon_status", {})
    assert status["authenticated"] and status["api_reachable"], status
    assert status["capabilities"] == ["triage"], status["capabilities"]
    vuln = status["probe"]["Vulnerabilities:read"]
    assert vuln["state"] == "missing scope or not licensed", vuln
    assert status["probe"]["Alerts:read"]["state"] == "ok", status["probe"]["Alerts:read"]

    found = call("falcon_alert", {"action": "search", "filter": "status:'new'"})
    assert ALERT in json.dumps(found), found

    call("falcon_alert", {"action": "update", "ids": [ALERT],
                          "params": {"update_status": "closed"}, "reason": REASON})
    print(f"ok: {len(tools)} tools, writable {writable}")
  '';
in
pkgs.testers.runNixOSTest {
  name = "falcon-mcp-vm";

  nodes.machine =
    { ... }:
    {
      imports = [ self.nixosModules.falcon-mcp ];

      environment.systemPackages = [
        pkgs.curl
        session
      ];

      systemd.services.stub-falcon = {
        description = "Stub Falcon API";
        wantedBy = [ "multi-user.target" ];
        before = [ "falcon-mcp.service" ];
        serviceConfig = {
          ExecStart = pkgs.lib.getExe stub;
          Restart = "on-failure";
        };
      };

      # Root-only 0400 files, the shape sops-nix and agenix produce.
      systemd.tmpfiles.settings."10-falcon-mcp" = {
        "/run/falcon-client-secret".f = {
          user = "root";
          group = "root";
          mode = "0400";
          argument = clientSecret;
        };
        "/run/falcon-client-id".f = {
          user = "root";
          group = "root";
          mode = "0400";
          argument = clientId;
        };
        "/run/falcon-mcp-bearer".f = {
          user = "root";
          group = "root";
          mode = "0400";
          argument = httpToken;
        };
      };

      # gofalcon logs credentials under these (docs/adr/0001); ours must not.
      systemd.services.falcon-mcp.environment = {
        DEBUG = "1";
        SWAGGER_DEBUG = "1";
      };

      services.falcon-mcp = {
        enable = true;
        http.enable = true;
        http.authTokenFile = "/run/falcon-mcp-bearer";
        baseUrl = "http://127.0.0.1:${toString stubPort}";
        clientIdFile = "/run/falcon-client-id";
        clientSecretFile = "/run/falcon-client-secret";
        allow.triage = true;
        logLevel = "debug";
      };
    };

  testScript = ''
    import re

    machine.wait_for_unit("stub-falcon.service")
    machine.wait_for_unit("falcon-mcp.service")
    machine.wait_for_open_port(${toString mcpPort})

    with subtest("a full MCP session: status, search, triage write"):
        print(machine.succeed("mcp-session"))

    with subtest("the secret reached the token endpoint and the bearer reached the API"):
        machine.succeed("grep -qxF ${clientSecret} /tmp/stub-secrets")
        machine.succeed("grep -qxF 'Bearer ${accessToken}' /tmp/stub-bearers")

    with subtest("the alerts search waited out a 429"):
        machine.succeed("grep -qxF 429 /tmp/stub-throttled")

    with subtest("the reason went to Falcon as append_comment and to the audit log"):
        machine.succeed("grep -qF '${reason}' /tmp/stub-comments")
        machine.succeed(
            "journalctl -u falcon-mcp.service -o cat "
            "| grep -F 'msg=\"falcon write\"' | grep -F 'reason=\"${reason}\"' "
            "| grep -qF '${alertId}'"
        )

    with subtest("the credentials are not readable by anything else"):
        creds = "/run/credentials/falcon-mcp.service"
        # systemd's layout: root-group only; the unit reads them through an ACL.
        modes = {p: machine.succeed(f"stat -L -c %a:%G {creds}/{p}").strip()
                 for p in ("", "client-secret", "client-id", "http-auth-token")}
        print(modes)
        want = {p: "440:root" for p in ("client-secret", "client-id", "http-auth-token")}
        assert modes == {"": "550:root", **want}, modes
        machine.fail(f"runuser -u nobody -- cat {creds}/client-secret")

    pid = machine.succeed("systemctl show -p MainPID --value falcon-mcp.service").strip()

    with subtest("the secrets are in neither argv nor the environment"):
        for f in ("cmdline", "environ"):
            for secret in ("${clientSecret}", "${httpToken}"):
                machine.fail(f"tr '\\0' '\\n' < /proc/{pid}/{f} | grep -qF {secret}")
        # The leak check below means nothing unless these reached the process.
        for var in ("DEBUG=1", "SWAGGER_DEBUG=1"):
            machine.succeed(f"tr '\\0' '\\n' < /proc/{pid}/environ | grep -qx {var}")

    with subtest("the unit is actually hardened"):
        out = machine.succeed("systemd-analyze security falcon-mcp.service --no-pager | tail -1")
        print(out)
        # "Overall exposure level for falcon-mcp.service: 1.1 OK :-)"
        found = re.search(r"level for \S+: ([0-9.]+)", out)
        assert found is not None, f"could not read an exposure score from: {out}"
        assert float(found.group(1)) < 3.0, f"unit exposure score regressed: {out}"
        machine.fail(f"nsenter --mount --target {pid} -- test -w /etc")

    with subtest("it comes back healthy after a restart"):
        machine.succeed("truncate -s 0 /tmp/stub-secrets")
        machine.succeed("systemctl restart falcon-mcp.service")
        machine.wait_for_open_port(${toString mcpPort})
        machine.succeed("curl -fsS http://127.0.0.1:${toString mcpPort}/healthz")
        # /healthz is static: a fresh token and a second session prove it is healthy.
        print(machine.succeed("mcp-session"))
        machine.succeed("grep -qxF ${clientSecret} /tmp/stub-secrets")

    with subtest("the journal never holds the client secret or a bearer"):
        journal = machine.succeed("journalctl -o cat --no-pager")
        assert "starting" in journal and "falcon request" in journal, "debug logging did not run"
        for secret in ("${clientSecret}", "${accessToken}", "${httpToken}"):
            assert secret not in journal, f"{secret} leaked into the journal"
  '';
}
