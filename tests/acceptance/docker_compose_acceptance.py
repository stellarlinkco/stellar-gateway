#!/usr/bin/env python3
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ["docker", "compose", "-f", "docker-compose.acceptance.yml"]
APEX_HOST = "hdd.ink"
HOST = "demo.hdd.ink"
HTTP_PORT = os.environ.get("ACCEPTANCE_HTTP_PORT", "28080")
HTTPS_PORT = os.environ.get("ACCEPTANCE_HTTPS_PORT", "28443")


def run(args, **kwargs):
    check = kwargs.pop("check", True)
    return subprocess.run(args, cwd=ROOT, text=True, check=check, **kwargs)


def capture(args, **kwargs):
    return run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kwargs).stdout


def gatewayfile(upstream: str = "upstream:3000", reload_enabled: bool = True) -> str:
    return f"""listeners:
  http:
    bind: "0.0.0.0:8080"
  https:
    bind: "0.0.0.0:8443"

routes:
  apex:
    host: "hdd.ink"
    upstream:
      addr: "{upstream}"
      tls: false
  wildcard:
    suffix: "hdd.ink"
    upstream:
      addr: "{upstream}"
      tls: false

tls:
  ask_url: "http://ask:9000/ask"

acme:
  directory_url: "https://pebble:14000/dir"
  email: "admin@example.com"
  http_01: true
  ca_cert_path: "/app/tests/fixtures/pebble.minica.pem"

cert_cache:
  dir: "/cache"

reload:
  enabled: {str(reload_enabled).lower()}

logging:
  level: "info"
"""


def write_gatewayfile(contents: str):
    acc = ROOT / ".acceptance"
    acc.mkdir(exist_ok=True)
    (acc / "cert-cache").mkdir(exist_ok=True)
    (acc / "Gatewayfile").write_text(contents)


def curl(args):
    return capture(["curl", "--noproxy", "*", "-fsS", "--max-time", "8", *args])


def wait_for_http(expected: str, host: str = HOST):
    deadline = time.time() + 60
    last = ""
    while time.time() < deadline:
        try:
            last = curl(["-H", f"Host: {host}", f"http://127.0.0.1:{HTTP_PORT}/"])
            if expected in last:
                return
        except subprocess.CalledProcessError as err:
            last = err.stdout or str(err)
        time.sleep(1)
    raise AssertionError(f"HTTP route for {host} did not return {expected!r}; last={last!r}")


def assert_https_issues_and_proxies():
    deadline = time.time() + 90
    last = ""
    while time.time() < deadline:
        try:
            out = curl([
                "-k",
                "--resolve",
                f"{HOST}:{HTTPS_PORT}:127.0.0.1",
                f"https://{HOST}:{HTTPS_PORT}/",
            ])
            if "upstream-one" in out:
                return
            last = out
        except subprocess.CalledProcessError as err:
            last = err.stdout or str(err)
        time.sleep(2)
    logs = capture([*COMPOSE, "logs", "--no-color", "gateway"], check=False)
    raise AssertionError(f"HTTPS ACME proxy did not pass; last={last!r}\nlogs:\n{logs}")


def assert_non_matching_host_rejected():
    result = subprocess.run(
        [
            "curl",
            "--noproxy",
            "*",
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "-H",
            "Host: example.com",
            f"http://127.0.0.1:{HTTP_PORT}/",
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if result.stdout.strip() != "404":
        raise AssertionError(f"expected 404 for non-matching host, got {result.stdout!r}")


def assert_health_and_metrics():
    deadline = time.time() + 60
    last = ""
    while time.time() < deadline:
        try:
            health = curl([f"http://127.0.0.1:{HTTP_PORT}/health"])
            metrics = curl([f"http://127.0.0.1:{HTTP_PORT}/metrics"])
            if health == "ok\n" and "stellar_gateway_requests_total" in metrics:
                return
            last = f"health={health!r}; metrics={metrics!r}"
        except subprocess.CalledProcessError as err:
            last = err.stdout or str(err)
        time.sleep(1)
    raise AssertionError(f"health/metrics did not pass; last={last!r}")


def main():
    if (ROOT / ".acceptance").exists():
        shutil.rmtree(ROOT / ".acceptance")
    write_gatewayfile(gatewayfile())

    try:
        run([*COMPOSE, "up", "-d", "--build"])
        assert_health_and_metrics()
        wait_for_http("upstream-one", APEX_HOST)
        wait_for_http("upstream-one", HOST)
        assert_non_matching_host_rejected()
        assert_https_issues_and_proxies()
        run([*COMPOSE, "exec", "-T", "gateway", "test", "-f", f"/cache/{HOST}.yaml"])

        write_gatewayfile(gatewayfile("upstream2:3001"))
        run([*COMPOSE, "kill", "-s", "HUP", "gateway"])
        wait_for_http("upstream-two")

        write_gatewayfile("listeners: {}\n")
        run([*COMPOSE, "kill", "-s", "HUP", "gateway"])
        wait_for_http("upstream-two")

        write_gatewayfile(gatewayfile("upstream2:3001"))
        run([*COMPOSE, "restart", "gateway"])
        wait_for_http("upstream-two")
        out = curl([
            "-k",
            "--resolve",
            f"{HOST}:{HTTPS_PORT}:127.0.0.1",
            f"https://{HOST}:{HTTPS_PORT}/",
        ])
        if "upstream-two" not in out:
            raise AssertionError(f"cached HTTPS after restart failed: {out!r}")
    finally:
        if os.environ.get("KEEP_ACCEPTANCE") != "1":
            run([*COMPOSE, "down", "-v"], check=False)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"acceptance failed: {exc}", file=sys.stderr)
        sys.exit(1)
