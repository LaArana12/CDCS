#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import secrets
import time
from copy import deepcopy
from pathlib import Path
from typing import Any

import requests

ATTACKER_KEY = "attacker_user"
VICTIM_KEY = "victim_user"
ADMIN_KEY = "system_admin"


def load_json(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: JSON root phải là object")
    return data


def save_json(path: str | Path, data: dict[str, Any]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def safe_json(response: requests.Response) -> Any:
    try:
        return response.json()
    except Exception:
        return None


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in headers.items():
        result[key] = "Bearer <redacted>" if key.lower() == "authorization" else value
    return result


class TargetLabFuzzer:
    def __init__(self, base_url: str, seed_context: dict[str, Any], timeout: int = 10) -> None:
        self.base_url = base_url.rstrip("/")
        self.seed_context = seed_context
        self.timeout = timeout
        self.session = requests.Session()
        self.tokens: dict[str, str] = {}

    def account(self, key: str) -> dict[str, Any]:
        account = self.seed_context.get("accounts", {}).get(key)
        if not isinstance(account, dict):
            raise RuntimeError(f"Không tìm thấy account trong seed_context: {key}")
        resolved = dict(account)
        password = resolved.get("password")
        if isinstance(password, str) and password.startswith("${") and password.endswith("}"):
            env_name = password[2:-1]
            resolved["password"] = os.getenv(env_name)
            if not resolved["password"]:
                raise RuntimeError(f"Thiếu biến môi trường credential: {env_name}")
        return resolved

    def login(self, key: str) -> str:
        if key in self.tokens:
            return self.tokens[key]

        account = self.account(key)
        response = self.session.post(
            f"{self.base_url}/api/auth/login",
            json={"username": account["username"], "password": account["password"]},
            timeout=self.timeout,
        )
        if response.status_code != 200:
            raise RuntimeError(f"Login failed for {key}: {response.status_code} {response.text[:300]}")

        data = safe_json(response)
        token = data.get("access_token") if isinstance(data, dict) else None
        if not token:
            raise RuntimeError(f"Login response không có access_token cho {key}")

        self.tokens[key] = token
        return token

    def token_from_source(self, source: str | None) -> str | None:
        mapping = {
            "ATTACKER": ATTACKER_KEY,
            "VICTIM": VICTIM_KEY,
            "ADMIN": ADMIN_KEY,
        }
        key = mapping.get(str(source or "NONE").upper())
        return self.login(key) if key else None

    def runtime_headers(self, scenario: dict[str, Any], body: Any) -> dict[str, str]:
        headers = deepcopy(scenario.get("request", {}).get("headers", {}) or {})

        if str(headers.get("Authorization", "")).startswith("Bearer <"):
            headers.pop("Authorization", None)

        token_source = scenario.get("auth_context", {}).get("token_source", "NONE")
        token = self.token_from_source(token_source)
        if token:
            headers["Authorization"] = f"Bearer {token}"

        if body is not None:
            headers.setdefault("Content-Type", "application/json")

        return headers

    def fill_path(self, path: str, path_params: dict[str, Any]) -> str:
        params = dict(path_params or {})
        known = self.seed_context.get("known_objects", {}) or {}

        if "{order_id}" in path and "order_id" not in params:
            params["order_id"] = known.get("victim_order_id", 1001)

        for key, value in params.items():
            path = path.replace("{" + str(key) + "}", str(value))

        return path

    def send_request(self, scenario: dict[str, Any]) -> dict[str, Any]:
        req = scenario.get("request", {})
        target = scenario.get("target", {})

        method = str(req.get("method") or target.get("method") or "GET").upper()
        raw_path = str(req.get("path") or target.get("path") or "/")
        path = self.fill_path(raw_path, req.get("path_params", {}) or {})
        url = f"{self.base_url}{path}"

        query_params = req.get("query_params", {}) or {}
        body = req.get("body", None)
        headers = self.runtime_headers(scenario, body)

        started = time.time()
        response = self.session.request(
            method,
            url,
            params=query_params,
            json=body,
            headers=headers,
            timeout=self.timeout,
        )
        elapsed_ms = round((time.time() - started) * 1000, 2)

        return {
            "request": {
                "method": method,
                "url": url,
                "path": path,
                "headers": redact_headers(headers),
                "query_params": query_params,
                "body": body,
            },
            "response": {
                "status_code": response.status_code,
                "elapsed_ms": elapsed_ms,
                "json": safe_json(response),
                "text_preview": response.text[:1500],
            },
        }

    def get_me(self, token_source: str = "ATTACKER") -> dict[str, Any]:
        token = self.token_from_source(token_source)
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        response = self.session.get(f"{self.base_url}/api/users/me", headers=headers, timeout=self.timeout)
        return {
            "status_code": response.status_code,
            "json": safe_json(response),
            "text_preview": response.text[:1000],
        }

    def reset_attacker_role_if_possible(self) -> None:
        try:
            token = self.token_from_source("ATTACKER")
            self.session.patch(
                f"{self.base_url}/api/users/me",
                json={"role": "user"},
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                timeout=self.timeout,
            )
            self.tokens.pop(ATTACKER_KEY, None)
            self.login(ATTACKER_KEY)
        except Exception:
            pass

    def normalize_register_payload(self, scenario: dict[str, Any]) -> None:
        if scenario.get("vulnerability_type") != "MASS_ASSIGNMENT":
            return
        if scenario.get("target", {}).get("path") != "/api/auth/register":
            return

        body = scenario.get("request", {}).get("body")
        if not isinstance(body, dict):
            return

        suffix = int(time.time())
        username = f"{body.get('username', 'evil_admin_user')}_{suffix}"
        body["username"] = username
        body["email"] = f"{username}@test.com"
        body.setdefault("password", os.getenv("CDCS_REGISTRATION_PASSWORD") or secrets.token_urlsafe(18))
        body["role"] = "admin"

    def detect_ma_register(self, scenario: dict[str, Any], primary: dict[str, Any]) -> tuple[bool, str]:
        status = primary["response"]["status_code"]
        data = primary["response"].get("json")
        body = scenario.get("request", {}).get("body", {}) or {}

        if isinstance(data, dict) and data.get("role") == "admin":
            return True, "Response đăng ký trả về role=admin."

        if status not in (200, 201):
            return False, "Request đăng ký không thành công hoặc không có bằng chứng role=admin."

        username = body.get("username")
        password = body.get("password")
        if not username or not password:
            return False, "Không đủ username/password để login kiểm chứng user mới."

        try:
            login_r = self.session.post(
                f"{self.base_url}/api/auth/login",
                json={"username": username, "password": password},
                timeout=self.timeout,
            )
            login_json = safe_json(login_r)
            token = login_json.get("access_token") if isinstance(login_json, dict) else None
            if not token:
                return False, "User mới tạo được nhưng không login lấy token kiểm chứng được."

            me_r = self.session.get(
                f"{self.base_url}/api/users/me",
                headers={"Authorization": f"Bearer {token}"},
                timeout=self.timeout,
            )
            me_json = safe_json(me_r)
            if isinstance(me_json, dict) and (me_json.get("role") == "admin" or me_json.get("user_role") == "admin"):
                return True, "Tài khoản đăng ký mới có role=admin sau khi chèn field role."
        except Exception as exc:
            return False, f"Không kiểm chứng được user mới: {exc}"

        return False, "User mới không có role=admin khi kiểm chứng."

    def detect_ma_profile(self, primary: dict[str, Any]) -> tuple[bool, str]:
        status = primary["response"]["status_code"]
        data = primary["response"].get("json")

        if status == 200 and isinstance(data, dict):
            if data.get("role") == "admin" or data.get("user_role") == "admin":
                return True, "Response PATCH /api/users/me cho thấy role hoặc user_role=admin."

        me = self.get_me("ATTACKER")
        me_json = me.get("json")
        if me["status_code"] == 200 and isinstance(me_json, dict):
            if me_json.get("role") == "admin" or me_json.get("user_role") == "admin":
                return True, "GET /api/users/me sau PATCH cho thấy attacker_user có role=admin."

        return False, "Không thấy role attacker_user đổi thành admin."

    def detect_bola_order(self, primary: dict[str, Any]) -> tuple[bool, str]:
        status = primary["response"]["status_code"]
        data = primary["response"].get("json")
        text = primary["response"].get("text_preview", "")

        if status != 200:
            return False, "Endpoint không trả 200 nên chưa có bằng chứng BOLA."

        if isinstance(data, dict):
            owner = data.get("order_owner")
            requested_by = data.get("requested_by")

            if isinstance(owner, dict) and owner.get("username") == VICTIM_KEY:
                if isinstance(requested_by, dict) and requested_by.get("username") == ATTACKER_KEY:
                    return True, "attacker_user xem được order thuộc victim_user."
                return True, "Response trả về order_owner=victim_user khi attacker gọi order_id=1001."

            if data.get("user_id") or data.get("order_id") or data.get("id"):
                return True, "Endpoint trả dữ liệu order khi attacker_user truy cập order_id=1001."

        if "victim_user" in text or "order_owner" in text:
            return True, "Response text chứa dấu hiệu dữ liệu order của victim_user."

        return False, "Không thấy response trả dữ liệu order của victim_user cho attacker_user."

    def detect_bfla_admin_users(self, primary: dict[str, Any]) -> tuple[bool, str]:
        status = primary["response"]["status_code"]
        data = primary["response"].get("json")
        text = primary["response"].get("text_preview", "")

        if status != 200:
            return False, "User thường không gọi được /api/admin/users."

        if isinstance(data, list):
            return True, "User thường gọi /api/admin/users và nhận danh sách user."
        if isinstance(data, dict) and ("users" in data or "items" in data):
            return True, "User thường gọi /api/admin/users và response có danh sách user."
        if any(marker in text for marker in ["victim_user", "system_admin", "attacker_user"]):
            return True, "Response /api/admin/users chứa dữ liệu user hệ thống."
        return True, "Endpoint admin/users trả 200 cho user thường."

    def detect_bfla_order_status(self, primary: dict[str, Any]) -> tuple[bool, str]:
        status = primary["response"]["status_code"]
        data = primary["response"].get("json")

        if status != 200:
            return False, "User thường không cập nhật được trạng thái order qua endpoint admin."

        if isinstance(data, dict):
            if data.get("new_status") or data.get("status"):
                return True, "Endpoint admin trả 200 và có trạng thái order mới."
            if data.get("message"):
                return True, "Endpoint admin trả 200 khi user thường cập nhật trạng thái order."

        return True, "Endpoint admin update status trả 200 cho user thường."

    def detect_vulnerability(self, scenario: dict[str, Any], primary: dict[str, Any]) -> tuple[bool, str]:
        vuln = scenario.get("vulnerability_type")
        path = scenario.get("target", {}).get("path", "")

        if vuln == "MASS_ASSIGNMENT" and path == "/api/auth/register":
            return self.detect_ma_register(scenario, primary)
        if vuln == "MASS_ASSIGNMENT" and path == "/api/users/me":
            return self.detect_ma_profile(primary)
        if vuln == "BOLA" and path == "/api/orders/{order_id}":
            return self.detect_bola_order(primary)
        if vuln == "BFLA" and path == "/api/admin/users":
            return self.detect_bfla_admin_users(primary)
        if vuln == "BFLA" and path == "/api/admin/orders/{order_id}/status":
            return self.detect_bfla_order_status(primary)

        suspicious = scenario.get("suspicious_behavior", {}).get("status_codes", [])
        status = primary["response"]["status_code"]
        if status in suspicious:
            return True, "Phát hiện theo suspicious status code."
        return False, "Không khớp heuristic phát hiện."

    def run(self, scenarios_doc: dict[str, Any]) -> dict[str, Any]:
        login_status: dict[str, str] = {}
        for key in [ATTACKER_KEY, VICTIM_KEY, ADMIN_KEY]:
            try:
                self.login(key)
                login_status[key] = "ok"
            except Exception as exc:
                login_status[key] = f"failed: {exc}"
                print(f"[WARN] Login {key} failed: {exc}")

        results: list[dict[str, Any]] = []
        for scenario in scenarios_doc.get("scenarios", []):
            scenario = deepcopy(scenario)
            self.normalize_register_payload(scenario)

            started_at = int(time.time())
            try:
                primary = self.send_request(scenario)
                detected, evidence = self.detect_vulnerability(scenario, primary)
                error = None
            except Exception as exc:
                primary = {
                    "request": {},
                    "response": {"status_code": None, "elapsed_ms": None, "json": None, "text_preview": ""},
                }
                detected = False
                evidence = f"Lỗi khi chạy scenario: {exc}"
                error = str(exc)

            item = {
                "scenario_id": scenario.get("scenario_id"),
                "source_endpoint_id": scenario.get("source_endpoint_id"),
                "vulnerability_type": scenario.get("vulnerability_type"),
                "target": scenario.get("target"),
                "detected": detected,
                "evidence_summary": evidence,
                "request": primary["request"],
                "response": primary["response"],
                "expected_secure_behavior": scenario.get("expected_secure_behavior"),
                "suspicious_behavior": scenario.get("suspicious_behavior"),
                "started_at_unix": started_at,
            }
            if error:
                item["error"] = error
            results.append(item)

            if scenario.get("vulnerability_type") == "MASS_ASSIGNMENT" and scenario.get("target", {}).get("path") == "/api/users/me":
                self.reset_attacker_role_if_possible()

        total = len(results)
        detected_count = sum(1 for item in results if item["detected"])

        return {
            "scan_meta": {
                "base_url": self.base_url,
                "generated_at_unix": int(time.time()),
                "total_scenarios": total,
                "detected_count": detected_count,
                "login_status": login_status,
            },
            "results": results,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run attack scenarios against Target Lab API.")
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--scenarios", default="../03_attack_scenario_generator_final/attack_scenarios_gemini.json")
    parser.add_argument("--seed-context", default="../03_attack_scenario_generator_final/seed_context.json")
    parser.add_argument("--output", default="../05_experiment_data/scan_results_final.json")
    parser.add_argument("--timeout", type=int, default=10)
    args = parser.parse_args()

    scenarios_doc = load_json(args.scenarios)
    seed_context = load_json(args.seed_context)

    fuzzer = TargetLabFuzzer(args.base_url, seed_context, timeout=args.timeout)
    result = fuzzer.run(scenarios_doc)
    save_json(args.output, result)

    print(
        f"Đã chạy {result['scan_meta']['total_scenarios']} scenario, "
        f"detected={result['scan_meta']['detected_count']}. "
        f"Output: {args.output}"
    )


if __name__ == "__main__":
    main()

