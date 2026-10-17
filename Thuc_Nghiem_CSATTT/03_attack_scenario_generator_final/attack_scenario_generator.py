#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import random
import time
from pathlib import Path
from typing import Any

ATTACKER = "attacker_user"
VICTIM = "victim_user"
ADMIN = "system_admin"
ORDER_ID = 1001
ALLOWED_VULNS = {"MASS_ASSIGNMENT", "BOLA", "BFLA"}
DEFAULT_MODEL = "gemini-2.5-flash-lite"


def load_json(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: JSON root phải là object")
    return data


def save_json(data: dict[str, Any], path: str | Path) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def schema_generated_from_fields(schema: dict[str, Any]) -> set[str]:
    return set(
        schema.get("properties", {})
        .get("generated_from", {})
        .get("properties", {})
        .keys()
    )


def metadata(
    parser_output: dict[str, Any],
    generator: str,
    schema: dict[str, Any],
    model: str | None = None,
) -> dict[str, Any]:
    info = parser_output.get("api_info", {})
    result: dict[str, Any] = {
        "parser_output_version": parser_output.get(
            "parser_output_version",
            parser_output.get("parser_meta", {}).get("parser_version", "unknown"),
        ),
        "api_title": info.get("title", "Target Lab API"),
        "base_url": info.get("base_url", "http://localhost:8000"),
        "generator": generator,
    }
    if model:
        result["model"] = model

    allowed = schema_generated_from_fields(schema)
    return {k: v for k, v in result.items() if not allowed or k in allowed}


def build_headers(token_source: str, has_json_body: bool) -> dict[str, str]:
    headers: dict[str, str] = {}

    token_placeholders = {
        "ATTACKER": "Bearer <attacker_token>",
        "VICTIM": "Bearer <victim_token>",
        "ADMIN": "Bearer <admin_token>",
    }

    if token_source in token_placeholders:
        headers["Authorization"] = token_placeholders[token_source]

    if has_json_body:
        headers["Content-Type"] = "application/json"

    return headers


def build_scenario(
    sid: str,
    endpoint: dict[str, Any],
    vuln_type: str,
    token_source: str,
    request_path: str,
    body: dict[str, Any] | None,
    expected_codes: list[int],
    expected_text: str,
    suspicious_codes: list[int],
    suspicious_text: str,
    evidence_fields: list[str],
    validation_steps: list[str],
    reason: str,
    *,
    victim_user: str | None = None,
    admin_user: str | None = None,
    path_params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    method = str(endpoint["method"]).upper()

    return {
        "scenario_id": sid,
        "source_endpoint_id": endpoint.get("endpoint_id", ""),
        "vulnerability_type": vuln_type,
        "target": {"method": method, "path": endpoint["path"]},
        "auth_context": {
            "attacker_user": "anonymous_new_user" if token_source == "NONE" else ATTACKER,
            "victim_user": victim_user,
            "admin_user": admin_user,
            "token_source": token_source,
        },
        "request": {
            "method": method,
            "path": request_path,
            "path_params": path_params or {},
            "query_params": {},
            "headers": build_headers(token_source, body is not None),
            "body": body,
        },
        "expected_secure_behavior": {
            "status_codes": expected_codes,
            "description": expected_text,
        },
        "suspicious_behavior": {
            "status_codes": suspicious_codes,
            "description": suspicious_text,
            "evidence_fields": evidence_fields,
        },
        "validation_steps": validation_steps,
        "reason_summary": reason,
        "priority": "HIGH",
        "in_scope": True,
    }


def generate_template(
    parser_output: dict[str, Any],
    schema: dict[str, Any],
    generator: str = "Template",
) -> dict[str, Any]:
    scenarios: list[dict[str, Any]] = []

    for endpoint in parser_output.get("endpoints", []):
        path = str(endpoint.get("path", ""))
        method = str(endpoint.get("method", "")).upper()
        hints = set(endpoint.get("risk_hints", []))

        if "MASS_ASSIGNMENT" in hints and path == "/api/auth/register":
            scenarios.append(
                build_scenario(
                    "MA_REGISTER_001",
                    endpoint,
                    "MASS_ASSIGNMENT",
                    "NONE",
                    path,
                    {
                        "username": "evil_admin_user",
                        "email": "evil_admin_user@test.com",
                        "password": "${CDCS_REGISTRATION_PASSWORD}",
                        "role": "admin",
                    },
                    [201, 400, 403, 422],
                    "Hệ thống phải bỏ qua hoặc từ chối role do client tự gửi.",
                    [200, 201],
                    "Tài khoản mới được tạo với role=admin.",
                    ["role", "user_role", "access_token"],
                    [
                        "Gửi request đăng ký có role=admin.",
                        "Đăng nhập tài khoản vừa tạo nếu API trả 201.",
                        "Gọi GET /api/users/me để xác minh role.",
                    ],
                    "Endpoint đăng ký cho phép thêm field role ngoài schema.",
                )
            )

        elif (
            "MASS_ASSIGNMENT" in hints
            and path == "/api/users/me"
            and method in {"PATCH", "PUT", "POST"}
        ):
            scenarios.append(
                build_scenario(
                    "MA_PROFILE_001",
                    endpoint,
                    "MASS_ASSIGNMENT",
                    "ATTACKER",
                    path,
                    {
                        "full_name": "Attacker Updated",
                        "phone_number": "0988888888",
                        "address": "Updated Address",
                        "role": "admin",
                    },
                    [200, 400, 403, 422],
                    "Hệ thống không được cập nhật role từ request hồ sơ.",
                    [200],
                    "Role của attacker_user bị đổi thành admin.",
                    ["role", "user_role", "profile"],
                    [
                        "Đăng nhập attacker_user.",
                        "Gửi PATCH /api/users/me có role=admin.",
                        "Gọi GET /api/users/me để xác minh role.",
                    ],
                    "Endpoint cập nhật hồ sơ có candidate field role.",
                )
            )

        elif "BOLA" in hints and path == "/api/orders/{order_id}":
            scenarios.append(
                build_scenario(
                    "BOLA_ORDER_001",
                    endpoint,
                    "BOLA",
                    "ATTACKER",
                    "/api/orders/1001",
                    None,
                    [403, 404],
                    "attacker_user không được xem đơn hàng của victim_user.",
                    [200],
                    "API trả đơn hàng của victim_user cho attacker_user.",
                    ["order_owner", "requested_by", "user_id", "email"],
                    [
                        "Đăng nhập attacker_user.",
                        "Gửi GET /api/orders/1001.",
                        "Kiểm tra chủ sở hữu đơn hàng.",
                    ],
                    "order_id là định danh tài nguyên có quan hệ sở hữu.",
                    victim_user=VICTIM,
                    path_params={"order_id": ORDER_ID},
                )
            )

        elif "BFLA" in hints and path == "/api/admin/users":
            scenarios.append(
                build_scenario(
                    "BFLA_ADMIN_USERS_001",
                    endpoint,
                    "BFLA",
                    "ATTACKER",
                    path,
                    None,
                    [403],
                    "User thường không được gọi endpoint quản trị.",
                    [200],
                    "attacker_user nhận được danh sách người dùng.",
                    ["username", "email", "role"],
                    [
                        "Đăng nhập attacker_user.",
                        "Gửi GET /api/admin/users.",
                        "Kiểm tra danh sách user trả về.",
                    ],
                    "Path /admin biểu thị chức năng đặc quyền.",
                    admin_user=ADMIN,
                )
            )

        elif "BFLA" in hints and path == "/api/admin/orders/{order_id}/status":
            scenarios.append(
                build_scenario(
                    "BFLA_ORDER_STATUS_001",
                    endpoint,
                    "BFLA",
                    "ATTACKER",
                    "/api/admin/orders/1001/status",
                    {"status": "Completed"},
                    [403],
                    "User thường không được đổi trạng thái đơn hàng qua endpoint admin.",
                    [200],
                    "attacker_user đổi được trạng thái đơn hàng.",
                    ["new_status", "executed_by", "role_current", "order_owner"],
                    [
                        "Đăng nhập attacker_user.",
                        "Gửi PATCH trạng thái order 1001.",
                        "Kiểm tra trạng thái mới và role người thực thi.",
                    ],
                    "Endpoint /admin thay đổi trạng thái đơn hàng.",
                    victim_user=VICTIM,
                    admin_user=ADMIN,
                    path_params={"order_id": ORDER_ID},
                )
            )

    return {
        "schema_version": "2.0",
        "generated_from": metadata(parser_output, generator, schema),
        "scenarios": scenarios,
    }


def compact_input(parser_output: dict[str, Any]) -> dict[str, Any]:
    endpoints: list[dict[str, Any]] = []

    for endpoint in parser_output.get("endpoints", []):
        hints = endpoint.get("risk_hints", []) or []
        if not any(hint in ALLOWED_VULNS or hint == "AUTH" for hint in hints):
            continue

        endpoints.append(
            {
                "endpoint_id": endpoint.get("endpoint_id"),
                "path": endpoint.get("path"),
                "method": endpoint.get("method"),
                "security": endpoint.get("security"),
                "parameters": endpoint.get("parameters"),
                "request_body": endpoint.get("request_body"),
                "responses": endpoint.get("responses"),
                "risk_hints": hints,
                "reason": endpoint.get("reason"),
            }
        )

    return {
        "api_info": parser_output.get("api_info", {}),
        "endpoints": endpoints,
        "seed_context": {
            "attacker_user": ATTACKER,
            "victim_user": VICTIM,
            "admin_user": ADMIN,
            "victim_order_id": ORDER_ID,
        },
    }


def build_prompt(parser_output: dict[str, Any], schema: dict[str, Any]) -> str:
    compact = compact_input(parser_output)

    return f"""
Bạn là chuyên gia kiểm thử bảo mật Web API.

Hãy sinh attack scenarios cho đúng ba loại: MASS_ASSIGNMENT, BOLA và BFLA.

Quy tắc:
- Chỉ trả JSON hợp lệ theo JSON Schema, không dùng Markdown.
- Chỉ sinh scenario cho endpoint có risk_hints MASS_ASSIGNMENT, BOLA hoặc BFLA.
- Không sinh scenario cho AUTH hoặc NORMAL.
- source_endpoint_id, target.method và target.path phải khớp tuyệt đối với parser_output.
- target.path giữ path mẫu; request.path mới thay tham số bằng giá trị thật.
- Với order_id, dùng request.path="/api/orders/1001" và path_params={{"order_id": 1001}}.
- MASS_ASSIGNMENT chỉ chèn "role": "admin".
- BOLA dùng attacker_user truy cập order 1001 của victim_user.
- BFLA dùng attacker_user gọi endpoint /admin.
- Endpoint cần xác thực dùng Authorization: "Bearer <attacker_token>".

Parser output:
{json.dumps(compact, ensure_ascii=False, indent=2)}

JSON Schema:
{json.dumps(schema, ensure_ascii=False, indent=2)}
"""


def call_gemini(
    parser_output: dict[str, Any],
    schema: dict[str, Any],
    model: str,
    retries: int,
) -> dict[str, Any]:
    try:
        from google import genai
        from google.genai import types
    except ImportError as exc:
        raise RuntimeError("Cài thư viện: python -m pip install google-genai") from exc

    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    if not api_key:
        raise RuntimeError("Chưa thiết lập GEMINI_API_KEY hoặc GOOGLE_API_KEY")

    client = genai.Client(api_key=api_key)
    last_error: Exception | None = None

    for attempt in range(retries + 1):
        try:
            response = client.models.generate_content(
                model=model,
                contents=build_prompt(parser_output, schema),
                config=types.GenerateContentConfig(
                    temperature=0.15,
                    response_mime_type="application/json",
                    response_json_schema=schema,
                ),
            )

            if not response.text:
                raise RuntimeError("Gemini trả response rỗng")

            result = json.loads(response.text)
            if not isinstance(result, dict):
                raise ValueError("Gemini output phải là JSON object")

            result["schema_version"] = "2.0"
            result["generated_from"] = metadata(parser_output, "Gemini API", schema, model)
            return result

        except Exception as exc:
            last_error = exc
            if attempt >= retries:
                break

            delay = (2 ** (attempt + 1)) + random.random()
            print(f"[WARN] Gemini lỗi: {exc}. Thử lại sau {delay:.1f}s")
            time.sleep(delay)

    raise RuntimeError(f"Gemini thất bại: {last_error}")


def fill_path_template(template: str, path_params: dict[str, Any]) -> str:
    result = template
    for name, value in path_params.items():
        result = result.replace(f"{{{name}}}", str(value))
    return result


def endpoint_key(item: dict[str, Any]) -> tuple[str, str, str]:
    source_id = str(item.get("source_endpoint_id", ""))
    vuln = str(item.get("vulnerability_type", ""))
    path = str(item.get("target", {}).get("path", item.get("request", {}).get("path", "")))
    return source_id, vuln, path


def apply_known_request_defaults(item: dict[str, Any], source: dict[str, Any]) -> None:
    request = item.setdefault("request", {})
    auth = item.setdefault("auth_context", {})
    vuln = item.get("vulnerability_type")
    path_template = str(source.get("path", ""))

    token_source = auth.get("token_source")
    if token_source not in {"NONE", "ATTACKER", "VICTIM", "ADMIN"}:
        token_source = "ATTACKER" if source.get("security", {}).get("required") else "NONE"
        auth["token_source"] = token_source

    auth.setdefault("attacker_user", "anonymous_new_user" if token_source == "NONE" else ATTACKER)
    auth.setdefault("victim_user", None)
    auth.setdefault("admin_user", None)

    if vuln == "BOLA":
        auth["victim_user"] = VICTIM

    if vuln == "BFLA":
        auth["admin_user"] = ADMIN

    body = request.get("body", None)
    body_is_empty_object = isinstance(body, dict) and not body

    if vuln == "MASS_ASSIGNMENT" and path_template == "/api/auth/register":
        body = {
            "username": "evil_admin_user",
            "email": "evil_admin_user@test.com",
            "password": "${CDCS_REGISTRATION_PASSWORD}",
            "role": "admin",
        }
        auth["attacker_user"] = "anonymous_new_user"
        auth["token_source"] = "NONE"

    elif vuln == "MASS_ASSIGNMENT" and path_template == "/api/users/me":
        if body is None or body_is_empty_object:
            body = {
                "full_name": "Attacker Updated",
                "phone_number": "0988888888",
                "address": "Updated Address",
                "role": "admin",
            }
        auth["token_source"] = "ATTACKER"

    elif vuln == "BFLA" and path_template == "/api/admin/orders/{order_id}/status":
        if body is None or body_is_empty_object:
            body = {"status": "Completed"}
        auth["token_source"] = "ATTACKER"

    elif vuln in {"BOLA", "BFLA"} and request.get("body", None) == {}:
        body = None

    request["body"] = body
    request["headers"] = build_headers(auth["token_source"], body is not None)


def normalize_output(output: dict[str, Any], parser_output: dict[str, Any]) -> None:
    endpoint_map = {
        endpoint.get("endpoint_id"): endpoint
        for endpoint in parser_output.get("endpoints", [])
    }

    normalized: list[dict[str, Any]] = []

    for item in output.get("scenarios", []):
        source = endpoint_map.get(item.get("source_endpoint_id"))
        if not source:
            continue

        method = str(source.get("method", "")).upper()
        path_template = str(source.get("path", ""))

        item.setdefault("target", {})
        item["target"]["method"] = method
        item["target"]["path"] = path_template

        request = item.setdefault("request", {})
        request["method"] = method

        path_params = request.get("path_params")
        if not isinstance(path_params, dict):
            path_params = {}
            request["path_params"] = path_params

        if "{order_id}" in path_template:
            path_params["order_id"] = ORDER_ID

        request["path"] = fill_path_template(path_template, path_params)
        request.setdefault("query_params", {})

        apply_known_request_defaults(item, source)
        normalized.append(item)

    output["scenarios"] = normalized


def validate_output(
    output: dict[str, Any],
    parser_output: dict[str, Any],
    schema: dict[str, Any],
) -> None:
    try:
        from jsonschema import validate
    except ImportError as exc:
        raise RuntimeError("Cài thư viện: python -m pip install jsonschema") from exc

    validate(instance=output, schema=schema)

    endpoint_map = {
        endpoint.get("endpoint_id"): endpoint
        for endpoint in parser_output.get("endpoints", [])
    }
    seen: set[str] = set()

    for item in output.get("scenarios", []):
        sid = item["scenario_id"]
        if sid in seen:
            raise ValueError(f"Trùng scenario_id: {sid}")
        seen.add(sid)

        source = endpoint_map.get(item["source_endpoint_id"])
        if not source:
            raise ValueError(f"{sid}: không tìm thấy endpoint nguồn")

        if str(item["target"]["method"]).upper() != str(source["method"]).upper():
            raise ValueError(f"{sid}: method không khớp")

        if item["target"]["path"] != source["path"]:
            raise ValueError(f"{sid}: path không khớp")

        if item["vulnerability_type"] not in set(source.get("risk_hints", [])):
            raise ValueError(f"{sid}: vulnerability_type không khớp risk_hints")


def main() -> None:
    parser = argparse.ArgumentParser(description="Sinh attack scenarios bằng template hoặc Gemini API")
    parser.add_argument("--input", "-i", required=True, help="Đường dẫn parser_output.json")
    parser.add_argument("--output", "-o", required=True, help="Đường dẫn file output attack_scenarios.json")
    parser.add_argument("--schema", default="attack_scenario_schema.json", help="Đường dẫn JSON Schema")
    parser.add_argument("--mode", choices=["template", "gemini", "hybrid"], default="hybrid")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--retries", type=int, default=2)
    args = parser.parse_args()

    parser_output = load_json(args.input)
    schema = load_json(args.schema)

    if args.mode == "template":
        result = generate_template(parser_output, schema, "Template")
        source = "Template"
    else:
        try:
            result = call_gemini(parser_output, schema, args.model, max(0, args.retries))
            source = "Gemini API"
        except Exception as exc:
            if args.mode == "gemini":
                raise SystemExit(f"[ERROR] {exc}") from exc

            print(f"[WARN] {exc}")
            print("[WARN] Chuyển sang template")
            result = generate_template(parser_output, schema, "Template fallback")
            source = "Template fallback"

    normalize_output(result, parser_output)
    validate_output(result, parser_output, schema)
    save_json(result, args.output)

    print(f"[OK] Nguồn sinh: {source}")
    if source == "Gemini API":
        print(f"[OK] Model: {args.model}")
    print(f"[OK] Số scenario: {len(result['scenarios'])}")
    print(f"[OK] Đã lưu: {args.output}")


if __name__ == "__main__":
    main()

