"""
Module Parser đọc tài liệu OpenAPI/Swagger và chuẩn hóa endpoint.

Cách chạy:
    python parser.py --input openapi.json --output parser_output.json

Đầu ra phục vụ module LLM/Prompt ở bước tiếp theo:
    - api_info
    - endpoints[] gồm path, method, parameters, request_body, responses,
      security, risk_hints và reason.
    - risk_hint_values: danh sách nhãn risk_hints hợp lệ để TV1 dùng thống nhất schema.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml  # type: ignore
except ImportError:  # Cho phép chạy chỉ với JSON mà không cần PyYAML
    yaml = None

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}
RISK_HINT_VALUES = ["MASS_ASSIGNMENT", "BOLA", "BFLA", "AUTH", "NORMAL"]
SENSITIVE_FIELD_NAMES = {
    "role",
    "is_admin",
    "admin",
    "permission",
    "permissions",
    "balance",
    "price",
    "status",
    "owner_id",
    "user_id",
    "account_id",
    "total_amount",
}
PASSWORD_FIELD_NAMES = {"password", "password_hash", "token", "access_token", "refresh_token"}


class OpenAPIParser:
    def __init__(self, spec: Dict[str, Any]) -> None:
        self.spec = spec
        self.components = spec.get("components", {})
        self.schemas = self.components.get("schemas", {})
        self.security_schemes = self.components.get("securitySchemes", {})
        self.global_security = spec.get("security", [])

    def parse(self) -> Dict[str, Any]:
        endpoints: List[Dict[str, Any]] = []
        paths = self.spec.get("paths", {})

        counter = 1
        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            for method, operation in path_item.items():
                if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                    continue

                endpoint = self._parse_operation(counter, path, method.upper(), operation, path_item)
                endpoints.append(endpoint)
                counter += 1

        return {
            "api_info": self._extract_api_info(),
            "risk_hint_values": RISK_HINT_VALUES,
            "parser_meta": {
                "parser_name": "TV2 OpenAPI Parser",
                "parser_version": "1.0",
                "source": "openapi.json",
                "description": "Chuẩn hóa endpoint từ OpenAPI để phục vụ LLM sinh kịch bản kiểm thử."
            },
            "endpoints": endpoints,
        }

    def _extract_api_info(self) -> Dict[str, Any]:
        info = self.spec.get("info", {})
        servers = self.spec.get("servers", [])
        base_url = "http://localhost:8000"
        if servers and isinstance(servers, list):
            base_url = servers[0].get("url", base_url)

        return {
            "title": info.get("title", "Unknown API"),
            "version": info.get("version", "unknown"),
            "openapi_version": self.spec.get("openapi", self.spec.get("swagger", "unknown")),
            "base_url": base_url,
        }

    def _parse_operation(
        self,
        index: int,
        path: str,
        method: str,
        operation: Dict[str, Any],
        path_item: Dict[str, Any],
    ) -> Dict[str, Any]:
        parameters = self._extract_parameters(path_item, operation)
        request_body = self._extract_request_body(path, method, operation)
        responses = self._extract_responses(operation)
        security = self._extract_security(operation)
        risk_hints, reason = self._assign_risk_hints(path, method, request_body, parameters, security)

        return {
            "endpoint_id": f"EP_{index:03d}",
            "path": path,
            "method": method,
            "summary": operation.get("summary", ""),
            "description": operation.get("description", ""),
            "operation_id": operation.get("operationId", ""),
            "security": security,
            "parameters": parameters,
            "request_body": request_body,
            "responses": responses,
            "risk_hints": risk_hints,
            "reason": reason,
        }

    def _extract_parameters(self, path_item: Dict[str, Any], operation: Dict[str, Any]) -> List[Dict[str, Any]]:
        raw_parameters = []
        raw_parameters.extend(path_item.get("parameters", []) or [])
        raw_parameters.extend(operation.get("parameters", []) or [])

        parameters: List[Dict[str, Any]] = []
        for param in raw_parameters:
            param = self._resolve_ref(param)
            schema = self._resolve_ref(param.get("schema", {}))
            name = param.get("name", "")
            parameters.append({
                "name": name,
                "in": param.get("in", ""),
                "required": bool(param.get("required", False)),
                "type": self._schema_type(schema),
                "sensitive": self._is_sensitive_name(name),
                "description": param.get("description", ""),
            })
        return parameters

    def _extract_request_body(self, path: str, method: str, operation: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        raw_body = operation.get("requestBody")
        if not raw_body:
            return None

        body = self._resolve_ref(raw_body)
        content = body.get("content", {})
        if not content:
            return {
                "required": bool(body.get("required", False)),
                "content_type": None,
                "schema_ref": None,
                "fields": [],
                "allows_additional_properties": False,
                "candidate_injected_fields": [],
            }

        content_type = "application/json" if "application/json" in content else next(iter(content.keys()))
        schema_raw = content.get(content_type, {}).get("schema", {})
        schema_ref = schema_raw.get("$ref") if isinstance(schema_raw, dict) else None
        schema = self._resolve_ref(schema_raw)

        fields = self._extract_fields_from_schema(schema)
        allows_additional = bool(schema.get("additionalProperties", False))
        candidate_injected_fields = self._candidate_injected_fields(path, method, schema, fields)

        # Nếu endpoint status dùng schema object tự do, OpenAPI không liệt kê field.
        # Parser suy luận field status từ path /status để TV1 có dữ liệu prompt rõ hơn.
        if path.endswith("/status") and not any(f["name"] == "status" for f in fields):
            fields.append({
                "name": "status",
                "type": "string",
                "required": False,
                "sensitive": True,
                "source": "inferred_from_path",
                "description": "Suy luận từ endpoint cập nhật trạng thái đơn hàng."
            })

        return {
            "required": bool(body.get("required", False)),
            "content_type": content_type,
            "schema_ref": schema_ref,
            "schema_title": schema.get("title"),
            "fields": fields,
            "allows_additional_properties": allows_additional,
            "candidate_injected_fields": candidate_injected_fields,
        }

    def _extract_fields_from_schema(self, schema: Dict[str, Any]) -> List[Dict[str, Any]]:
        properties = schema.get("properties", {}) or {}
        required = set(schema.get("required", []) or [])
        fields: List[Dict[str, Any]] = []

        for name, field_schema in properties.items():
            field_schema = self._resolve_ref(field_schema)
            fields.append({
                "name": name,
                "type": self._schema_type(field_schema),
                "required": name in required,
                "sensitive": self._is_sensitive_name(name),
                "source": "openapi_schema",
                "description": field_schema.get("description", ""),
            })
        return fields

    def _extract_responses(self, operation: Dict[str, Any]) -> List[Dict[str, Any]]:
        responses = []
        for status_code, response in (operation.get("responses", {}) or {}).items():
            response = self._resolve_ref(response)
            responses.append({
                "status_code": str(status_code),
                "description": response.get("description", ""),
            })
        return responses

    def _extract_security(self, operation: Dict[str, Any]) -> Dict[str, Any]:
        security_reqs = operation.get("security", self.global_security)
        required = bool(security_reqs)

        schemes = []
        scheme_type = None
        scheme = None
        header_name = None

        for req in security_reqs or []:
            for scheme_name in req.keys():
                schemes.append(scheme_name)
                detail = self.security_schemes.get(scheme_name, {})
                if detail.get("type") == "http" and detail.get("scheme") == "bearer":
                    scheme_type = "http"
                    scheme = "bearer"
                    header_name = "Authorization"
                elif detail:
                    scheme_type = detail.get("type")
                    scheme = detail.get("scheme") or detail.get("name")
                    header_name = detail.get("name") if detail.get("in") == "header" else None

        return {
            "required": required,
            "schemes": schemes,
            "type": scheme_type,
            "scheme": scheme,
            "header": header_name,
            "token_format": "Bearer <token>" if scheme == "bearer" else None,
        }

    def _assign_risk_hints(
        self,
        path: str,
        method: str,
        request_body: Optional[Dict[str, Any]],
        parameters: List[Dict[str, Any]],
        security: Dict[str, Any],
    ) -> tuple[List[str], str]:
        lower_path = path.lower()

        if lower_path == "/api/auth/login":
            return ["AUTH"], "Endpoint đăng nhập dùng để lấy Bearer token phục vụ kiểm thử các endpoint cần xác thực."

        if "/admin" in lower_path:
            return ["BFLA"], "Endpoint thuộc nhóm quản trị (/admin), cần kiểm thử user thường có gọi được chức năng vượt quyền hay không."

        has_object_id = any(
            p.get("in") == "path" and re.search(r"(^id$|_id$|order_id|user_id|account_id)", p.get("name", ""), re.I)
            for p in parameters
        )
        if has_object_id and method in {"GET", "PUT", "PATCH", "DELETE"}:
            return ["BOLA"], "Endpoint có path parameter định danh tài nguyên, cần kiểm thử truy cập tài nguyên thuộc người dùng khác."

        if self._is_mass_assignment_candidate(path, method, request_body):
            return ["MASS_ASSIGNMENT"], "Endpoint có request body cho thao tác tạo/cập nhật dữ liệu người dùng và schema cho phép thêm field ngoài mô tả, cần thử chèn các field nhạy cảm."

        return ["NORMAL"], "Endpoint phục vụ luồng nghiệp vụ cơ bản của Target Lab, chưa có dấu hiệu trực tiếp thuộc các nhóm lỗ hổng trọng tâm BOLA, BFLA hoặc Mass Assignment."

    def _is_mass_assignment_candidate(self, path: str, method: str, request_body: Optional[Dict[str, Any]]) -> bool:
        if method not in {"POST", "PUT", "PATCH"} or not request_body:
            return False

        lower_path = path.lower()
        user_related = lower_path in {"/api/auth/register", "/api/users/me"} or "user" in lower_path or "profile" in lower_path
        allows_additional = bool(request_body.get("allows_additional_properties"))
        has_sensitive_field = any(f.get("sensitive") for f in request_body.get("fields", []))
        has_candidate_injected = bool(request_body.get("candidate_injected_fields"))
        return user_related and (allows_additional or has_sensitive_field or has_candidate_injected)

    def _candidate_injected_fields(
        self,
        path: str,
        method: str,
        schema: Dict[str, Any],
        fields: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        lower_path = path.lower()
        existing_names = {f["name"] for f in fields}
        candidates: List[Dict[str, Any]] = []

        if method in {"POST", "PUT", "PATCH"} and (lower_path == "/api/auth/register" or lower_path == "/api/users/me"):
            # Theo thống nhất nhóm, Mass Assignment tuần 3 chỉ thử chèn field role.
            # Không đưa is_admin hoặc permissions vào candidate_injected_fields.
            for name, value_type, sample in [("role", "string", "admin")]:
                if name not in existing_names:
                    candidates.append({
                        "name": name,
                        "type": value_type,
                        "sample_value": sample,
                        "reason": "Field role không nằm trong schema chính thức nhưng có thể bị chèn nếu backend cho phép extra fields."
                    })
        return candidates

    def _resolve_ref(self, node: Any) -> Any:
        if not isinstance(node, dict) or "$ref" not in node:
            return node
        ref = node["$ref"]
        if not ref.startswith("#/"):
            return node
        current: Any = self.spec
        for part in ref[2:].split("/"):
            current = current.get(part, {}) if isinstance(current, dict) else {}
        return current

    def _schema_type(self, schema: Dict[str, Any]) -> str:
        if not isinstance(schema, dict):
            return "unknown"
        if "type" in schema:
            return str(schema["type"])
        if "anyOf" in schema:
            types = [self._schema_type(item) for item in schema.get("anyOf", [])]
            return " | ".join(t for t in types if t != "unknown") or "unknown"
        if "oneOf" in schema:
            types = [self._schema_type(item) for item in schema.get("oneOf", [])]
            return " | ".join(t for t in types if t != "unknown") or "unknown"
        if "$ref" in schema:
            resolved = self._resolve_ref(schema)
            return self._schema_type(resolved)
        return "unknown"

    def _is_sensitive_name(self, name: str) -> bool:
        normalized = name.lower()
        return normalized in SENSITIVE_FIELD_NAMES or normalized in PASSWORD_FIELD_NAMES


def load_spec(input_path: Path) -> Dict[str, Any]:
    text = input_path.read_text(encoding="utf-8")
    suffix = input_path.suffix.lower()

    if suffix in {".yaml", ".yml"}:
        if yaml is None:
            raise RuntimeError("Cần cài PyYAML để đọc file YAML: pip install pyyaml")
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)

    if not isinstance(data, dict):
        raise ValueError("OpenAPI spec không hợp lệ: root phải là object.")
    return data


def main() -> None:
    parser = argparse.ArgumentParser(description="Parse OpenAPI/Swagger and export normalized endpoint JSON.")
    parser.add_argument("--input", "-i", default="openapi.json", help="Đường dẫn file OpenAPI/Swagger đầu vào")
    parser.add_argument("--output", "-o", default="parser_output.json", help="Đường dẫn file JSON đầu ra")
    args = parser.parse_args()

    spec = load_spec(Path(args.input))
    result = OpenAPIParser(spec).parse()

    output_path = Path(args.output)
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Đã xuất {len(result['endpoints'])} endpoint ra {output_path}")


if __name__ == "__main__":
    main()

