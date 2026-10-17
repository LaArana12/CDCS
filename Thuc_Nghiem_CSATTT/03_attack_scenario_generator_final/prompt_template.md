# Prompt sinh kịch bản kiểm thử API logic

Input chính: `parser_output.json`.

Yêu cầu LLM sinh scenario thuộc 3 nhóm:
- MASS_ASSIGNMENT
- BOLA
- BFLA

Output phải tuân theo `attack_scenario_schema.json`.

Quy tắc quan trọng:
- Không sinh scenario cho AUTH hoặc NORMAL.
- `target.path` giữ path mẫu từ OpenAPI, ví dụ `/api/orders/{order_id}`.
- `request.path` mới thay tham số thật, ví dụ `/api/orders/1001`.
- Endpoint cần xác thực dùng `Authorization: Bearer <attacker_token>`.
- Mass Assignment chỉ inject `role=admin`.
- BOLA dùng `attacker_user` truy cập `order_id=1001` của `victim_user`.
- BFLA dùng `attacker_user` gọi endpoint `/admin`.

Các scenario tối thiểu:
- MA_REGISTER_001
- MA_PROFILE_001
- BOLA_ORDER_001
- BFLA_ADMIN_USERS_001
- BFLA_ORDER_STATUS_001

