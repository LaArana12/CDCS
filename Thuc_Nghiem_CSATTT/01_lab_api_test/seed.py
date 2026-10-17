import os

from sqlalchemy.orm import Session
from database import SessionLocal
import models


def required_secret(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"{name} must be set before seeding the target lab")
    return value

def seed_data():
    db: Session = SessionLocal()
    
    # Nếu đã có dữ liệu trong DB thì bỏ qua không nạp trùng
    if db.query(models.User).first():
        db.close()
        return

    print("=== Khởi tạo dữ liệu mồi (Seed Data Tự Động Sinh ID) ===")

    # 1. Định nghĩa danh sách Users (BỎ HOÀN TOÀN tham số id=)
    # Credentials are injected at runtime so this public lab never ships
    # usable passwords in source control.
    victim_password = required_secret("CDCS_VICTIM_PASSWORD")
    attacker_password = required_secret("CDCS_ATTACKER_PASSWORD")
    admin_password = required_secret("CDCS_ADMIN_PASSWORD")
    user_victim = models.User(username="victim_user", email="victim.invalid", password_hash=f"hashed_{victim_password}", role="user")
    user_attacker = models.User(username="attacker_user", email="attacker.invalid", password_hash=f"hashed_{attacker_password}", role="user")
    user_admin = models.User(username="system_admin", email="admin.invalid", password_hash=f"hashed_{admin_password}", role="admin")
    
    db.add_all([user_victim, user_attacker, user_admin])
    db.flush()  # Ép PostgreSQL cấp phát ID tự động cho 3 user này ngay lập tức ngầm dưới nền

    # 2. Định nghĩa danh sách Profiles (Dùng trực tiếp ID tự động của các đối tượng trên)
    profiles_data = [
        models.UserProfile(user_id=user_victim.id, full_name="Synthetic Victim", phone_number="", address="LAB"),
        models.UserProfile(user_id=user_attacker.id, full_name="Synthetic Attacker", phone_number="", address="LAB"),
        models.UserProfile(user_id=user_admin.id, full_name="Synthetic Administrator", phone_number="", address="LAB")
    ]
    db.add_all(profiles_data)

    # 3. Định nghĩa danh sách Sản phẩm trong kho (Bỏ id=)
    product_laptop = models.Product(name="Exploit Education Laptop", description="Thiết bị thực hành pentest mạng", price=1500.0, stock_quantity=10)
    product_shirt = models.Product(name="Premium Flag T-Shirt", description="Áo phông lưu niệm sự kiện CTF", price=25.0, stock_quantity=100)
    
    db.add_all([product_laptop, product_shirt])
    db.flush()  # Lấy ID tự động cho sản phẩm

    # 4. Định nghĩa Đơn hàng bẫy lỗi BOLA (Hóa đơn gán cho user_victim tự động)
    order = models.Order(id=1001, user_id=user_victim.id, total_amount=1500.0, status="Pending")
    db.add(order)
    db.flush()

    order_item = models.OrderItem(order_id=order.id, product_id=product_laptop.id, quantity=1, unit_price=1500.0)
    db.add(order_item)

    # 5. Định nghĩa dữ liệu mặt đất chấm điểm Ground Truth (Bỏ id=)
    ground_truths = [
        models.VulnerabilityGroundTruth(
            vuln_id="MA_001", vuln_type="Mass Assignment", target_endpoint="/api/auth/register",
            http_method="POST", severity="High", description="API đăng ký tài khoản không chặn việc truyền tham số 'role' trực tiếp từ Client."
        ),
        models.VulnerabilityGroundTruth(
            vuln_id="MA_002", vuln_type="Mass Assignment", target_endpoint="/api/users/me",
            http_method="PATCH", severity="High", description="API cập nhật hồ sơ cá nhân hiện tại không loại bỏ thuộc tính 'role' ở Back-end."
        ),
        models.VulnerabilityGroundTruth(
            vuln_id="BOLA_001", vuln_type="BOLA", target_endpoint="/api/orders/{order_id}",
            http_method="GET", severity="High", description="API truy vấn chi tiết hóa đơn thiếu bước kiểm tra quyền sở hữu thực thể."
        ),
        models.VulnerabilityGroundTruth(
            vuln_id="BFLA_001", vuln_type="BFLA", target_endpoint="/api/admin/users",
            http_method="GET", severity="High", description="API lấy danh sách toàn bộ người dùng thiếu cơ chế phân quyền kiểm tra vai trò admin."
        ),
        models.VulnerabilityGroundTruth(
            vuln_id="BFLA_002", vuln_type="BFLA", target_endpoint="/api/admin/orders/{order_id}/status",
            http_method="PATCH", severity="High", description="API thay đổi trạng thái hóa đơn của Admin thiếu phân quyền RBAC chặt chẽ."
        )
    ]
    db.add_all(ground_truths)
    
    db.commit()
    db.close()
    print("=== Hoàn tất nạp dữ liệu mồi Tự động hóa ID thành công! ===")

