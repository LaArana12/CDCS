from fastapi import FastAPI, Depends, HTTPException, Header, status
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, ConfigDict
from typing import List, Optional
from sqlalchemy.orm import Session, joinedload
import models
from database import engine, SessionLocal
import time
import seed
import jwt
from sqlalchemy.exc import OperationalError
from pathlib import Path              
import json
import os

app = FastAPI(title="Target Lab API", version="1.0")

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY must be set before starting the target lab")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

# Sử dụng HTTPBearer của FastAPI để tự động hiển thị nút bấm Authorize (Ổ khóa) trên Swagger UI
security_bearer = HTTPBearer(auto_error=False)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Định nghĩa Pydantic Request Schemas ---
class UserRegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    model_config = ConfigDict(extra ="allow")

class UserUpdateRequest(BaseModel):
    full_name: Optional[str] = None
    phone_number: Optional[str] = None
    address: Optional[str] = None
    model_config = ConfigDict(extra="allow")

class LoginRequest(BaseModel):
    username: str
    password: str
class OrderCreateRequest(BaseModel):
    product_id: int   # < ID của sản phẩm mua
    quantity: int     # Số lượng mua
    model_config = ConfigDict(extra="allow")

# --- Khởi tạo database tự động ---
def init_db_with_retry():
    print("=== [PostgreSQL] Đang kết nối và khởi tạo cấu trúc bảng ===")
    retries = 5
    while retries > 0:
        try:
            models.Base.metadata.create_all(bind=engine)
            print("=== [PostgreSQL] Tạo cấu trúc các bảng thành công! ===")
            seed.seed_data()
            break
        except OperationalError:
            print("--- [PostgreSQL] Database chưa sẵn sàng, đang thử lại sau 3 giây...")
            retries -= 1
            time.sleep(3)
    if retries == 0:
        print("LỖI: Không thể kết nối tới cơ sở dữ liệu PostgreSQL!")

init_db_with_retry()

# === CHUẨN HÓA AUTH: Giải mã JWT từ Authorization Header Bearer ===
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security_bearer), db: Session = Depends(get_db)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Missing Authorization header or invalid format")
    
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("user_id")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials, token expired or fake")
        
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User associated with token not found")
    return user

# ==========================================
# 1. MASS ASSIGNMENT: API ĐĂNG KÝ (MA_001)
# ==========================================
@app.post("/api/auth/register", status_code=201)
def register_user(user_in: UserRegisterRequest, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.username == user_in.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")

    # Đọc dữ liệu thô dưới dạng dictionary bao gồm cả extra fields (nếu attacker chèn vào)
    user_data = user_in.model_dump()
    
    # Lấy trường 'role' từ các trường extra (nếu không truyền mặc định là 'user')
    injected_role = user_data.get("role", "user")

    # Bẫy lỗi Mass Assignment thực tế: Đọc trực tiếp thuộc tính ẩn từ payload chèn ép
    new_user = models.User(
        username=user_in.username,
        email=user_in.email,
        password_hash=f"hashed_{user_in.password}",
        role=injected_role  # Vẫn dính bẫy lỗ hổng logic nghiệp vụ
    )
    db.add(new_user)
    db.flush() 

    new_profile = models.UserProfile(
        user_id=new_user.id, 
        full_name=user_in.username, 
        phone_number="", 
        address=""
    )
    db.add(new_profile)
    db.commit()
    db.refresh(new_user)
    
    return new_user

# ==========================================
# 2. ENDPOINT ĐĂNG NHẬP SINH JWT TOKEN REALISTIC
# ==========================================
@app.post("/api/auth/login")
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == payload.username).first()
    if not user or user.password_hash != f"hashed_{payload.password}":
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    # Sinh JWT chứa ID người dùng để phân tích phiên đăng nhập thực tế
    token_data = {"user_id": user.id, "username": user.username, "role": user.role}
    token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)
    
    return {
        "username": user.username,
        "role": user.role, 
        "access_token": token, 
        "token_type": "bearer",
    }



# =================================================================
# 3. LUỒNG CHUẨN: XEM HỒ SƠ CÁ NHÂN (GET /api/users/me)
# =================================================================
@app.get("/api/users/me")
def get_my_profile(current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    profile = db.query(models.UserProfile).filter(models.UserProfile.user_id == current_user.id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role,
        "profile": {
            "full_name": profile.full_name,
            "phone_number": profile.phone_number,
            "address": profile.address
        }
    }

# ==========================================
# 4. MASS ASSIGNMENT: CẬP NHẬT HỒ SƠ (MA_002)
# ==========================================
@app.patch("/api/users/me")
def update_profile(payload: UserUpdateRequest, credentials: HTTPAuthorizationCredentials = Depends(security_bearer), db: Session = Depends(get_db)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Missing Authorization header or invalid format")
        
    try:
        token_payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = token_payload.get("user_id")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

    current_user = db.query(models.User).filter(models.User.id == user_id).first()
    if not current_user:
        raise HTTPException(status_code=401, detail="User not found")

    profile = db.query(models.UserProfile).filter(models.UserProfile.user_id == current_user.id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    if payload.full_name is not None: profile.full_name = payload.full_name
    if payload.phone_number is not None: profile.phone_number = payload.phone_number  
    if payload.address is not None: profile.address = payload.address                 

    update_data = payload.model_dump()
    if "role" in update_data and update_data["role"] is not None:
        current_user.role = update_data["role"]
        db.add(current_user)

    db.add(profile)
    db.commit()
    
    return {
        "message": "Profile updated successfully", 
        "user_role": current_user.role,
        "profile": {"full_name": profile.full_name, "phone_number": profile.phone_number, "address": profile.address}
    }

# =================================================================
# 5. LUỒNG CHUẨN: XEM DANH SÁCH SẢN PHẨM (GET /api/products)
# =================================================================
@app.get("/api/products")
def get_products():
    # Trả về danh sách sản phẩm giả lập để phục vụ luồng nghiệp vụ UI/Swagger
    return [
        {"product_id": 1, "name": "Laptop Gaming ASUS", "price": 1200.0, "description": "High performance laptop"},
        {"product_id": 2, "name": "Bàn phím cơ AKKO", "price": 75.0, "description": "Mechanical keyboard"},
        {"product_id": 3, "name": "Chuột Logitech G Pro", "price": 110.0, "description": "Wireless gaming mouse"},
        {"product_id": 4, "name": "Màn hình Dell UltraSharp", "price": 350.0, "description": "27 inch 2K Monitor"}
    ]

# ==========================================
# 6. BOLA / IDOR: TRUY VẤN ĐƠN HÀNG (BOLA_001)
# ==========================================
@app.get("/api/orders/{order_id}")
def get_order_detail(order_id: int, credentials: HTTPAuthorizationCredentials = Depends(security_bearer), db: Session = Depends(get_db)):
    # 1. Bắt buộc phải có Token hợp lệ mới qua cửa (Authentication)
    if not credentials:
        raise HTTPException(status_code=401, detail="Missing Authorization header or invalid format")
        
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        attacker_info = {
            "user_id": payload.get("user_id"),
            "username": payload.get("username"),
            "role_current": payload.get("role")
        }
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

    # 2. Tìm đơn hàng và nạp kèm thông tin chủ sở hữu thực sự (Nạn nhân)
    order = db.query(models.Order)\
              .options(joinedload(models.Order.user))\
              .filter(models.Order.id == order_id)\
              .first()
              
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
        
    # LỖ HỔNG BOLA: Hoàn toàn không so sánh order.user_id == attacker_info["user_id"]
    return {
        "id": order.id,
        "total_amount": order.total_amount,
        "status": order.status,
        "created_at": order.created_at,
        "requested_by": attacker_info,  # Thông tin kẻ đang gọi API (Đọc từ Token)
        "order_owner": {                # Thông tin chủ sở hữu thực sự (Đọc từ DB)
            "user_id": order.user.id,
            "username": order.user.username,
            "email": order.user.email
        }
    }

# =================================================================
# 7. MỞ RỘNG LUỒNG: TẠO ĐƠN HÀNG MỚI (ĐỒNG BỘ THEO SẢN PHẨM)
# =================================================================
@app.post("/api/orders", status_code=201)
def create_order(payload: OrderCreateRequest, credentials: HTTPAuthorizationCredentials = Depends(security_bearer), db: Session = Depends(get_db)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    try:
        token_payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = token_payload.get("user_id")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Giả lập tính toán giá tiền tự động để khớp với cấu trúc DB (Mỗi sản phẩm mặc định lấy giá 500$)
    mock_price_per_item = 500
    calculated_total = payload.quantity * mock_price_per_item

    # Tạo đối tượng lưu vào DB theo đúng các trường của bảng Order hiện tại
    new_order = models.Order(
        user_id=user_id,
        total_amount=calculated_total, # Tự động tính toán dựa trên số lượng bạn nhập
        status="Pending"
    )
    db.add(new_order)
    db.commit()
    
    # Trả về kết quả JSON đầy đủ thông tin đồng bộ trên Swagger
    return {
        "id": new_order.id,
        "user_id": new_order.user_id,
        "product_id": payload.product_id,
        "quantity": payload.quantity,
        "total_amount": new_order.total_amount,
        "status": new_order.status
    }

# ==========================================
# 8. BFLA: LẤY DANH SÁCH USER ADMIN (BFLA_001)
# ==========================================
@app.get("/api/admin/users")
def admin_get_all_users(credentials: HTTPAuthorizationCredentials = Depends(security_bearer), db: Session = Depends(get_db)):
    # 1. Xác thực Token xem người dùng đã đăng nhập chưa
    if not credentials:
        raise HTTPException(status_code=401, detail="Missing Authorization header or invalid format")
        
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        executor_role = payload.get("role")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")
        
    # LỖ HỔNG BFLA: Giải mã token xong nhưng LẠI QUÊN kiểm tra điều kiện này:
    # if executor_role != "admin": raise HTTPException(status_code=403, detail="Forbidden")
    
    users = db.query(models.User).all()
    return users




# =================================================================
# 9. BFLA: THAY ĐỔI TRẠNG THÁI ĐƠN HÀNG (BFLA_002) - CẬP NHẬT CHUẨN JWT
# =================================================================
@app.patch("/api/admin/orders/{order_id}/status")
def update_order_status_admin(
    order_id: int, 
    status_update: dict, 
    current_user: models.User = Depends(get_current_user),  # SỬ DỤNG CURRENT_USER NHƯ BẠN MUỐN
    db: Session = Depends(get_db)
):
    # 1. Tìm đơn hàng và nạp kèm thông tin user (owner) qua mối quan hệ relationship
    order = db.query(models.Order)\
              .options(joinedload(models.Order.user))\
              .filter(models.Order.id == order_id)\
              .first()
              
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
        
    # LỖ HỔNG BFLA: Lập trình viên ép người dùng phải có Token hợp lệ (qua current_user),
    # nhưng lại hoàn toàn QUÊN kiểm tra điều kiện vai trò quản trị: if current_user.role != "admin"
    
    new_status = status_update.get("status", "Completed")
    order.status = new_status
    
    db.commit()
    db.refresh(order) 
    
    # 2. Trả về thông tin chi tiết bao gồm kẻ thực thi (trích xuất từ current_user) và chủ đơn hàng
    return {
        "message": "Order status updated successfully by admin",
        "order_id": order.id,
        "new_status": order.status,
        "executed_by": {
            "user_id": current_user.id,
            "username": current_user.username,
            "role_current": current_user.role  # Sẽ hiển thị rõ quyền "user" thường khi hack thành công
        },
        "order_owner": {
            "user_id": order.user.id,
            "username": order.user.username,
            "email": order.user.email
        }
    }

# =================================================================
# XEM KẾT QUẢ KIỂM THỬ TỰ ĐỘNG (DASHBOARD HTML)
# =================================================================
@app.get("/scan-results", response_class=HTMLResponse)
def scan_results_dashboard():
    # Định nghĩa đường dẫn tới file chứa kết quả quét JSON của bạn
    result_file = Path("/app/05_experiment_data/scan_results_final.json")

    # Nếu chưa chạy fuzzing hoặc sai đường dẫn file, trả về thông báo lỗi trực quan
    if not result_file.exists():
        return """
        <html>
        <head><title>Scan Results</title></head>
        <body style="font-family: Arial; text-align: center; margin-top: 100px;">
            <h2 style="color: #dc2626;">⚠️ Chưa tìm thấy file kết quả quét!</h2>
            <p>Hãy đảm bảo bạn đã chạy Fuzzing Engine hoặc cấu hình đúng đường dẫn tới file JSON.</p>
        </body>
        </html>
        """

    # Đọc dữ liệu từ file JSON
    data = json.loads(result_file.read_text(encoding="utf-8"))
    meta = data.get("scan_meta", {})
    results = data.get("results", [])

    rows = ""
    # Vòng lặp dựng các hàng (row) dữ liệu cho bảng kết quả
    for item in results:
        status_code = item.get("response", {}).get("status_code")
        detected = item.get("detected", False)
        result_text = "Phát hiện" if detected else "Không phát hiện"
        result_class = "detected" if detected else "not-detected"

        rows += f"""
        <tr>
            <td>{item.get("scenario_id", "")}</td>
            <td>{item.get("vulnerability_type", "")}</td>
            <td>
                <strong>{item.get("target", {}).get("method", "")}</strong> 
                {item.get("target", {}).get("path", "")}
            </td>
            <td><code>{status_code}</code></td>
            <td class="{result_class}">{result_text}</td>
            <td><small>{item.get("evidence_summary", "")}</small></td>
        </tr>
        """

    # Tính toán các thông số thống kê ở thẻ meta
    total = meta.get("total_scenarios", len(results))
    detected_count = meta.get("detected_count", 0)
    detection_rate = round(detected_count / total * 100, 2) if total else 0

    # Trả về toàn bộ giao diện HTML kết hợp CSS chỉn chu
    return f"""
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <title>Scan Results Dashboard</title>
        <style>
            body {{
                font-family: 'Segoe UI', Arial, sans-serif;
                margin: 40px;
                background: #f8fafc;
                color: #1e293b;
            }}
            h1 {{
                color: #0f172a;
                border-bottom: 2px solid #e2e8f0;
                padding-bottom: 15px;
            }}
            .summary {{
                display: flex;
                gap: 20px;
                margin-bottom: 30px;
                margin-top: 20px;
            }}
            .card {{
                background: white;
                padding: 20px 30px;
                border-radius: 12px;
                box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);
                flex: 1;
                border: 1px solid #e2e8f0;
            }}
            .card strong {{
                color: #64748b;
                font-size: 14px;
                text-transform: uppercase;
            }}
            .card h2 {{
                margin: 10px 0 0 0;
                font-size: 28px;
                color: #1e293b;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                background: white;
                border-radius: 12px;
                overflow: hidden;
                box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);
                border: 1px solid #e2e8f0;
            }}
            th, td {{
                padding: 14px 18px;
                border-bottom: 1px solid #e2e8f0;
                text-align: left;
            }}
            th {{
                background: #2563eb;
                color: white;
                font-weight: 600;
            }}
            tr:hover {{
                background: #f8fafc;
            }}
            code {{
                background: #f1f5f9;
                padding: 4px 8px;
                border-radius: 4px;
                font-family: monospace;
            }}
            .detected {{
                color: #16a34a;
                font-weight: bold;
            }}
            .not-detected {{
                color: #dc2626;
                font-weight: bold;
            }}
        </style>
    </head>
    <body>
        <h1>📊 Kết quả kiểm thử tự động Web API</h1>

        <div class="summary">
            <div class="card">
                <strong>Tổng số Kịch bản (Scenarios)</strong>
                <h2>{total}</h2>
            </div>
            <div class="card">
                <strong>Số lỗ hổng phát hiện</strong>
                <h2 style="color: #16a34a;">{detected_count}</h2>
            </div>
            <div class="card">
                <strong>Tỷ lệ phát hiện thành công</strong>
                <h2 style="color: #2563eb;">{detection_rate}%</h2>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th style="width: 12%;">Scenario ID</th>
                    <th style="width: 18%;">Loại lỗ hổng</th>
                    <th style="width: 25%;">Endpoint kiểm thử</th>
                    <th style="width: 12%;">Status Code</th>
                    <th style="width: 15%;">Kết quả quét</th>
                    <th style="width: 18%;">Bằng chứng (Evidence)</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </body>
    </html>
    """

