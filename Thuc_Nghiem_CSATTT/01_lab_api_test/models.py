from sqlalchemy import Column, Integer, String, Boolean, Float, ForeignKey, Text, DateTime
from sqlalchemy.orm import relationship
import datetime
from datetime import timezone
from database import Base

# 1. Bảng Users (Lưu trữ thông tin định danh và phân quyền)
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="user")                 

    profile = relationship("UserProfile", uselist=False, back_populates="user", cascade="all, delete-orphan")
    orders = relationship("Order", back_populates="user")

# 2. Bảng User Profiles (Thông tin cá nhân nâng cao)
class UserProfile(Base):
    __tablename__ = "user_profiles"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True)
    full_name = Column(String, index=True)
    phone_number = Column(String)  # Khớp với tài liệu thiết kế
    address = Column(String)       # Khớp với tài liệu thiết kế

    user = relationship("User", back_populates="profile")

# 3. Bảng Products (Thông tin sản phẩm lưu kho)
class Product(Base):
    __tablename__ = "products"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True, nullable=False)
    description = Column(Text)
    price = Column(Float, nullable=False)
    stock_quantity = Column(Integer, default=0)

# 4. Bảng Orders (Thông tin đơn hàng tổng quát)
class Order(Base):
    __tablename__ = "orders"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    total_amount = Column(Float, default=0.0)
    status = Column(String, default="Pending")         
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.datetime.now(timezone.utc))

    user = relationship("User", back_populates="orders")
    items = relationship("OrderItem", back_populates="order", cascade="all, delete-orphan")

# 5. Bảng Order Items (Chi tiết mặt hàng trong đơn hàng)
class OrderItem(Base):
    __tablename__ = "order_items"

    id = Column(Integer, primary_key=True, index=True)
    order_id = Column(Integer, ForeignKey("orders.id", ondelete="CASCADE"))
    product_id = Column(Integer, ForeignKey("products.id"))
    quantity = Column(Integer, default=1)
    unit_price = Column(Float)                  

    order = relationship("Order", back_populates="items")
    product = relationship("Product")

# 6. Bảng Vulnerability Ground Truth (Bảng đối chứng quản lý đáp án kiểm thử bảo mật cho AI)
class VulnerabilityGroundTruth(Base):
    __tablename__ = "vulnerability_ground_truth"

    id = Column(Integer, primary_key=True, index=True)
    vuln_id = Column(String, unique=True, index=True, nullable=False) # Khớp tài liệu: VULN_001
    vuln_type = Column(String, nullable=False)                       # Khớp tài liệu: BOLA, BFLA, ...
    target_endpoint = Column(String, nullable=False)                 # Khớp tài liệu: URL endpoint
    http_method = Column(String, nullable=False)                     # Khớp tài liệu: GET, POST...
    severity = Column(String, nullable=False)                        # Khớp tài liệu: High, Critical...
    description = Column(Text, nullable=False)                       # Khớp tài liệu: Mô tả chi tiết
