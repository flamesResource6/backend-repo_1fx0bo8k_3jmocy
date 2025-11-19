"""
Database Schemas for DermaCare+

Each Pydantic model corresponds to a MongoDB collection.
Collection name = lowercase of the class name (handled by caller).

We keep fields focused and pragmatic so the MVP works end-to-end.
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List
from datetime import datetime


class User(BaseModel):
    email: EmailStr
    password_hash: str = Field(..., description="Hashed password")
    name: Optional[str] = None
    phone: Optional[str] = None
    gender: Optional[str] = Field(None, description="male | female | other")
    age: Optional[int] = Field(None, ge=0, le=120)
    photo_url: Optional[str] = None
    preferred_doctor_id: Optional[str] = None
    health_notes: Optional[str] = None
    loyalty_points: int = 0
    role: str = Field("user", description="user | doctor | admin")


class Doctor(BaseModel):
    name: str
    specialty: str
    photo_url: Optional[str] = None
    bio: Optional[str] = None
    rating: float = 5.0


class Service(BaseModel):
    name: str
    category: str
    description: Optional[str] = None
    duration_minutes: int = 30
    price: float = 0.0
    before_after_images: Optional[List[str]] = None
    video_url: Optional[str] = None
    featured: bool = False


class Appointment(BaseModel):
    user_id: str
    doctor_id: Optional[str] = None
    service_id: str
    date: str  # ISO date string (YYYY-MM-DD)
    time: str  # HH:mm
    mode: str = Field("in_clinic", description="in_clinic | online")
    status: str = Field("pending", description="pending | approved | rejected | completed | cancelled")
    payment_status: str = Field("unpaid", description="unpaid | paid | refunded")
    notes: Optional[str] = None


class Message(BaseModel):
    user_id: str
    doctor_id: str
    sender: str = Field(..., description="user | doctor")
    text: Optional[str] = None
    image_url: Optional[str] = None
    audio_url: Optional[str] = None
    created_at: Optional[datetime] = None


class Offer(BaseModel):
    title: str
    description: Optional[str] = None
    image_url: Optional[str] = None
    starts_at: Optional[datetime] = None
    ends_at: Optional[datetime] = None
    promo_code: Optional[str] = None
    discount_percent: Optional[int] = Field(None, ge=1, le=100)


class Payment(BaseModel):
    user_id: str
    appointment_id: Optional[str] = None
    amount: float
    currency: str = "USD"
    provider: str = Field("stripe", description="stripe | apple_pay | google_pay | wallet")
    status: str = Field("initiated", description="initiated | succeeded | failed | refunded")
    reference: Optional[str] = None


class NotificationToken(BaseModel):
    user_id: str
    platform: str = Field(..., description="ios | android | web")
    token: str
    locale: Optional[str] = None
    tz: Optional[str] = None
