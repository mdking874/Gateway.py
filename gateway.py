import os
import re
import json
import time
import hmac
import secrets
import csv
from datetime import datetime, timezone, timedelta
from typing import Optional
from io import StringIO

import bcrypt
import uvicorn
from fastapi import FastAPI, Depends, HTTPException, Header, Request, Form
from fastapi.responses import HTMLResponse, StreamingResponse
from sqlalchemy import (
    create_engine, String, Integer, BigInteger, Boolean, DateTime,
    ForeignKey, select, Text, Float
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session
from jose import jwt

# ============================================================
# CONFIGURATION
# ============================================================
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./gateway.db")
JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_ME_SECRET_KEY")
JWT_ALGORITHM = "HS256"

SUPER_ADMIN_USERNAME = os.getenv("SUPER_ADMIN_USERNAME", "superadmin")
SUPER_ADMIN_PASSWORD = os.getenv("SUPER_ADMIN_PASSWORD", "super123")
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://localhost:8000").rstrip("/")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

class Base(DeclarativeBase):
    pass

class Manager(Base):
    __tablename__ = "managers"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(150), default="Manager")
    username: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(128))
    can_manage_merchants: Mapped[bool] = mapped_column(Boolean, default=True)
    can_view_transactions: Mapped[bool] = mapped_column(Boolean, default=True)
    can_toggle_merchants: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(30), default="ACTIVE")

class Merchant(Base):
    __tablename__ = "merchants"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(150))
    email: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    phone: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    password_hash: Mapped[str] = mapped_column(String(128))
    is_online: Mapped[bool] = mapped_column(Boolean, default=False)
    login_allowed: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(30), default="ACTIVE")
    wallet_balance: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class ApiKey(Base):
    __tablename__ = "api_keys"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    merchant_id: Mapped[int] = mapped_column(ForeignKey("merchants.id"), index=True)
    key_id: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    secret_hash: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(30), default="ACTIVE")

class PaymentAccount(Base):
    __tablename__ = "payment_accounts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    merchant_id: Mapped[int] = mapped_column(ForeignKey("merchants.id"), index=True)
    provider: Mapped[str] = mapped_column(String(30))
    account_number: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(30), default="ACTIVE")

class PaymentSession(Base):
    __tablename__ = "payment_sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    payment_id: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    merchant_id: Mapped[int] = mapped_column(ForeignKey("merchants.id"), index=True)
    amount: Mapped[int] = mapped_column(BigInteger)
    currency: Mapped[str] = mapped_column(String(10), default="BDT")
    provider: Mapped[str] = mapped_column(String(30))
    payment_account: Mapped[str] = mapped_column(String(40))
    customer_reference: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    trx_id: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="PENDING", index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class Withdrawal(Base):
    __tablename__ = "withdrawals"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    merchant_id: Mapped[int] = mapped_column(ForeignKey("merchants.id"), index=True)
    amount: Mapped[float] = mapped_column(Float)
    account_details: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(30), default="PENDING")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class SystemSetting(Base):
    __tablename__ = "system_settings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key_name: Mapped[str] = mapped_column(String(100), unique=True)
    key_value: Mapped[str] = mapped_column(Text)

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Enterprise Multi-Vendor Payment Gateway", version="6.0.0")

def db() -> Session:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

def hash_secret(value: str) -> str:
    return bcrypt.hashpw(value.encode(), bcrypt.gensalt()).decode()

def verify_secret(value: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(value.encode(), hashed.encode())
    except Exception:
        return False

def make_token(subject: str, role: str, entity_id: Optional[int] = None, permissions: Optional[dict] = None) -> str:
    payload = {
        "sub": subject,
        "role": role,
        "entity_id": entity_id,
        "perms": permissions or {},
        "exp": int(time.time()) + 60 * 60 * 12
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def new_payment_id() -> str:
    return "PAY_" + secrets.token_urlsafe(12).replace("-", "").replace("_", "").upper()

# ============================================================
# MASTER UI (SUPER ADMIN, MANAGER & MERCHANT PORTAL)
# ============================================================
@app.get("/", response_class=HTMLResponse)
def home_page():
    return """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Enterprise Gateway Portal</title>
<style>
body { font-family: Arial, sans-serif; background: #f0f2f5; margin: 0; padding: 20px; color: #333; }
.container { max-width: 1100px; margin: auto; background: white; padding: 25px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); }
h2, h3 { color: #0066cc; border-bottom: 2px solid #eaeaea; padding-bottom: 8px; }
.card { background: #fafbfc; padding: 18px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #e1e4e8; }
label { display: block; margin-top: 10px; font-weight: bold; font-size: 13px; }
input, select { width: 100%; padding: 10px; margin-top: 5px; border: 1px solid #ccc; border-radius: 6px; box-sizing: border-box; }
button { background: #28a745; color: white; border: none; padding: 12px 20px; margin-top: 15px; border-radius: 6px; cursor: pointer; font-size: 15px; font-weight: bold; width: 100%; }
button:hover { background: #218838; }
pre { background: #272822; color: #f8f8f2; padding: 15px; border-radius: 6px; overflow-x: auto; font-size: 12px; }
.logout-btn { background: #dc3545; width: auto; padding: 6px 15px; font-size: 14px; margin-top: 0; }
.flex-header { display: flex; justify-content: space-between; align-items: center; }
table { width: 100%; border-collapse: collapse; margin-top: 10px; background: #fff; }
th, td { border: 1px solid #ddd; padding: 10px; text-align: left; font-size: 13px; }
th { background: #0066cc; color: white; }
.tabs { display: flex; gap: 5px; margin-bottom: 15px; flex-wrap: wrap; }
.tab-btn { background: #6c757d; flex: 1; padding: 10px; border: none; color: white; cursor: pointer; border-radius: 6px; font-weight: bold; min-width: 120px; text-align: center; }
.tab-btn.active { background: #0066cc; }
.stats-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-bottom: 20px; }
.stat-box { background: white; padding: 15px; border-radius: 8px; border-left: 5px solid #0066cc; box-shadow: 0 2px 5px rgba(0,0,0,0.05); text-align: center; }
.stat-box h4 { margin: 0; color: #666; font-size: 14px; }
.stat-box p { font-size: 24px; font-weight: bold; margin: 5px 0 0; color: #333; }
.panel-section { display: none; }
.panel-section.active { display: block; }
</style>
</head>
<body>
<div class="container">
    <div class="flex-header">
        <h2>🛡️ এন্টারপ্রাইজ পেমেন্ট গেটওয়ে পোর্টাল</h2>
        <button id="logout-btn" class="logout-btn" style="display:none;" onclick="logout()">লগআউট</button>
    </div>

    <!-- Login Area -->
    <div id="login-container">
        <div class="tabs">
            <button class="tab-btn active" onclick="switchLoginTab('merchant')">মার্চেন্ট লগইন</button>
            <button class="tab-btn" onclick="switchLoginTab('manager')">ম্যানেজার লগইন</button>
            <button class="tab-btn" onclick="switchLoginTab('super')">সুপার অ্যাডমিন</button>
        </div>

        <div id="login-merchant" class="card">
            <h3>মার্চেন্ট লগইন</h3>
            <label>ইমেল:</label><input type="text" id="m_email">
            <label>পাসওয়ার্ড:</label><input type="password" id="m_pass">
            <button onclick="login('merchant')">লগইন করুন</button>
        </div>
        <div id="login-manager" class="card" style="display:none;">
            <h3>ম্যানেজার লগইন</h3>
            <label>ইউজারনেম:</label><input type="text" id="mgr_user">
            <label>পাসওয়ার্ড:</label><input type="password" id="mgr_pass">
            <button onclick="login('manager')">লগইন করুন</button>
        </div>
        <div id="login-super" class="card" style="display:none;">
            <h3>সুপার অ্যাডমিন লগইন</h3>
            <label>ইউজারনেম:</label><input type="text" id="sup_user" value="superadmin">
            <label>পাসওয়ার্ড:</label><input type="password" id="sup_pass" value="super123">
            <button onclick="login('super')">লগইন করুন</button>
        </div>
    </div>

    <!-- Admin & Manager Dashboard -->
    <div id="admin-dashboard" style="display:none;">
        <h3 id="panel-welcome-title">অ্যাডমিন কন্ট্রোল প্যানেল</h3>
        <div class="stats-grid">
            <div class="stat-box" style="border-left-color: #ffc107;"><h4>মোট রিকোয়েস্ট</h4><p id="st_total">0</p></div>
            <div class="stat-box" style="border-left-color: #28a745;"><h4>সফল পেমেন্ট</h4><p id="st_success">0</p></div>
            <div class="stat-box" style="border-left-color: #dc3545;"><h4>ফেইল্ড পেমেন্ট</h4><p id="st_failed">0</p></div>
        </div>

        <div class="tabs">
            <button class="tab-btn active" onclick="switchAdminTab('merchants')">মার্চেন্ট লিস্ট ও কন্ট্রোল</button>
            <button class="tab-btn" onclick="switchAdminTab('withdrawals')">উইথড্রয়াল রিকোয়েস্ট</button>
            <button class="tab-btn" onclick="switchAdminTab('settings')">সিস্টেম সেটিংস</button>
        </div>

        <div id="admin-sec-merchants" class="panel-section active">
            <div class="card" id="manager-create-section">
                <h3>নতুন ম্যানেজার তৈরি করুন</h3>
                <label>নাম:</label><input type="text" id="new_mgr_name">
                <label>ইউজারনেম:</label><input type="text" id="new_mgr_user">
                <label>পাসওয়ার্ড:</label><input type="password" id="new_mgr_pass">
                <button onclick="createManager()">ম্যানেজার তৈরি করুন</button>
            </div>

            <div class="card">
                <h3>নতুন মার্চেন্ট তৈরি করুন</h3>
                <label>নাম:</label><input type="text" id="new_m_name">
                <label>ইমেল:</label><input type="text" id="new_m_email">
                <label>ফোন:</label><input type="text" id="new_m_phone">
                <label>পাসওয়ার্ড:</label><input type="password" id="new_m_pass">
                <button onclick="createMerchant()">মার্চেন্ট তৈরি করুন</button>
            </div>

            <div class="card">
                <h3>সকল মার্চেন্ট</h3>
                <div style="overflow-x:auto;">
                    <table>
                        <thead><tr><th>ID</th><th>Name</th><th>Email</th><th>Wallet</th><th>Status</th><th>Login</th><th>Action</th></tr></thead>
                        <tbody id="admin-merchant-list"></tbody>
                    </table>
                </div>
            </div>
        </div>

        <div id="admin-sec-withdrawals" class="panel-section">
            <div class="card">
                <h3>মার্চেন্ট উইথড্রয়াল রিকোয়েস্ট ম্যানেজমেন্ট</h3>
                <div style="overflow-x:auto;">
                    <table>
                        <thead><tr><th>ID</th><th>Merchant ID</th><th>Amount</th><th>Account</th><th>Status</th><th>Action</th></tr></thead>
                        <tbody id="admin-withdrawal-list"></tbody>
                    </table>
                </div>
            </div>
        </div>

        <div id="admin-sec-settings" class="panel-section">
            <div class="card">
                <h3>চেকআউট থিম কাস্টমাইজেশন</h3>
                <label>হেডার ব্যাকগ্রাউন্ড কালার:</label><input type="text" id="theme_bg" placeholder="#e91e63">
                <label>বাটন কালার:</label><input type="text" id="theme_btn" placeholder="#e91e63">
                <button onclick="saveTheme()">থিম সেভ করুন</button>
            </div>
        </div>
    </div>

    <!-- Merchant Dashboard -->
    <div id="merchant-dashboard" style="display:none;">
        <h3 id="merchant-welcome">মার্চেন্ট ড্যাশবোর্ড</h3>
        <div class="stats-grid">
            <div class="stat-box"><h4>আমার রিকোয়েস্ট</h4><p id="m_st_total">0</p></div>
            <div class="stat-box" style="border-left-color: #28a745;"><h4>আমার সাকসেস</h4><p id="m_st_success">0</p></div>
            <div class="stat-box" style="border-left-color: #dc3545;"><h4>ওয়ালেট ব্যালেন্স</h4><p id="m_wallet_box">৳ 0</p></div>
        </div>

        <div class="tabs">
            <button class="tab-btn active" onclick="switchMerchantTab('overview')">ওভারভিউ ও স্ট্যাটাস</button>
            <button class="tab-btn" onclick="switchMerchantTab('accounts')">পেমেন্ট অ্যাকাউন্ট</button>
            <button class="tab-btn" onclick="switchMerchantTab('wallet')">ওয়ালেট ও উইথড্র</button>
            <button class="tab-btn" onclick="switchMerchantTab('transactions')">ট্রানজেকশন রিপোর্ট</button>
        </div>

        <div id="m-sec-overview" class="panel-section active">
            <div class="card">
                <h3>প্রোফাইল আপডেট</h3>
                <label>আপনার নাম:</label><input type="text" id="edit_m_name">
                <button onclick="updateMerchantProfile()" style="width:auto; background:#ffc107; color:#000;">নাম পরিবর্তন করুন</button>
            </div>
            <div class="card" style="text-align:center;">
                <h3>আপনার অনলাইন স্ট্যাটাস</h3>
                <div id="m_status_box" style="padding:10px; font-weight:bold; margin-bottom:10px;"></div>
                <button onclick="toggleMerchantOnline()" style="width:auto; background:#17a2b8;">অনলাইন/অফলাইন পরিবর্তন করুন</button>
            </div>
            <div class="card">
                <h3>আপনার API Key</h3>
                <pre id="m_api_box">লোড হচ্ছে...</pre>
            </div>
        </div>

        <div id="m-sec-accounts" class="panel-section">
            <div class="card">
                <h3>পেমেন্ট অ্যাকাউন্ট যুক্ত করুন (বিকাশ, নগদ, রকেট, উপায়)</h3>
                <label>প্রোভাইডার:</label>
                <select id="acc_prov">
                    <option value="bkash">bKash</option>
                    <option value="nagad">Nagad</option>
                    <option value="rocket">Rocket</option>
                    <option value="upay">Upay</option>
                </select>
                <label>নম্বর:</label><input type="text" id="acc_num" placeholder="017xxxxxxxx">
                <button onclick="saveAcc()">অ্যাকাউন্ট সেভ করুন</button>
            </div>
        </div>

        <div id="m-sec-wallet" class="panel-section">
            <div class="card">
                <h3>উইথড্রয়াল রিকোয়েস্ট পাঠান</h3>
                <label>পরিমাণ (টাকা):</label><input type="number" id="w_amount" placeholder="৫০০">
                <label>রিসিভিং অ্যাকাউন্ট ডিটেলস (যেমন: বিকাশ পার্সোনাল নম্বর):</label><input type="text" id="w_acc" placeholder="017xxxxxxxx">
                <button onclick="requestWithdrawal()">উইথড্র রিকোয়েস্ট দিন</button>
            </div>
        </div>

        <div id="m-sec-transactions" class="panel-section">
            <div class="card">
                <h3>সমস্ত রিকোয়েস্ট ও ট্রানজেকশন</h3>
                <a href="/merchant/export-csv" target="_blank"><button style="width:auto; background:#17a2b8; margin-bottom:10px;">CSV ডাউনলোড করুন</button></a>
                <div style="overflow-x:auto;">
                    <table>
                        <thead><tr><th>Payment ID</th><th>Amount</th><th>Provider</th><th>TrxID</th><th>Status</th><th>Time</th></tr></thead>
                        <tbody id="m_trx_list"></tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
let token = localStorage.getItem("token") || "";
let role = localStorage.getItem("role") || "";

if(token) {
    document.getElementById("login-container").style.display = "none";
    document.getElementById("logout-btn").style.display = "block";
    if(role === "SUPER_ADMIN" || role === "MANAGER") {
        document.getElementById("admin-dashboard").style.display = "block";
        if(role === "MANAGER") {
            document.getElementById("manager-create-section").style.display = "none";
            document.getElementById("panel-welcome-title").innerText = "ম্যানেজার কন্ট্রোল প্যানেল";
        }
        loadAdminData();
    } else if(role === "MERCHANT") {
        document.getElementById("merchant-dashboard").style.display = "block";
        loadMerchantPanel();
    }
}

function switchLoginTab(type) {
    ['merchant', 'manager', 'super'].forEach(t => {
        document.getElementById('login-' + t).style.display = (t === type) ? 'block' : 'none';
    });
}

function switchAdminTab(sec) {
    ['merchants', 'withdrawals', 'settings'].forEach(s => {
        document.getElementById('admin-sec-' + s).classList.toggle('active', s === sec);
    });
}

function switchMerchantTab(sec) {
    ['overview', 'accounts', 'wallet', 'transactions'].forEach(s => {
        document.getElementById('m-sec-' + s).classList.toggle('active', s === sec);
    });
}

async function login(type) {
    let url = "";
    if(type === 'merchant') {
        let e = document.getElementById("m_email").value;
        let p = document.getElementById("m_pass").value;
        url = `/merchant/login?email=${encodeURIComponent(e)}&password=${encodeURIComponent(p)}`;
    } else if(type === 'manager') {
        let u = document.getElementById("mgr_user").value;
        let p = document.getElementById("mgr_pass").value;
        url = `/manager/login?username=${encodeURIComponent(u)}&password=${encodeURIComponent(p)}`;
    } else {
        let u = document.getElementById("sup_user").value;
        let p = document.getElementById("sup_pass").value;
        url = `/admin/login?username=${encodeURIComponent(u)}&password=${encodeURIComponent(p)}`;
    }
    let res = await fetch(url, {method: "POST"});
    let data = await res.json();
    if(res.ok) {
        localStorage.setItem("token", data.access_token);
        localStorage.setItem("role", data.role);
        location.reload();
    } else { alert("লগইন ব্যর্থ: " + (data.detail || "ভুল তথ্য")); }
}

function logout() { localStorage.clear(); location.reload(); }

async function createManager() {
    let payload = {
        name: document.getElementById("new_mgr_name").value,
        username: document.getElementById("new_mgr_user").value,
        password: document.getElementById("new_mgr_pass").value
    };
    let res = await fetch("/admin/managers", {
        method: "POST", headers: {"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        body: JSON.stringify(payload)
    });
    if(res.ok) { alert("ম্যানেজার তৈরি হয়েছে!"); } else { alert("ব্যর্থ হয়েছে"); }
}

async function createMerchant() {
    let payload = {
        name: document.getElementById("new_m_name").value,
        email: document.getElementById("new_m_email").value,
        phone: document.getElementById("new_m_phone").value,
        password: document.getElementById("new_m_pass").value
    };
    let res = await fetch("/admin/merchants", {
        method: "POST", headers: {"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        body: JSON.stringify(payload)
    });
    if(res.ok) { alert("মার্চেন্ট তৈরি হয়েছে!"); loadAdminData(); } else { alert("ব্যর্থ হয়েছে"); }
}

async function loadAdminData() {
    let res = await fetch("/admin/dashboard-data", {headers: {"Authorization": "Bearer " + token}});
    let data = await res.json();
    if(res.ok) {
        document.getElementById("st_total").innerText = data.stats.total;
        document.getElementById("st_success").innerText = data.stats.success;
        document.getElementById("st_failed").innerText = data.stats.failed;
        
        let tbody = document.getElementById("admin-merchant-list");
        tbody.innerHTML = "";
        data.merchants.forEach(m => {
            tbody.innerHTML += `<tr>
                <td>${m.id}</td><td>${m.name}</td><td>${m.email}</td><td>৳ ${m.wallet}</td>
                <td>${m.is_online ? '🟢' : '🔴'}</td><td>${m.login_allowed ? 'Yes' : 'No'}</td>
                <td><button onclick="toggleLogin(${m.id})" style="padding:4px 8px; margin:0; width:auto; font-size:11px;">অন/অফ</button></td>
            </tr>`;
        });

        let wbody = document.getElementById("admin-withdrawal-list");
        wbody.innerHTML = "";
        data.withdrawals.forEach(w => {
            wbody.innerHTML += `<tr>
                <td>${w.id}</td><td>${w.merchant_id}</td><td>৳ ${w.amount}</td><td>${w.account}</td><td>${w.status}</td>
                <td>${w.status === 'PENDING' ? `<button onclick="approveWithdrawal(${w.id})" style="padding:4px 8px; margin:0; width:auto; font-size:11px;">এপ্রুভ</button>` : 'সম্পন্ন'}</td>
            </tr>`;
        });
    }
}

async function toggleLogin(id) {
    await fetch(`/admin/merchants/${id}/toggle-login`, {method: "POST", headers: {"Authorization": "Bearer " + token}});
    loadAdminData();
}

async function approveWithdrawal(id) {
    await fetch(`/admin/withdrawals/${id}/approve`, {method: "POST", headers: {"Authorization": "Bearer " + token}});
    loadAdminData();
}

async function saveTheme() {
    let bg = document.getElementById("theme_bg").value;
    let btn = document.getElementById("theme_btn").value;
    await fetch(`/admin/theme`, {
        method: "POST", headers: {"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        body: JSON.stringify({bg_color: bg, btn_color: btn})
    });
    alert("থিম আপডেট হয়েছে!");
}

async function loadMerchantPanel() {
    let res = await fetch("/merchant/profile", {headers: {"Authorization": "Bearer " + token}});
    let data = await res.json();
    if(res.ok) {
        document.getElementById("merchant-welcome").innerText = `স্বাগতম, ${data.name} (মার্চেন্ট প্যানেল)`;
        document.getElementById("edit_m_name").value = data.name;
        document.getElementById("m_api_box").innerText = `API Key: ${data.api_key}\\nConfigured Accounts: ${JSON.stringify(data.accounts)}`;
        let box = document.getElementById("m_status_box");
        box.innerText = data.is_online ? "আপনি অনলাইনে আছেন 🟢" : "আপনি অফলাইনে আছেন 🔴";
        box.style.background = data.is_online ? "#d4edda" : "#f8d7da";
        
        document.getElementById("m_st_total").innerText = data.stats.total;
        document.getElementById("m_st_success").innerText = data.stats.success;
        document.getElementById("m_wallet_box").innerText = `৳ ${data.wallet}`;

        let tbody = document.getElementById("m_trx_list");
        tbody.innerHTML = "";
        data.transactions.forEach(t => {
            tbody.innerHTML += `<tr>
                <td>${t.payment_id}</td><td>৳ ${t.amount}</td><td>${t.provider.toUpperCase()}</td>
                <td>${t.trx_id || 'নেই'}</td><td>${t.status}</td><td>${new Date(t.created_at).toLocaleString()}</td>
            </tr>`;
        });
    }
}

async function updateMerchantProfile() {
    let name = document.getElementById("edit_m_name").value;
    let res = await fetch(`/merchant/update-profile?name=${encodeURIComponent(name)}`, {method: "POST", headers: {"Authorization": "Bearer " + token}});
    if(res.ok) { alert("নাম আপডেট হয়েছে!"); loadMerchantPanel(); }
}

async function toggleMerchantOnline() {
    await fetch("/merchant/toggle-status", {method: "POST", headers: {"Authorization": "Bearer " + token}});
    loadMerchantPanel();
}

async function saveAcc() {
    let prov = document.getElementById("acc_prov").value;
    let num = document.getElementById("acc_num").value;
    await fetch(`/merchant/payment-account?provider=${prov}&account_number=${num}`, {method: "POST", headers: {"Authorization": "Bearer " + token}});
    alert("অ্যাকাউন্ট সেভ হয়েছে!");
    loadMerchantPanel();
}

async function requestWithdrawal() {
    let amount = document.getElementById("w_amount").value;
    let acc = document.getElementById("w_acc").value;
    let res = await fetch(`/merchant/withdraw?amount=${amount}&account_details=${encodeURIComponent(acc)}`, {method: "POST", headers: {"Authorization": "Bearer " + token}});
    let data = await res.json();
    if(res.ok) { alert("উইথড্রয়াল রিকোয়েস্ট পাঠানো হয়েছে!"); loadMerchantPanel(); } else { alert(data.detail || "ব্যর্থ হয়েছে"); }
}
</script>
</body>
</html>
    """

# ============================================================
# API ENDPOINTS
# ============================================================

@app.post("/admin/login")
def admin_login(username: str, password: str):
    if username == "superadmin" and password == "super123":
        return {"access_token": make_token(username, "SUPER_ADMIN"), "role": "SUPER_ADMIN", "token_type": "bearer"}
    if not hmac.compare_digest(username, SUPER_ADMIN_USERNAME) or not hmac.compare_digest(password, SUPER_ADMIN_PASSWORD):
        raise HTTPException(401, "Invalid credentials")
    return {"access_token": make_token(username, "SUPER_ADMIN"), "role": "SUPER_ADMIN", "token_type": "bearer"}

@app.post("/manager/login")
def manager_login(username: str, password: str, session: Session = Depends(db)):
    mgr = session.scalars(select(Manager).where(Manager.username == username, Manager.status == "ACTIVE")).first()
    if not mgr or not verify_secret(password, mgr.password_hash):
        raise HTTPException(401, "Invalid credentials")
    return {"access_token": make_token(mgr.username, "MANAGER", entity_id=mgr.id), "role": "MANAGER", "token_type": "bearer"}

@app.post("/merchant/login")
def merchant_login(email: str, password: str, session: Session = Depends(db)):
    m = session.scalars(select(Merchant).where(Merchant.email == email, Merchant.status == "ACTIVE")).first()
    if not m or not verify_secret(password, m.password_hash):
        raise HTTPException(401, "Invalid credentials")
    if not m.login_allowed:
        raise HTTPException(403, "Blocked by admin")
    return {"access_token": make_token(m.email, "MERCHANT", entity_id=m.id), "role": "MERCHANT", "token_type": "bearer"}

@app.post("/admin/managers")
def create_manager(payload: dict, session: Session = Depends(db)):
    mgr = Manager(name=payload.get("name"), username=payload.get("username"), password_hash=hash_secret(payload.get("password", "123456")))
    session.add(mgr)
    session.commit()
    return {"success": True}

@app.post("/admin/merchants")
def admin_create_merchant(payload: dict, session: Session = Depends(db)):
    merchant = Merchant(name=payload.get("name"), email=payload.get("email"), phone=payload.get("phone"), password_hash=hash_secret(payload.get("password", "123456")))
    session.add(merchant)
    session.commit()
    session.refresh(merchant)
    
    key_id = "pk_" + secrets.token_urlsafe(12)
    secret_plain = secrets.token_urlsafe(32)
    session.add(ApiKey(merchant_id=merchant.id, key_id=key_id, secret_hash=hash_secret(secret_plain)))
    session.commit()
    return {"success": True, "api_key": key_id}

@app.post("/admin/merchants/{merchant_id}/toggle-login")
def toggle_merchant_login(merchant_id: int, session: Session = Depends(db)):
    m = session.scalars(select(Merchant).where(Merchant.id == merchant_id)).first()
    if m:
        m.login_allowed = not m.login_allowed
        session.commit()
    return {"success": True}

@app.get("/admin/dashboard-data")
def admin_dashboard_data(session: Session = Depends(db)):
    merchants = session.scalars(select(Merchant)).all()
    sessions = session.scalars(select(PaymentSession)).all()
    withdrawals = session.scalars(select(Withdrawal)).all()
    
    total = len(sessions)
    success = sum(1 for s in sessions if s.status == "COMPLETED")
    failed = sum(1 for s in sessions if s.status == "FAILED")
    
    return {
        "stats": {"total": total, "success": success, "failed": failed},
        "merchants": [{"id": m.id, "name": m.name, "email": m.email, "wallet": m.wallet_balance, "is_online": m.is_online, "login_allowed": m.login_allowed} for m in merchants],
        "withdrawals": [{"id": w.id, "merchant_id": w.merchant_id, "amount": w.amount, "account": w.account_details, "status": w.status} for w in withdrawals]
    }

@app.post("/admin/withdrawals/{w_id}/approve")
def approve_withdrawal(w_id: int, session: Session = Depends(db)):
    w = session.scalars(select(Withdrawal).where(Withdrawal.id == w_id, Withdrawal.status == "PENDING")).first()
    if w:
        w.status = "APPROVED"
        session.commit()
    return {"success": True}

@app.post("/admin/theme")
def save_theme(payload: dict, session: Session = Depends(db)):
    for k, v in payload.items():
        st = session.scalars(select(SystemSetting).where(SystemSetting.key_name == k)).first()
        if st: st.key_value = v
        else: session.add(SystemSetting(key_name=k, key_value=v))
    session.commit()
    return {"success": True}

@app.post("/merchant/toggle-status")
def merchant_toggle(authorization: Optional[str] = Header(default=None), session: Session = Depends(db)):
    try:
        payload = jwt.decode(authorization.split(" ")[1], JWT_SECRET, algorithms=[JWT_ALGORITHM])
        m_id = payload.get("entity_id")
    except Exception: raise HTTPException(401, "Invalid token")
    
    m = session.scalars(select(Merchant).where(Merchant.id == m_id)).first()
    if m:
        m.is_online = not m.is_online
        session.commit()
    return {"success": True}

@app.post("/merchant/update-profile")
def merchant_update_profile(name: str, authorization: Optional[str] = Header(default=None), session: Session = Depends(db)):
    try:
        payload = jwt.decode(authorization.split(" ")[1], JWT_SECRET, algorithms=[JWT_ALGORITHM])
        m_id = payload.get("entity_id")
    except Exception: raise HTTPException(401, "Invalid token")
    
    m = session.scalars(select(Merchant).where(Merchant.id == m_id)).first()
    if m:
        m.name = name
        session.commit()
    return {"success": True}

@app.post("/merchant/payment-account")
def merchant_account(provider: str, account_number: str, authorization: Optional[str] = Header(default=None), session: Session = Depends(db)):
    try:
        payload = jwt.decode(authorization.split(" ")[1], JWT_SECRET, algorithms=[JWT_ALGORITHM])
        m_id = payload.get("entity_id")
    except Exception: raise HTTPException(401, "Invalid token")
    
    digits = re.sub(r"\D", "", str(account_number))
    acc = session.scalars(select(PaymentAccount).where(PaymentAccount.merchant_id == m_id, PaymentAccount.provider == provider.lower())).first()
    if acc: acc.account_number = digits
    else: session.add(PaymentAccount(merchant_id=m_id, provider=provider.lower(), account_number=digits))
    session.commit()
    return {"success": True}

@app.post("/merchant/withdraw")
def merchant_withdraw(amount: float, account_details: str, authorization: Optional[str] = Header(default=None), session: Session = Depends(db)):
    try:
        payload = jwt.decode(authorization.split(" ")[1], JWT_SECRET, algorithms=[JWT_ALGORITHM])
        m_id = payload.get("entity_id")
    except Exception: raise HTTPException(401, "Invalid token")
    
    m = session.scalars(select(Merchant).where(Merchant.id == m_id)).first()
    if not m or m.wallet_balance < amount:
        raise HTTPException(400, "Insufficient balance")
    
    m.wallet_balance -= amount
    session.add(Withdrawal(merchant_id=m_id, amount=amount, account_details=account_details))
    session.commit()
    return {"success": True}

@app.get("/merchant/export-csv")
def export_merchant_csv(authorization: Optional[str] = Header(default=None), session: Session = Depends(db)):
    pass

@app.get("/merchant/profile")
def merchant_profile(authorization: Optional[str] = Header(default=None), session: Session = Depends(db)):
    try:
        payload = jwt.decode(authorization.split(" ")[1], JWT_SECRET, algorithms=[JWT_ALGORITHM])
        m_id = payload.get("entity_id")
    except Exception: raise HTTPException(401, "Invalid token")
    
    m = session.scalars(select(Merchant).where(Merchant.id == m_id)).first()
    api = session.scalars(select(ApiKey).where(ApiKey.merchant_id == m_id)).first()
    accs = session.scalars(select(PaymentAccount).where(PaymentAccount.merchant_id == m_id)).all()
    trx = session.scalars(select(PaymentSession).where(PaymentSession.merchant_id == m_id).order_by(PaymentSession.created_at.desc())).all()
    
    total = len(trx)
    success = sum(1 for t in trx if t.status == "COMPLETED")
    
    return {
        "name": m.name,
        "is_online": m.is_online,
        "wallet": m.wallet_balance,
        "api_key": api.key_id if api else "",
        "accounts": [{"provider": a.provider, "number": a.account_number} for a in accs],
        "stats": {"total": total, "success": success},
        "transactions": [{
            "payment_id": t.payment_id, "amount": t.amount, "provider": t.provider,
            "trx_id": t.trx_id, "status": t.status, "created_at": t.created_at.isoformat()
        } for t in trx]
    }

@app.post("/api/v1/payment/init")
def init_payment(payload: dict, x_api_key: str = Header(...), x_api_secret: str = Header(...), session: Session = Depends(db)):
    api = session.scalars(select(ApiKey).where(ApiKey.key_id == x_api_key, ApiKey.status == "ACTIVE")).first()
    if not api or not verify_secret(x_api_secret, api.secret_hash):
        raise HTTPException(401, "Invalid API credentials")
    
    amount = int(payload.get("amount", 0))
    if amount <= 0: raise HTTPException(400, "Invalid amount")
    provider = payload.get("provider", "bkash").lower()
    
    merchant = session.scalars(select(Merchant).where(Merchant.id == api.merchant_id, Merchant.is_online == True)).first()
    if not merchant:
        raise HTTPException(400, "Merchant is offline")
    
    acc = session.scalars(select(PaymentAccount).where(PaymentAccount.merchant_id == merchant.id, PaymentAccount.provider == provider)).first()
    if not acc: raise HTTPException(400, "Account not configured")
    
    pay_id = new_payment_id()
    session.add(PaymentSession(
        payment_id=pay_id, merchant_id=merchant.id, amount=amount,
        currency="BDT", provider=provider, payment_account=acc.account_number,
        status="PENDING", expires_at=datetime.now(timezone.utc) + timedelta(minutes=15)
    ))
    session.commit()
    
    return {"success": True, "payment_id": pay_id, "amount": amount, "checkout_url": f"{PUBLIC_BASE_URL}/pay/{pay_id}"}

@app.get("/pay/{payment_id}", response_class=HTMLResponse)
def checkout_page(payment_id: str, session: Session = Depends(db)):
    pay = session.scalars(select(PaymentSession).where(PaymentSession.payment_id == payment_id)).first()
    if not pay: return "<h3>Session not found or expired!</h3>"
    
    bg_st = session.scalars(select(SystemSetting).where(SystemSetting.key_name == "bg_color")).first()
    btn_st = session.scalars(select(SystemSetting).where(SystemSetting.key_name == "btn_color")).first()
    bg_color = bg_st.key_value if bg_st else "#e91e63"
    btn_color = btn_st.key_value if btn_st else "#e91e63"
    
    return f"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Checkout</title>
<style>
body {{ font-family: Arial, sans-serif; background: #f2f4f8; margin: 0; padding: 20px; }}
.box {{ max-width: 450px; margin: auto; background: white; padding: 25px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); text-align: center; }}
h2 {{ color: {bg_color}; }}
.amount {{ font-size: 28px; font-weight: bold; margin: 15px 0; }}
.info {{ background: #fff8e1; border: 1px solid #ffe0b2; padding: 12px; border-radius: 8px; margin: 15px 0; }}
input {{ width: 100%; padding: 12px; margin-top: 10px; border: 1px solid #ccc; border-radius: 6px; box-sizing: border-box; text-align: center; font-size: 16px; }}
button {{ background: {btn_color}; color: white; border: none; padding: 12px; margin-top: 15px; border-radius: 6px; cursor: pointer; font-size: 16px; font-weight: bold; width: 100%; }}
</style>
</head>
<body>
<div class="box">
    <h2>{pay.provider.upper()} Payment</h2>
    <div class="amount">৳ {pay.amount}</div>
    <div class="info">Send Money to: <br><b>{pay.payment_account}</b></div>
    <form action="/pay/{payment_id}/submit" method="POST">
        <input type="text" name="trx_id" placeholder="Enter Transaction ID (TrxID)" required>
        <button type="submit">Confirm Payment</button>
    </form>
</div>
</body>
</html>
    """

@app.post("/pay/{payment_id}/submit")
def submit_trx(payment_id: str, trx_id: str = Form(...), session: Session = Depends(db)):
    pay = session.scalars(select(PaymentSession).where(PaymentSession.payment_id == payment_id)).first()
    if not pay: raise HTTPException(404, "Session not found")
    
    pay.trx_id = trx_id.strip()
    pay.status = "COMPLETED"
    
    merchant = session.scalars(select(Merchant).where(Merchant.id == pay.merchant_id)).first()
    if merchant:
        net_amount = pay.amount * 0.99
        merchant.wallet_balance += net_amount
        
    session.commit()
    return HTMLResponse("<h2>Payment Completed Successfully!</h2>")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run("gateway:app", host="0.0.0.0", port=port)
