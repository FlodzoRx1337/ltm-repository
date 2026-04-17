from flask import Flask, request, jsonify
from datetime import datetime, timedelta
import hashlib
import json
import os

DB_FILE = "users_db.json"
ADMIN_SECRET = "super_secret_admin_key"  # можешь поменять на свой ключ

app = Flask(__name__)

def h(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def load_db():
    if not os.path.exists(DB_FILE):
        return {"users": []}
    with open(DB_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_db(db):
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)

def gen_uid(db):
    used = {int(u["uid"]) for u in db["users"] if "uid" in u and str(u["uid"]).isdigit()}
    uid = 1
    while uid in used:
        uid += 1
    return str(uid)

def find_user_by_login(db, login):
    for u in db["users"]:
        if u.get("login", "").lower() == login.lower():
            return u
    return None

def require_admin(req):
    key = (req.args.get("key") or (req.json or {}).get("key") or "").strip()
    return key == ADMIN_SECRET

@app.route("/auth", methods=["POST"])
def auth():
    data = request.json or {}
    login = data.get("login", "").strip()
    password = data.get("password", "")
    hwid = data.get("hwid", "")

    db = load_db()
    user = find_user_by_login(db, login)
    if not user or user.get("pass_hash") != h(password):
        return jsonify({"ok": False, "error": "bad_credentials"}), 401

    if user.get("banned"):
        return jsonify({"ok": False, "error": "banned"}), 403

    plan = user.get("plan")
    expire_at = user.get("expire_at")

    if plan != "lifetime":
        if not expire_at:
            return jsonify({"ok": False, "error": "no_expire"}), 402
        try:
            exp = datetime.fromisoformat(expire_at)
        except ValueError:
            return jsonify({"ok": False, "error": "bad_date"}), 500
        if datetime.utcnow() > exp:
            return jsonify({"ok": False, "error": "expired"}), 402

    saved_hwid = user.get("hwid")
    if saved_hwid and saved_hwid != hwid:
        return jsonify({"ok": False, "error": "hwid_mismatch"}), 403
    if not saved_hwid:
        user["hwid"] = hwid
        save_db(db)

    return jsonify({
        "ok": True,
        "uid": user.get("uid"),
        "login": user.get("login"),
        "name": user.get("name"),
        "plan": user.get("plan"),
        "expire_at": user.get("expire_at"),
        "hwid": user.get("hwid")
    }), 200

@app.route("/admin/create_user", methods=["POST"])
def admin_create_user():
    if not require_admin(request):
        return jsonify({"ok": False, "error": "forbidden"}), 403

    data = request.json or {}
    login = data.get("login", "").strip()
    name = data.get("name", "").strip() or login
    password = data.get("password", "")

    db = load_db()
    if find_user_by_login(db, login):
        return jsonify({"ok": False, "error": "exists"}), 400

    uid = gen_uid(db)
    user = {
        "uid": uid,
        "login": login,
        "name": name,
        "pass_hash": h(password),
        "plan": "none",
        "expire_at": None,
        "banned": False,
        "hwid": None
    }
    db["users"].append(user)
    save_db(db)
    return jsonify({"ok": True, "uid": uid})

@app.route("/admin/set_sub", methods=["POST"])
def admin_set_sub():
    if not require_admin(request):
        return jsonify({"ok": False, "error": "forbidden"}), 403

    data = request.json or {}
    login = data.get("login", "").strip()
    plan = data.get("plan", "").strip()  # "30","60","90","365","lifetime"

    db = load_db()
    user = find_user_by_login(db, login)
    if not user:
        return jsonify({"ok": False, "error": "not_found"}), 404

    if plan == "lifetime":
        user["plan"] = "lifetime"
        user["expire_at"] = None
    else:
        DAYS = {"30": 30, "60": 60, "90": 90, "365": 365}
        if plan not in DAYS:
            return jsonify({"ok": False, "error": "bad_plan"}), 400
        now = datetime.utcnow()
        exp = now + timedelta(days=DAYS[plan])
        user["plan"] = f"sub{plan}"
        user["expire_at"] = exp.isoformat(timespec="seconds")

    save_db(db)
    return jsonify({"ok": True})

@app.route("/admin/set_hwid", methods=["POST"])
def admin_set_hwid():
    if not require_admin(request):
        return jsonify({"ok": False, "error": "forbidden"}), 403

    data = request.json or {}
    login = data.get("login", "").strip()
    hwid = data.get("hwid", "").strip()

    db = load_db()
    user = find_user_by_login(db, login)
    if not user:
        return jsonify({"ok": False, "error": "not_found"}), 404

    user["hwid"] = hwid or None
    save_db(db)
    return jsonify({"ok": True})

@app.route("/admin/ban_toggle", methods=["POST"])
def admin_ban_toggle():
    if not require_admin(request):
        return jsonify({"ok": False, "error": "forbidden"}), 403

    data = request.json or {}
    login = data.get("login", "").strip()

    db = load_db()
    user = find_user_by_login(db, login)
    if not user:
        return jsonify({"ok": False, "error": "not_found"}), 404

    user["banned"] = not user.get("banned", False)
    save_db(db)
    return jsonify({"ok": True, "banned": user["banned"]})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
