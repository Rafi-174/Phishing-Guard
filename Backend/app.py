import os
import re
import hmac
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps

import requests
import mysql.connector

from flask import Flask, request, jsonify, g
from flask_cors import CORS

from itsdangerous import (
    URLSafeTimedSerializer,
    BadSignature,
    SignatureExpired
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from config import (
    FRONTEND_ORIGINS,
    FLASK_DEBUG,
    AUTH_SECRET_KEY
)

from analyzer import analyze_url

from database import (
    create_user,
    get_user_by_email,
    get_user_by_identifier,
    get_user_by_id,
    username_exists,
    create_password_reset_otp,
    get_valid_password_reset_otp,
    increment_otp_attempts,
    reset_password_with_otp,
    save_scan,
    get_all_scans,
    get_scan_statistics,
    delete_all_scans
)


# ==========================================
# APP CONFIGURATION
# ==========================================

app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 10 * 1024

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": FRONTEND_ORIGINS,
            "allow_headers": ["Content-Type", "Authorization"],
            "methods": ["GET", "POST", "DELETE", "OPTIONS"]
        }
    }
)

token_serializer = URLSafeTimedSerializer(
    AUTH_SECRET_KEY,
    salt="phishguard-auth"
)

reset_serializer = URLSafeTimedSerializer(
    AUTH_SECRET_KEY,
    salt="phishguard-password-reset"
)

TOKEN_MAX_AGE = 24 * 60 * 60
RESET_TOKEN_MAX_AGE = 10 * 60
OTP_EXPIRY_MINUTES = 10
OTP_MAX_ATTEMPTS = 5

RESEND_API_KEY = os.getenv("RESEND_API_KEY")
RESEND_FROM_EMAIL = os.getenv("RESEND_FROM_EMAIL")


# ==========================================
# COMMON RESPONSES
# ==========================================

def error_response(message, status=400):

    return jsonify({
        "status": "error",
        "message": message
    }), status


def user_response(user):

    return {
        "id": user["id"],
        "name": user["name"],
        "username": user["username"],
        "email": user["email"]
    }


# ==========================================
# TOKEN FUNCTIONS
# ==========================================

def create_access_token(user_id):

    return token_serializer.dumps({
        "user_id": int(user_id)
    })


def get_token_from_request():

    auth_header = request.headers.get("Authorization", "")

    if not auth_header.startswith("Bearer "):
        return None

    return auth_header.split(" ", 1)[1].strip()


# ==========================================
# AUTHENTICATION DECORATOR
# ==========================================

def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        token = get_token_from_request()

        if not token:
            return error_response(
                "Authentication required. Please login.",
                401
            )

        try:

            payload = token_serializer.loads(
                token,
                max_age=TOKEN_MAX_AGE
            )

            user_id = payload.get("user_id")

            if not user_id:
                raise BadSignature("Invalid token payload")

            user = get_user_by_id(user_id)

            if not user:
                return error_response(
                    "User account not found.",
                    401
                )

            g.current_user = user

        except SignatureExpired:

            return error_response(
                "Session expired. Please login again.",
                401
            )

        except (BadSignature, TypeError, ValueError):

            return error_response(
                "Invalid authentication token.",
                401
            )

        return function(*args, **kwargs)

    return wrapper


# ==========================================
# EMAIL OTP FUNCTIONS
# ==========================================

def hash_otp(otp):

    return hmac.new(
        AUTH_SECRET_KEY.encode("utf-8"),
        otp.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def send_reset_email(email, otp):

    if not RESEND_API_KEY or not RESEND_FROM_EMAIL:
        raise RuntimeError(
            "Resend email configuration is missing."
        )

    response = requests.post(
        "https://api.resend.com/emails",
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json"
        },
        json={
            "from": RESEND_FROM_EMAIL,
            "to": [email],
            "subject": "PhishGuard Password Reset OTP",
            "html": f"""
                <div style="
                    font-family: Arial, sans-serif;
                    max-width: 500px;
                    margin: auto;
                    padding: 25px;
                    color: #292631;
                ">
                    <h2 style="color: #d94350;">
                        PhishGuard
                    </h2>

                    <h3>Password Reset Verification</h3>

                    <p>
                        Your password reset verification code is:
                    </p>

                    <div style="
                        font-size: 30px;
                        font-weight: bold;
                        letter-spacing: 8px;
                        padding: 18px;
                        background: #fff0f1;
                        border-radius: 10px;
                        text-align: center;
                    ">
                        {otp}
                    </div>

                    <p>
                        This code expires in 10 minutes.
                    </p>

                    <p>
                        If you did not request a password reset,
                        you can ignore this email.
                    </p>

                    <small>
                        PhishGuard Security Team
                    </small>
                </div>
            """
        },
        timeout=15
    )

    if response.status_code not in (200, 201):
        raise RuntimeError(
            f"Email provider returned HTTP {response.status_code}"
        )


# ==========================================
# HOME / HEALTH CHECK
# ==========================================

@app.route("/api/health", methods=["GET"])
def health():

    return jsonify({
        "status": "success",
        "message": "PhishGuard backend is running."
    }), 200


# ==========================================
# USER REGISTRATION
# ==========================================

@app.route("/api/auth/register", methods=["POST"])
def register():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error_response("Request body must be valid JSON.")

    name = data.get("name")
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not all(
        isinstance(value, str)
        for value in (name, username, email, password)
    ):
        return error_response(
            "Name, username, email and password are required."
        )

    name = name.strip()
    username = username.strip()
    email = email.strip().lower()

    if not name or len(name) > 100:
        return error_response(
            "Name must be between 1 and 100 characters."
        )

    if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
        return error_response(
            "Username must be 3-30 characters and contain only letters, numbers or underscores."
        )

    if len(email) > 255 or not re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+",
        email
    ):
        return error_response("Please provide a valid email address.")

    if len(password) < 8 or len(password) > 128:
        return error_response(
            "Password must be 8 to 128 characters long."
        )

    try:

        password_hash = generate_password_hash(password)

        user_id = create_user(
            name,
            username,
            email,
            password_hash
        )

        token = create_access_token(user_id)

        user = {
            "id": user_id,
            "name": name,
            "username": username,
            "email": email
        }

        return jsonify({
            "status": "success",
            "message": "Account created successfully.",
            "token": token,
            "user": user
        }), 201

    except mysql.connector.IntegrityError as error:

        if error.errno == 1062:
            return error_response(
                "Username or email already exists.",
                409
            )

        app.logger.exception("Registration integrity error")
        return error_response("Could not create account.", 500)

    except mysql.connector.Error:

        app.logger.exception("Registration database error")

        return error_response(
            "Database operation failed.",
            500
        )


# ==========================================
# USER LOGIN - USERNAME OR EMAIL
# ==========================================

@app.route("/api/auth/login", methods=["POST"])
def login():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error_response("Request body must be valid JSON.")

    identifier = data.get("identifier")
    password = data.get("password")

    if not isinstance(identifier, str) or not isinstance(password, str):
        return error_response(
            "Username/email and password are required."
        )

    identifier = identifier.strip()

    if (
        not identifier
        or len(identifier) > 255
        or len(password) > 128
    ):
        return error_response(
            "Invalid username/email or password.",
            401
        )

    try:

        user = get_user_by_identifier(identifier)

        if not user or not check_password_hash(
            user["password_hash"],
            password
        ):
            return error_response(
                "Invalid username/email or password.",
                401
            )

        token = create_access_token(user["id"])

        return jsonify({
            "status": "success",
            "message": "Login successful.",
            "token": token,
            "user": user_response(user)
        }), 200

    except mysql.connector.Error:

        app.logger.exception("Login database error")

        return error_response(
            "Login service is temporarily unavailable.",
            500
        )


# ==========================================
# FORGOT PASSWORD - SEND OTP
# ==========================================

@app.route("/api/auth/forgot-password", methods=["POST"])
def forgot_password():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error_response("Request body must be valid JSON.")

    email = data.get("email")

    if not isinstance(email, str):
        return error_response("Please provide your email address.")

    email = email.strip().lower()

    if len(email) > 255 or not re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+",
        email
    ):
        return error_response("Please provide a valid email address.")

    # Same response whether the account exists or not.
    generic_response = {
        "status": "success",
        "message": (
            "If an account exists with this email, "
            "a password reset code will be sent."
        )
    }

    try:

        user = get_user_by_email(email)

        if not user:
            return jsonify(generic_response), 200

        otp = f"{secrets.randbelow(1000000):06d}"

        otp_digest = hash_otp(otp)

        expires_at = datetime.utcnow() + timedelta(
            minutes=OTP_EXPIRY_MINUTES
        )

        create_password_reset_otp(
            user["id"],
            otp_digest,
            expires_at
        )

        send_reset_email(email, otp)

        return jsonify(generic_response), 200

    except Exception:

        app.logger.exception("Forgot password processing failed")

        # Do not reveal account existence or provider details.
        return jsonify(generic_response), 200


# ==========================================
# VERIFY RESET OTP
# ==========================================

@app.route("/api/auth/verify-reset-otp", methods=["POST"])
def verify_reset_otp():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error_response("Request body must be valid JSON.")

    email = data.get("email")
    otp = data.get("otp")

    if not isinstance(email, str) or not isinstance(otp, str):
        return error_response("Email and OTP are required.")

    email = email.strip().lower()
    otp = otp.strip()

    if not re.fullmatch(r"\d{6}", otp):
        return error_response("Invalid or expired verification code.", 400)

    try:

        user = get_user_by_email(email)

        if not user:
            return error_response(
                "Invalid or expired verification code.",
                400
            )

        otp_record = get_valid_password_reset_otp(user["id"])

        if not otp_record:
            return error_response(
                "Invalid or expired verification code.",
                400
            )

        supplied_hash = hash_otp(otp)

        if not hmac.compare_digest(
            supplied_hash,
            otp_record["otp_hash"]
        ):

            increment_otp_attempts(otp_record["id"])

            return error_response(
                "Invalid or expired verification code.",
                400
            )

        reset_token = reset_serializer.dumps({
            "user_id": int(user["id"]),
            "otp_id": int(otp_record["id"])
        })

        return jsonify({
            "status": "success",
            "message": "OTP verified successfully.",
            "reset_token": reset_token
        }), 200

    except mysql.connector.Error:

        app.logger.exception("OTP verification database error")

        return error_response(
            "Could not verify the code right now.",
            500
        )


# ==========================================
# RESET PASSWORD
# ==========================================

@app.route("/api/auth/reset-password", methods=["POST"])
def reset_password():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error_response("Request body must be valid JSON.")

    reset_token = data.get("reset_token")
    new_password = data.get("new_password")

    if not isinstance(reset_token, str):
        return error_response("Password reset verification is required.")

    if not isinstance(new_password, str):
        return error_response("New password is required.")

    if len(new_password) < 8 or len(new_password) > 128:
        return error_response(
            "Password must be 8 to 128 characters long."
        )

    try:

        payload = reset_serializer.loads(
            reset_token,
            max_age=RESET_TOKEN_MAX_AGE
        )

        user_id = payload.get("user_id")
        otp_id = payload.get("otp_id")

        if not user_id or not otp_id:
            return error_response(
                "Invalid or expired password reset session.",
                400
            )

        new_password_hash = generate_password_hash(new_password)

        success = reset_password_with_otp(
            user_id,
            otp_id,
            new_password_hash
        )

        if not success:
            return error_response(
                "Verification expired or already used. Request a new code.",
                400
            )

        return jsonify({
            "status": "success",
            "message": "Password reset successfully. Please login again."
        }), 200

    except SignatureExpired:

        return error_response(
            "Password reset session expired. Request a new code.",
            400
        )

    except BadSignature:

        return error_response(
            "Invalid password reset session.",
            400
        )

    except mysql.connector.Error:

        app.logger.exception("Password reset database error")

        return error_response(
            "Could not reset password right now.",
            500
        )


# ==========================================
# CURRENT USER PROFILE
# ==========================================

@app.route("/api/auth/me", methods=["GET"])
@login_required
def current_user():

    return jsonify({
        "status": "success",
        "user": user_response(g.current_user)
    }), 200


# ==========================================
# LOGOUT
# ==========================================

@app.route("/api/auth/logout", methods=["POST"])
@login_required
def logout():

    return jsonify({
        "status": "success",
        "message": "Logout successful. Remove the token from the frontend."
    }), 200


# ==========================================
# URL SCAN API
# ==========================================

@app.route("/api/scan", methods=["POST"])
@login_required
def scan_url():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error_response("Request body must be valid JSON.")

    url = data.get("url")

    if not isinstance(url, str):
        return error_response("Please provide a URL.")

    try:

        # Analyze URL without visiting it.
        result = analyze_url(url)

        # Save scan under the logged-in user.
        scan_id = save_scan(
            g.current_user["id"],
            result["url"],
            result["risk_score"],
            result["risk_level"],
            result["indicators"],
            result.get("domain_age_days"),
            result.get("days_to_expiry"),
            result.get("rdap_status", "unknown")
        )

        return jsonify({
            "status": "success",
            "message": "URL analysis completed.",
            "scan_id": scan_id,
            "result": result
        }), 201

    except ValueError as error:

        return error_response(str(error), 400)

    except mysql.connector.Error:

        app.logger.exception("Database error during URL scan")

        return error_response(
            "Database operation failed.",
            500
        )

    except Exception:

        app.logger.exception("Unexpected error during URL scan")

        return error_response(
            "An unexpected server error occurred.",
            500
        )


# ==========================================
# PERSONAL SCAN HISTORY API
# ==========================================

@app.route("/api/scans", methods=["GET"])
@login_required
def scan_history():

    try:

        limit_value = request.args.get("limit", "100")

        try:
            limit = int(limit_value)
        except ValueError:
            return error_response("Limit must be a number.")

        if limit < 1 or limit > 500:
            return error_response(
                "Limit must be between 1 and 500."
            )

        scans = get_all_scans(
            g.current_user["id"],
            limit
        )

        return jsonify({
            "status": "success",
            "total": len(scans),
            "scans": scans
        }), 200

    except mysql.connector.Error:

        app.logger.exception("Database error while loading history")

        return error_response(
            "Could not load scan history.",
            500
        )


# ==========================================
# PERSONAL DASHBOARD STATISTICS
# ==========================================

@app.route("/api/stats", methods=["GET"])
@login_required
def dashboard_stats():

    try:

        stats = get_scan_statistics(
            g.current_user["id"]
        )

        return jsonify({
            "status": "success",
            "stats": stats
        }), 200

    except mysql.connector.Error:

        app.logger.exception("Database error while loading statistics")

        return error_response(
            "Could not load dashboard statistics.",
            500
        )


# ==========================================
# DELETE PERSONAL SCAN HISTORY
# ==========================================

@app.route("/api/scans", methods=["DELETE"])
@login_required
def clear_history():

    try:

        deleted_count = delete_all_scans(
            g.current_user["id"]
        )

        return jsonify({
            "status": "success",
            "message": "Your scan history has been cleared.",
            "deleted": deleted_count
        }), 200

    except mysql.connector.Error:

        app.logger.exception("Database error while clearing history")

        return error_response(
            "Could not clear scan history.",
            500
        )


# ==========================================
# START SERVER
# ==========================================

if __name__ == "__main__":

    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=FLASK_DEBUG
    )