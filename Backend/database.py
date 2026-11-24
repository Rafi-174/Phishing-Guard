import json
import mysql.connector

from config import DB_CONFIG


# ==========================================
# DATABASE CONNECTION
# ==========================================

def get_connection():
    return mysql.connector.connect(**DB_CONFIG)


# ==========================================
# CREATE USER
# ==========================================

def create_user(name, username, email, password_hash):

    connection = get_connection()
    cursor = None

    try:
        cursor = connection.cursor()

        sql = """
            INSERT INTO users
            (name, username, email, password_hash)
            VALUES (%s, %s, %s, %s)
        """

        cursor.execute(
            sql,
            (name, username, email, password_hash)
        )

        connection.commit()
        return cursor.lastrowid

    finally:
        if cursor is not None:
            cursor.close()
        connection.close()


# ==========================================
# GET USER BY EMAIL
# ==========================================

def get_user_by_email(email):

    connection = get_connection()
    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)

        sql = """
            SELECT
                id, name, username, email,
                password_hash, created_at
            FROM users
            WHERE LOWER(email) = LOWER(%s)
            LIMIT 1
        """

        cursor.execute(sql, (email,))
        return cursor.fetchone()

    finally:
        if cursor is not None:
            cursor.close()
        connection.close()


# ==========================================
# GET USER BY USERNAME OR EMAIL
# ==========================================

def get_user_by_identifier(identifier):

    connection = get_connection()
    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)

        sql = """
            SELECT
                id, name, username, email,
                password_hash, created_at
            FROM users
            WHERE LOWER(username) = LOWER(%s)
               OR LOWER(email) = LOWER(%s)
            LIMIT 1
        """

        cursor.execute(
            sql,
            (identifier, identifier)
        )

        return cursor.fetchone()

    finally:
        if cursor is not None:
            cursor.close()
        connection.close()


# ==========================================
# CHECK USERNAME EXISTS
# ==========================================

def username_exists(username):

    connection = get_connection()
    cursor = None

    try:
        cursor = connection.cursor()

        sql = """
            SELECT id
            FROM users
            WHERE LOWER(username) = LOWER(%s)
            LIMIT 1
        """

        cursor.execute(sql, (username,))
        return cursor.fetchone() is not None

    finally:
        if cursor is not None:
            cursor.close()
        connection.close()


# ==========================================
# GET USER BY ID
# ==========================================

def get_user_by_id(user_id):

    connection = get_connection()
    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)

        sql = """
            SELECT id, name, username, email, created_at
            FROM users
            WHERE id = %s
            LIMIT 1
        """

        cursor.execute(sql, (user_id,))
        return cursor.fetchone()

    finally:
        if cursor is not None:
            cursor.close()
        connection.close()


# ==========================================
# CREATE PASSWORD RESET OTP
# ==========================================

def create_password_reset_otp(
    user_id,
    otp_hash,
    expires_at
):

    connection = get_connection()
    cursor = None

    try:
        cursor = connection.cursor()

        # Invalidate previous unused OTPs
        cursor.execute(
            """
            UPDATE password_reset_otps
            SET used_at = UTC_TIMESTAMP()
            WHERE user_id = %s
              AND used_at IS NULL
            """,
            (user_id,)
        )

        sql = """
            INSERT INTO password_reset_otps
            (
                user_id,
                otp_hash,
                expires_at,
                attempts
            )
            VALUES (%s, %s, %s, 0)
        """

        cursor.execute(
            sql,
            (user_id, otp_hash, expires_at)
        )

        connection.commit()
        return cursor.lastrowid

    except Exception:
        connection.rollback()
        raise

    finally:
        if cursor is not None:
            cursor.close()
        connection.close()


# ==========================================
# GET VALID PASSWORD RESET OTP
# ==========================================

def get_valid_password_reset_otp(user_id):

    connection = get_connection()
    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)

        sql = """
            SELECT
                id,
                user_id,
                otp_hash,
                expires_at,
                attempts
            FROM password_reset_otps
            WHERE user_id = %s
              AND used_at IS NULL
              AND expires_at > UTC_TIMESTAMP()
              AND attempts < 5
            ORDER BY created_at DESC, id DESC
            LIMIT 1
        """

        cursor.execute(sql, (user_id,))
        return cursor.fetchone()

    finally:
        if cursor is not None:
            cursor.close()
        connection.close()


# ==========================================
# INCREMENT OTP ATTEMPTS
# ==========================================

def increment_otp_attempts(otp_id):

    connection = get_connection()
    cursor = None

    try:
        cursor = connection.cursor()

        sql = """
            UPDATE password_reset_otps
            SET attempts = attempts + 1
            WHERE id = %s
              AND used_at IS NULL
              AND expires_at > UTC_TIMESTAMP()
              AND attempts < 5
        """

        cursor.execute(sql, (otp_id,))
        connection.commit()

        return cursor.rowcount > 0

    finally:
        if cursor is not None:
            cursor.close()
        connection.close()


# ==========================================
# RESET PASSWORD AND CONSUME OTP
# ==========================================

def reset_password_with_otp(
    user_id,
    otp_id,
    new_password_hash
):

    connection = get_connection()
    cursor = None

    try:
        cursor = connection.cursor()

        # Confirm OTP is still valid
        cursor.execute(
            """
            SELECT id
            FROM password_reset_otps
            WHERE id = %s
              AND user_id = %s
              AND used_at IS NULL
              AND expires_at > UTC_TIMESTAMP()
              AND attempts < 5
            FOR UPDATE
            """,
            (otp_id, user_id)
        )

        otp_record = cursor.fetchone()

        if not otp_record:
            connection.rollback()
            return False

        # Update password
        cursor.execute(
            """
            UPDATE users
            SET password_hash = %s
            WHERE id = %s
            """,
            (new_password_hash, user_id)
        )

        if cursor.rowcount != 1:
            connection.rollback()
            return False

        # Consume this OTP
        cursor.execute(
            """
            UPDATE password_reset_otps
            SET used_at = UTC_TIMESTAMP()
            WHERE id = %s
            """,
            (otp_id,)
        )

        # Invalidate every other OTP for this user
        cursor.execute(
            """
            UPDATE password_reset_otps
            SET used_at = UTC_TIMESTAMP()
            WHERE user_id = %s
              AND used_at IS NULL
            """,
            (user_id,)
        )

        connection.commit()
        return True

    except Exception:
        connection.rollback()
        raise

    finally:
        if cursor is not None:
            cursor.close()
        connection.close()


# ==========================================
# SAVE URL SCAN FOR A USER
# ==========================================

def save_scan(
    user_id,
    url,
    risk_score,
    risk_level,
    indicators,
    domain_age_days=None,
    days_to_expiry=None,
    rdap_status="unknown"
):

    connection = get_connection()
    cursor = None

    try:
        cursor = connection.cursor()

        sql = """
            INSERT INTO scans
            (
                user_id,
                url,
                risk_score,
                risk_level,
                indicators,
                domain_age_days,
                days_to_expiry,
                rdap_status
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """

        values = (
            user_id,
            url,
            risk_score,
            risk_level,
            json.dumps(indicators),
            domain_age_days,
            days_to_expiry,
            rdap_status
        )

        cursor.execute(sql, values)
        connection.commit()

        return cursor.lastrowid

    finally:
        if cursor is not None:
            cursor.close()
        connection.close()


# ==========================================
# GET PERSONAL SCAN HISTORY
# ==========================================

def get_all_scans(user_id, limit=100):

    connection = get_connection()
    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)

        sql = """
            SELECT
                id,
                url,
                risk_score,
                risk_level,
                indicators,
                domain_age_days,
                days_to_expiry,
                rdap_status,
                scanned_at
            FROM scans
            WHERE user_id = %s
            ORDER BY scanned_at DESC, id DESC
            LIMIT %s
        """

        cursor.execute(sql, (user_id, limit))

        results = cursor.fetchall()

        for item in results:

            if isinstance(item["indicators"], str):
                item["indicators"] = json.loads(
                    item["indicators"]
                )

            if item["scanned_at"]:
                item["scanned_at"] = item["scanned_at"].isoformat(
                    sep=" ",
                    timespec="seconds"
                )

        return results

    finally:
        if cursor is not None:
            cursor.close()
        connection.close()


# ==========================================
# PERSONAL DASHBOARD STATISTICS
# ==========================================

def get_scan_statistics(user_id):

    connection = get_connection()
    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)

        sql = """
            SELECT
                COUNT(*) AS total_scans,

                SUM(
                    CASE WHEN risk_level = 'High Risk'
                    THEN 1 ELSE 0 END
                ) AS high_risk,

                SUM(
                    CASE WHEN risk_level = 'Suspicious'
                    THEN 1 ELSE 0 END
                ) AS suspicious,

                SUM(
                    CASE WHEN risk_level = 'Low Risk'
                    THEN 1 ELSE 0 END
                ) AS low_risk

            FROM scans
            WHERE user_id = %s
        """

        cursor.execute(sql, (user_id,))
        result = cursor.fetchone()

        return {
            key: int(value or 0)
            for key, value in result.items()
        }

    finally:
        if cursor is not None:
            cursor.close()
        connection.close()


# ==========================================
# DELETE PERSONAL SCAN HISTORY
# ==========================================

def delete_all_scans(user_id):

    connection = get_connection()
    cursor = None

    try:
        cursor = connection.cursor()

        sql = """
            DELETE FROM scans
            WHERE user_id = %s
        """

        cursor.execute(sql, (user_id,))
        connection.commit()

        return cursor.rowcount

    finally:
        if cursor is not None:
            cursor.close()
        connection.close()