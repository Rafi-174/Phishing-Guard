import json
import mysql.connector

from config import DB_CONFIG


# DATABASE CONNECTION

def get_connection():
    return mysql.connector.connect(**DB_CONFIG)


# SAVE URL SCAN

def save_scan(
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
                url,
                risk_score,
                risk_level,
                indicators,
                domain_age_days,
                days_to_expiry,
                rdap_status
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """

        values = (
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


# GET ALL SCANS

def get_all_scans(limit=100):

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
            ORDER BY scanned_at DESC, id DESC
            LIMIT %s
        """

        cursor.execute(sql, (limit,))

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


# DASHBOARD STATISTICS

def get_scan_statistics():

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
        """

        cursor.execute(sql)

        result = cursor.fetchone()

        return {
            key: int(value or 0)
            for key, value in result.items()
        }

    finally:
        if cursor is not None:
            cursor.close()

        connection.close()


# DELETE ALL SCAN HISTORY

def delete_all_scans():

    connection = get_connection()
    cursor = None

    try:
        cursor = connection.cursor()

        cursor.execute("DELETE FROM scans")

        connection.commit()

    finally:
        if cursor is not None:
            cursor.close()

        connection.close()