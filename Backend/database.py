import mysql.connector
from config import DB_CONFIG


def get_connection():
    return mysql.connector.connect(**DB_CONFIG)


def save_scan(url, risk_score, risk_level, indicators):

    connection = get_connection()

    try:
        cursor = connection.cursor()

        sql = """
            INSERT INTO scans
            (url, risk_score, risk_level, indicators)
            VALUES (%s, %s, %s, %s)
        """

        import json

        values = (
            url,
            risk_score,
            risk_level,
            json.dumps(indicators)
        )

        cursor.execute(sql, values)
        connection.commit()

        scan_id = cursor.lastrowid

        return scan_id

    finally:
        cursor.close()
        connection.close()


def get_all_scans(limit=100):

    connection = get_connection()

    try:
        cursor = connection.cursor(dictionary=True)

        sql = """
            SELECT
                id,
                url,
                risk_score,
                risk_level,
                indicators,
                scanned_at
            FROM scans
            ORDER BY scanned_at DESC, id DESC
            LIMIT %s
        """

        cursor.execute(sql, (limit,))

        results = cursor.fetchall()

        for item in results:
            if isinstance(item["indicators"], str):
                import json
                item["indicators"] = json.loads(item["indicators"])

            if item["scanned_at"]:
                item["scanned_at"] = item["scanned_at"].isoformat(
                    sep=" ",
                    timespec="seconds"
                )

        return results

    finally:
        cursor.close()
        connection.close()


def get_scan_statistics():

    connection = get_connection()

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
        cursor.close()
        connection.close()


def delete_all_scans():

    connection = get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute("DELETE FROM scans")

        connection.commit()

    finally:
        cursor.close()
        connection.close()