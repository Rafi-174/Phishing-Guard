import os

from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector

from config import FRONTEND_ORIGINS, FLASK_DEBUG
from analyzer import analyze_url
from database import (
    save_scan,
    get_all_scans,
    get_scan_statistics,
    delete_all_scans
)

app = Flask(__name__)

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": FRONTEND_ORIGINS
        }
    }
)

app.config["MAX_CONTENT_LENGTH"] = 10 * 1024


# HOME / HEALTH CHECK

@app.route("/api/health", methods=["GET"])
def health():

    return jsonify({
        "status": "success",
        "message": "PhishGuard backend is running."
    }), 200


# URL SCAN API

@app.route("/api/scan", methods=["POST"])
def scan_url():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "status": "error",
            "message": "Request body must be valid JSON."
        }), 400

    url = data.get("url")

    if not isinstance(url, str):
        return jsonify({
            "status": "error",
            "message": "Please provide a URL."
        }), 400

    try:

        # Analyze URL without visiting it.
        result = analyze_url(url)

        # Save result in MySQL.
        scan_id = save_scan(
            result["url"],
            result["risk_score"],
            result["risk_level"],
            result["indicators"]
        )

        return jsonify({
            "status": "success",
            "message": "URL analysis completed.",
            "scan_id": scan_id,
            "result": result
        }), 201

    except ValueError as error:

        return jsonify({
            "status": "error",
            "message": str(error)
        }), 400

    except mysql.connector.Error:

        app.logger.exception("Database error during URL scan")

        return jsonify({
            "status": "error",
            "message": "Database operation failed. Check the database connection."
        }), 500

    except Exception:

        app.logger.exception("Unexpected error during URL scan")

        return jsonify({
            "status": "error",
            "message": "An unexpected server error occurred."
        }), 500


# SCAN HISTORY API

@app.route("/api/scans", methods=["GET"])
def scan_history():

    try:

        limit_value = request.args.get("limit", "100")

        try:
            limit = int(limit_value)
        except ValueError:
            return jsonify({
                "status": "error",
                "message": "Limit must be a number."
            }), 400

        if limit < 1 or limit > 500:
            return jsonify({
                "status": "error",
                "message": "Limit must be between 1 and 500."
            }), 400

        scans = get_all_scans(limit)

        return jsonify({
            "status": "success",
            "total": len(scans),
            "scans": scans
        }), 200

    except mysql.connector.Error:

        app.logger.exception("Database error while loading history")

        return jsonify({
            "status": "error",
            "message": "Could not load scan history."
        }), 500


# DASHBOARD STATISTICS API

@app.route("/api/stats", methods=["GET"])
def dashboard_stats():

    try:

        stats = get_scan_statistics()

        return jsonify({
            "status": "success",
            "stats": stats
        }), 200

    except mysql.connector.Error:

        app.logger.exception("Database error while loading statistics")

        return jsonify({
            "status": "error",
            "message": "Could not load dashboard statistics."
        }), 500


# CLEAR SCAN HISTORY API

@app.route("/api/scans", methods=["DELETE"])
def clear_history():

    try:

        delete_all_scans()

        return jsonify({
            "status": "success",
            "message": "All scan history has been cleared."
        }), 200

    except mysql.connector.Error:

        app.logger.exception("Database error while clearing history")

        return jsonify({
            "status": "error",
            "message": "Could not clear scan history."
        }), 500


# START SERVER

if __name__ == "__main__":

    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=FLASK_DEBUG
    )