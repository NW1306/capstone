import os
import io
import csv
import json
import uuid
import random
import logging
import traceback
from datetime import datetime, timedelta

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, g, jsonify, send_file
)
from werkzeug.utils import secure_filename

from config import Config
from models import db, Report, Incident
from modules import email_analyzer, report_parser
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from collections import defaultdict


# =========================================================
# APP SETUP
# =========================================================

load_dotenv()

app = Flask(__name__)
app.config.from_object(Config)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")

db.init_app(app)

logging.basicConfig(level=logging.DEBUG)

DATABASE_URL = os.getenv("DATABASE_URL")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

ALLOWED_EXTENSIONS = {"eml", "txt", "xml"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

if not DATABASE_URL:
    raise ValueError("DATABASE_URL is not set. Check your .env file.")

# =========================================================
# DATABASE HELPERS
# =========================================================

def get_db():
    """Get PostgreSQL connection stored in Flask's g."""
    conn = getattr(g, "_database", None)
    if conn is None:
        try:
            conn = g._database = psycopg2.connect(
                DATABASE_URL,
                cursor_factory=psycopg2.extras.RealDictCursor
            )
            print("Connected to PostgreSQL database")
        except Exception as e:
            print(f"Database connection error: {e}")
            return None
    return conn


def execute_query(query, params=None, fetchone=False, fetchall=False, commit=False):
    """Reusable DB query helper."""
    conn = get_db()
    if not conn:
        raise Exception("Database connection not available")

    cur = conn.cursor()
    cur.execute(query, params or ())

    result = None
    if fetchone:
        result = cur.fetchone()
    elif fetchall:
        result = cur.fetchall()

    if commit:
        conn.commit()

    cur.close()
    return result


def init_db():
    """Initialize required PostgreSQL tables."""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                from_domain TEXT,
                verdict TEXT,
                threat_score INTEGER,
                details JSONB
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                severity TEXT NOT NULL,
                domain TEXT,
                source_ip TEXT,
                title TEXT NOT NULL,
                message TEXT,
                status TEXT DEFAULT 'open'
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                org_name TEXT,
                domain TEXT,
                total_emails INTEGER
            )
        """)

        conn.commit()
        cur.close()
        conn.close()

        print("PostgreSQL database initialization complete")
        return True

    except Exception as e:
        print(f"Database initialization error: {e}")
        traceback.print_exc()
        return False


@app.teardown_appcontext
def close_connection(exception):
    conn = getattr(g, "_database", None)
    if conn is not None:
        conn.close()


with app.app_context():
    init_db()

# =========================================================
# COMMON HELPERS
# =========================================================

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def save_uploaded_file(file_obj):
    """Save uploaded file with unique name and return metadata."""
    original_name = secure_filename(file_obj.filename)
    unique_name = f"{uuid.uuid4()}_{original_name}"
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], unique_name)
    file_obj.save(filepath)

    with open(filepath, "rb") as f:
        file_bytes = f.read()

    return {
        "original_name": original_name,
        "saved_name": unique_name,
        "filepath": filepath,
        "bytes": file_bytes
    }


def calculate_threat_score(verdict):
    verdict = (verdict or "").lower()
    scores = {
        "pass": 0,
        "legitimate": 0,
        "neutral": 20,
        "softfail": 60,
        "suspicious": 50,
        "none": 70,
        "fail": 80,
        "spoofed": 90
    }
    return scores.get(verdict, 40)


def risk_level(score):
    if score < 20:
        return "Low"
    elif score < 50:
        return "Medium"
    return "High"


def normalize_email_result(result):
    """Convert analyzer output into consistent internal format."""
    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "from_domain": result.get("from_domain", "unknown"),
        "verdict": result.get("verdict", "unknown").lower(),
        "source_ip": result.get("sending_ip", "unknown"),
        "details": json.dumps(result)
    }


def create_incident(timestamp, severity, domain, source_ip, message):
    """Centralized incident creation."""
    execute_query("""
        INSERT INTO incidents (timestamp, severity, domain, source_ip, title, message, status)
        VALUES (%s, %s, %s, %s, %s, %s, 'open')
    """, (
        timestamp,
        severity,
        domain,
        source_ip,
        "DMARC anomaly detected",
        message
    ), commit=True)


def process_scan_result(scan_data):
    """Store scan result and create incident if risky."""
    verdict = (scan_data.get("verdict") or "").lower()
    threat_score = calculate_threat_score(verdict)

    execute_query("""
        INSERT INTO scans (timestamp, from_domain, verdict, threat_score, details)
        VALUES (%s, %s, %s, %s, %s)
    """, (
        scan_data["timestamp"],
        scan_data["from_domain"],
        scan_data["verdict"],
        threat_score,
        scan_data["details"]
    ), commit=True)

    risky_verdicts = {"fail", "softfail", "none", "suspicious", "spoofed"}
    if verdict in risky_verdicts:
        severity = "high" if verdict in {"fail", "spoofed"} else "medium"
        create_incident(
            timestamp=scan_data["timestamp"],
            severity=severity,
            domain=scan_data["from_domain"],
            source_ip=scan_data.get("source_ip", "unknown"),
            message=f"Verdict={scan_data['verdict']} for {scan_data['from_domain']}"
        )

# =========================================================
# ERROR HANDLER
# =========================================================

@app.errorhandler(Exception)
def handle_exception(e):
    print("=" * 60)
    print(f"ERROR: {type(e).__name__}")
    print(f"Message: {str(e)}")
    print("Traceback:")
    traceback.print_exc()
    print("=" * 60)

    return f"""
    <html>
        <head><title>Error Details</title></head>
        <body style="font-family: Arial; padding: 20px;">
            <h1 style="color: red;">Error: {type(e).__name__}</h1>
            <p style="background: #ffeeee; padding: 10px; border-radius: 5px;">{str(e)}</p>
            <h2>Traceback:</h2>
            <pre style="background: #f5f5f5; padding: 10px; overflow: auto;">{traceback.format_exc()}</pre>
            <br>
            <a href="/" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">← Back to Home</a>
        </body>
    </html>
    """, 500

# =========================================================
# PAGE ROUTES
# =========================================================

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/healthz")
def health():
    return "OK"


@app.route("/dashboard")
def dashboard():
    try:
        rows = execute_query("""
            SELECT id, timestamp, from_domain, verdict, threat_score, details
            FROM scans
            ORDER BY id DESC
            LIMIT 20
        """, fetchall=True)

        total_scans_row = execute_query(
            "SELECT COUNT(*) AS total FROM scans",
            fetchone=True
        )
        pass_count_row = execute_query("""
            SELECT COUNT(*) AS pass_count
            FROM scans
            WHERE LOWER(verdict) IN ('pass', 'legitimate')
        """, fetchone=True)
        fail_count_row = execute_query("""
            SELECT COUNT(*) AS fail_count
            FROM scans
            WHERE LOWER(verdict) IN ('fail', 'softfail', 'none', 'suspicious', 'spoofed')
        """, fetchone=True)

        return render_template(
            "dashboard.html",
            total_scans=total_scans_row["total"],
            pass_count=pass_count_row["pass_count"],
            fail_count=fail_count_row["fail_count"],
            scans=rows
        )
    except Exception as e:
        traceback.print_exc()
        return f"Dashboard error: {e}", 500


# 1. Classification Chart
@app.route("/api/chart/severity")
def chart_severity():
    query = text("""
        SELECT severity, COUNT(*) AS total
        FROM incidents
        GROUP BY severity
    """)
    rows = db.session.execute(query).fetchall()

    counts = {
        "Legitimate": 0,
        "Suspicious": 0,
        "Spoofed": 0
    }

    for row in rows:
        label = row[0] if row[0] else "Unknown"
        if label in counts:
            counts[label] = row[1]

    return jsonify({
        "labels": list(counts.keys()),
        "values": list(counts.values())
    })


# 2. Incident Trend Chart
@app.route("/api/chart/trends")
def chart_trends():
    query = text("""
        SELECT DATE(timestamp) AS day, COUNT(*) AS total
        FROM incidents
        GROUP BY DATE(timestamp)
        ORDER BY day ASC
    """)
    rows = db.session.execute(query).fetchall()

    labels = [str(row[0]) for row in rows]
    values = [row[1] for row in rows]

    return jsonify({
        "labels": labels,
        "values": values
    })


# 3. Authentication Failures Chart
@app.route("/api/chart/auth-failures")
def chart_auth_failures():
    try:
        query = text("""
            SELECT
                SUM(CASE WHEN LOWER(verdict) = 'fail' THEN 1 ELSE 0 END) AS fail_count,
                SUM(CASE WHEN LOWER(verdict) = 'softfail' THEN 1 ELSE 0 END) AS softfail_count,
                SUM(CASE WHEN LOWER(verdict) = 'none' THEN 1 ELSE 0 END) AS none_count
            FROM scans
        """)
        row = db.session.execute(query).fetchone()

        return jsonify({
            "labels": ["Fail", "Softfail", "None"],
            "values": [
                row[0] or 0,
                row[1] or 0,
                row[2] or 0
            ]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 4. Top Sender Domains Chart
@app.route("/api/chart/top-domains")
def chart_top_domains():
    try:
        query = text("""
            SELECT domain, COUNT(*) AS total
            FROM incidents
            WHERE domain IS NOT NULL AND domain <> ''
            GROUP BY domain
            ORDER BY total DESC
            LIMIT 7
        """)
        rows = db.session.execute(query).fetchall()

        return jsonify({
            "labels": [row[0] for row in rows],
            "values": [row[1] for row in rows]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 5. Top Source IPs Chart

@app.route("/api/chart/top-ips")
def chart_top_ips():
    try:
        query = text("""
            SELECT source_ip, COUNT(*) AS total
            FROM incidents
            WHERE source_ip IS NOT NULL AND source_ip <> ''
            GROUP BY source_ip
            ORDER BY total DESC
            LIMIT 7
        """)
        rows = db.session.execute(query).fetchall()

        return jsonify({
            "labels": [row[0] for row in rows],
            "values": [row[1] for row in rows]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/domain", methods=["GET", "POST"])
def domain_lookup():
    try:
        if request.method == "POST":
            domain = request.form["domain"].strip()
            if not domain:
                flash("Please enter a domain")
                return redirect(url_for("domain_lookup"))

            dmarc_record = email_analyzer.get_dmarc_record(domain)
            dmarc_policy = email_analyzer.parse_dmarc(dmarc_record)
            spf_record = email_analyzer.get_spf_record(domain)

            return render_template(
                "domain.html",
                domain=domain,
                dmarc_record=dmarc_record,
                dmarc_policy=dmarc_policy,
                spf_record=spf_record
            )

        return render_template("domain.html")
    except Exception as e:
        flash(f"Error: {str(e)}")
        return redirect(url_for("index"))

# =========================================================
# ANALYZE EMAIL ROUTES
# =========================================================

@app.route("/analyze", methods=["POST"])
def analyze():
    """Analyze uploaded email file."""
    try:
        if "email_file" not in request.files:
            flash("No file part")
            return redirect(url_for("index"))

        file = request.files["email_file"]
        if file.filename == "":
            flash("No selected file")
            return redirect(url_for("index"))

        if not (file and allowed_file(file.filename)):
            flash("File type not allowed (use .eml, .txt, or .xml)")
            return redirect(url_for("index"))

        saved = save_uploaded_file(file)

        print(f"Original uploaded filename: {saved['original_name']}")
        print(f"Saved as: {saved['filepath']}")
        print(f"Read {len(saved['bytes'])} bytes from uploaded file")

        result = email_analyzer.analyze_email(saved["bytes"])
        result["uploaded_filename"] = saved["original_name"]
        result["saved_filename"] = saved["saved_name"]

        if "error" in result:
            flash(result["error"])
            return redirect(url_for("index"))

        normalized_result = normalize_email_result(result)
        process_scan_result(normalized_result)

        print("Scan processed and stored successfully")
        return render_template("result.html", result=result)

    except Exception as e:
        print(f"Error in analyze route: {e}")
        traceback.print_exc()
        flash(f"Error: {str(e)}")
        return redirect(url_for("index"))


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """API endpoint for real-time email analysis."""
    try:
        import base64

        if "email" in request.files:
            file = request.files["email"]
            email_bytes = file.read()
        elif request.is_json and "email" in request.json:
            email_bytes = base64.b64decode(request.json["email"])
        else:
            return jsonify({"error": "No email provided"}), 400

        result = email_analyzer.analyze_email(email_bytes)

        if "error" in result:
            return jsonify({"error": result["error"]}), 400

        normalized_result = normalize_email_result(result)
        process_scan_result(normalized_result)

        return jsonify({
            "success": True,
            "verdict": result.get("verdict"),
            "details": {
                "from_domain": result.get("from_domain"),
                "spf_pass": result.get("spf_pass"),
                "dkim_pass": result.get("dkim_pass"),
                "dmarc_policy": result.get("dmarc_policy"),
                "spf_aligned": result.get("spf_aligned"),
                "dkim_aligned": result.get("dkim_aligned"),
                "reason": result.get("reason")
            }
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# =========================================================
# REPORT UPLOAD ROUTE
# =========================================================

@app.route("/upload_report", methods=["POST"])
def upload_report():
    """Upload and parse DMARC XML report."""
    try:
        if "report_file" not in request.files:
            flash("No file part")
            return redirect(url_for("index"))

        file = request.files["report_file"]
        if file.filename == "":
            flash("No selected file")
            return redirect(url_for("index"))

        if not (file and allowed_file(file.filename)):
            flash("File type not allowed (use .xml)")
            return redirect(url_for("index"))

        saved = save_uploaded_file(file)
        parsed = report_parser.parse_dmarc_report(saved["bytes"])

        if "error" in parsed:
            flash(parsed["error"])
            return redirect(url_for("index"))

        execute_query("""
            INSERT INTO reports (org_name, domain, total_emails)
            VALUES (%s, %s, %s)
        """, (
            parsed.get("org_name"),
            parsed.get("domain"),
            parsed.get("total_emails", 0)
        ), commit=True)

        print("Report saved to database")
        return render_template("report.html", report=parsed)

    except Exception as e:
        traceback.print_exc()
        flash(f"Error: {str(e)}")
        return redirect(url_for("index"))

# =========================================================
# INCIDENT API ROUTES
# =========================================================

@app.route("/api/incidents")
def api_incidents():
    try:
        incidents = Incident.query.order_by(Incident.timestamp.desc()).all()

        data = []
        for i in incidents:
            data.append({
                "id": i.id,
                "severity": (i.severity or "").capitalize(),
                "domain": i.domain,
                "source_ip": i.source_ip,
                "title": i.title,
                "message": i.message,
                "detected": i.timestamp.strftime("%Y-%m-%d %H:%M") if i.timestamp else "N/A",
                "status": (i.status or "").capitalize()
            })

        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/incidents/count")
def api_incidents_count():
    try:
        count = Incident.query.filter(Incident.status.ilike("Open")).count()
        return jsonify({"count": count})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/incidents/<int:id>/resolve", methods=["POST"])
def resolve_incident(id):
    try:
        incident = Incident.query.get(id)
        if not incident:
            return jsonify({"error": "Incident not found"}), 404

        incident.status = "Resolved"
        db.session.commit()

        return jsonify({"success": True, "message": "Incident resolved"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =========================================================
# STATS + DASHBOARD API ROUTES
# =========================================================

@app.route("/api/stats")
def api_stats():
    try:
        stats = {
            "total_scans": execute_query(
                "SELECT COUNT(*) AS count FROM scans",
                fetchone=True
            )["count"],
            "legitimate": execute_query(
                "SELECT COUNT(*) AS count FROM scans WHERE LOWER(verdict)='legitimate'",
                fetchone=True
            )["count"],
            "suspicious": execute_query(
                "SELECT COUNT(*) AS count FROM scans WHERE LOWER(verdict)='suspicious'",
                fetchone=True
            )["count"],
            "spoofed": execute_query(
                "SELECT COUNT(*) AS count FROM scans WHERE LOWER(verdict)='spoofed'",
                fetchone=True
            )["count"]
        }

        recent = execute_query(
            "SELECT * FROM scans ORDER BY timestamp DESC LIMIT 10",
            fetchall=True
        )

        stats["recent_scans"] = [
            {
                "timestamp": scan["timestamp"],
                "from_domain": scan["from_domain"],
                "verdict": scan["verdict"]
            }
            for scan in recent
        ]

        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/stats/summary")
def api_stats_summary():
    try:
        reports = Report.query.all()
        incidents = Incident.query.all()

        total_reports = len(reports)
        total_domains = len(set(r.domain for r in reports if r.domain))
        total_emails = sum((r.total_emails or 0) for r in reports)
        active_alerts = sum(1 for i in incidents if (i.status or "").lower() == "open")

        return jsonify({
            "domains": total_domains,
            "reports": total_reports,
            "emails": total_emails,
            "active_alerts": active_alerts,
            "pass_rate": 0,
            "total_domains": total_domains,
            "total_reports": total_reports,
            "total_emails": total_emails,
            "alerts": active_alerts
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/stats/timeline")
def api_timeline():
    reports = Report.query.all()

    data = {}
    for r in reports:
        date = r.timestamp.date() if r.timestamp else None
        if not date:
            continue

        if date not in data:
            data[date] = {"passed": 0, "failed": 0}

        if (r.pass_rate or 0) > 0:
            data[date]["passed"] += r.total_emails or 0
        else:
            data[date]["failed"] += r.total_emails or 0

    result = [
        {"date": str(d), "passed": v["passed"], "failed": v["failed"]}
        for d, v in sorted(data.items())
    ]

    return jsonify(result)


@app.route("/api/charts/timeline")
def api_charts_timeline():
    try:
        return jsonify([
            {"date": "2026-03-20", "count": 5},
            {"date": "2026-03-21", "count": 3}
        ])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/recent-reports")
def recent_reports():
    try:
        rows = execute_query("""
            SELECT
                from_domain AS domain,
                MAX(timestamp) AS latest_time,
                COUNT(*) AS records,
                ROUND(
                    100.0 * SUM(CASE WHEN LOWER(verdict) IN ('pass', 'legitimate') THEN 1 ELSE 0 END) / COUNT(*),
                    2
                ) AS pass_rate
            FROM scans
            WHERE from_domain IS NOT NULL AND TRIM(from_domain) != ''
            GROUP BY from_domain
            ORDER BY latest_time DESC
            LIMIT 10
        """, fetchall=True)

        data = []
        for r in rows:
            data.append({
                "domain": r["domain"],
                "date": r["latest_time"].strftime("%Y-%m-%d %H:%M") if r["latest_time"] else "N/A",
                "records": r["records"] or 0,
                "pass_rate": r["pass_rate"] or 0
            })

        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/reports")
def api_reports():
    try:
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 5, type=int)

        pagination = Report.query.order_by(Report.timestamp.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )

        rows = []
        for r in pagination.items:
            rows.append({
                "domain": r.domain,
                "date": r.timestamp.strftime("%Y-%m-%d %H:%M") if r.timestamp else "N/A",
                "records": r.total_emails or 0,
                "pass_rate": 0
            })

        return jsonify({
            "reports": rows,
            "total": pagination.total,
            "pages": pagination.pages,
            "current_page": page
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =========================================================
# DOMAIN / ALERT API ROUTES
# =========================================================

@app.route("/api/risky-domains")
def api_risky_domains():
    try:
        rows = execute_query("""
            SELECT
                from_domain AS domain,
                COUNT(*) AS total,
                SUM(CASE WHEN LOWER(verdict) IN ('pass', 'legitimate') THEN 1 ELSE 0 END) AS pass_count,
                SUM(CASE WHEN LOWER(verdict) IN ('fail', 'softfail', 'none', 'neutral', 'spoofed', 'suspicious') THEN 1 ELSE 0 END) AS risky_count,
                (
                    SUM(CASE WHEN LOWER(verdict) IN ('spoofed', 'fail') THEN 3 ELSE 0 END) +
                    SUM(CASE WHEN LOWER(verdict) IN ('softfail', 'suspicious') THEN 2 ELSE 0 END) +
                    SUM(CASE WHEN LOWER(verdict) IN ('none', 'neutral') THEN 1 ELSE 0 END)
                ) AS risk_score
            FROM scans
            WHERE from_domain IS NOT NULL AND TRIM(from_domain) != ''
            GROUP BY from_domain
            ORDER BY risk_score DESC, risky_count DESC, total DESC
            LIMIT 10
        """, fetchall=True)

        data = []
        for r in rows:
            total = r["total"] or 0
            pass_rate = round((r["pass_count"] or 0) * 100 / total, 2) if total else 0

            data.append({
                "domain": r["domain"],
                "total": total,
                "risky": r["risky_count"] or 0,
                "risk_score": r["risk_score"] or 0,
                "pass_rate": pass_rate
            })

        return jsonify({"domains": data})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/domains")
def api_domains():
    try:
        rows = execute_query("""
            SELECT
                from_domain AS domain,
                COUNT(*) AS email_count,
                ROUND(
                    100.0 * SUM(
                        CASE
                            WHEN LOWER(verdict) IN ('pass', 'legitimate') THEN 1
                            ELSE 0
                        END
                    ) / COUNT(*),
                    2
                ) AS pass_rate
            FROM scans
            WHERE from_domain IS NOT NULL AND TRIM(from_domain) != ''
            GROUP BY from_domain
            ORDER BY email_count DESC
            LIMIT 10
        """, fetchall=True)

        return jsonify({"domains": [dict(r) for r in rows]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/alerts")
def api_alerts():
    try:
        rows = execute_query("""
            SELECT from_domain, verdict, timestamp
            FROM scans
            WHERE LOWER(verdict) IN ('fail', 'softfail', 'none', 'neutral', 'spoofed', 'suspicious')
            ORDER BY timestamp DESC
            LIMIT 10
        """, fetchall=True)

        alerts = []
        for r in rows:
            v = (r["verdict"] or "").lower()

            if v in ("fail", "spoofed"):
                severity = "high"
            elif v in ("softfail", "suspicious"):
                severity = "medium"
            else:
                severity = "low"

            alerts.append({
                "severity": severity,
                "domain": r["from_domain"],
                "source_ip": "unknown",
                "message": f"DMARC issue detected ({r['verdict']})",
                "detected": r["timestamp"]
            })

        return jsonify(alerts)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =========================================================
# EXPORT ROUTES
# =========================================================

@app.route("/export/csv")
def export_csv_route():
    """Export scans as CSV."""
    try:
        scans = execute_query(
            "SELECT * FROM scans ORDER BY timestamp DESC",
            fetchall=True
        )

        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(["ID", "Timestamp", "From Domain", "Verdict", "Details"])

        for scan in scans:
            writer.writerow([
                scan["id"],
                scan["timestamp"],
                scan["from_domain"],
                scan["verdict"],
                scan["details"]
            ])

        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode("utf-8")),
            mimetype="text/csv",
            download_name="dmarc_scans.csv",
            as_attachment=True
        )
    except Exception as e:
        return f"Export error: {str(e)}"


@app.route("/export/json")
def export_json_route():
    """Export scans as JSON."""
    try:
        scans = execute_query(
            "SELECT * FROM scans ORDER BY timestamp DESC",
            fetchall=True
        )

        data = []
        for scan in scans:
            try:
                details = json.loads(scan["details"]) if scan["details"] else {}
            except Exception:
                details = {}

            data.append({
                "id": scan["id"],
                "timestamp": scan["timestamp"],
                "from_domain": scan["from_domain"],
                "verdict": scan["verdict"],
                "details": details
            })

        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)})

# =========================================================
# DEV SEED ROUTE
# =========================================================

@app.route("/dev/seed")
def dev_seed():
    try:
        conn = get_db()
        cur = conn.cursor()

        domains = [
            "example.com",
            "amazon.com",
            "google.com",
            "microsoft.com",
            "bank-secure.com",
            "paypal.com"
        ]
        verdicts = ["pass", "pass", "pass", "softfail", "fail", "none"]

        for _ in range(80):
            domain = random.choice(domains)
            verdict = random.choice(verdicts)

            ts = datetime.now() - timedelta(
                days=random.randint(0, 29),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59)
            )

            details = json.dumps({
                "dmarc": verdict,
                "spf": random.choice(["pass", "fail", "softfail"]),
                "dkim": random.choice(["pass", "fail"]),
                "seed": True
            })

            threat_score = calculate_threat_score(verdict)

            cur.execute("""
                INSERT INTO scans (timestamp, from_domain, verdict, threat_score, details)
                VALUES (%s, %s, %s, %s, %s)
            """, (ts, domain, verdict, threat_score, details))

            if verdict in {"fail", "softfail", "none"}:
                severity = "high" if verdict == "fail" else "medium"
                cur.execute("""
                    INSERT INTO incidents (timestamp, severity, domain, source_ip, title, message, status)
                    VALUES (%s, %s, %s, %s, %s, %s, 'open')
                """, (
                    ts,
                    severity,
                    domain,
                    f"203.0.113.{random.randint(1, 254)}",
                    "DMARC anomaly detected",
                    f"Verdict={verdict}. Check SPF/DKIM alignment and DMARC policy."
                ))

        for _ in range(12):
            domain = random.choice(domains)
            ts = datetime.now() - timedelta(days=random.randint(0, 29))

            cur.execute("""
                INSERT INTO reports (timestamp, org_name, domain, total_emails)
                VALUES (%s, %s, %s, %s)
            """, (ts, "DemoOrg", domain, random.randint(50, 600)))

        conn.commit()
        cur.close()

        return "Seeded demo data for scans + reports (+ incidents). Refresh /dashboard"
    except Exception as e:
        traceback.print_exc()
        return f"Seed error: {e}", 500

# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":
    print(app.url_map)
    app.run(host="127.0.0.1", port=5000, debug=True)