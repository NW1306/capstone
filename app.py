import os
import psycopg2
import psycopg2.extras
import traceback
from flask import g
import traceback
import logging
import csv
import json
import io
from flask import Flask, render_template, request, redirect, url_for, flash, g, jsonify, send_file
from werkzeug.utils import secure_filename
from modules import email_analyzer, report_parser
from dotenv import load_dotenv
from config import Config

load_dotenv()

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

app.config.from_object(Config)
# Security
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key")

# Upload configuration
DATABASE_URL = os.environ.get("DATABASE_URL")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

ALLOWED_EXTENSIONS = {'eml', 'txt', 'xml'}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Database setup

DATABASE_URL = os.getenv("DATABASE_URL")
print("USING DATABASE_URL:", DATABASE_URL)
if not DATABASE_URL:
    raise ValueError("DATABASE_URL is not set. Check your .env file.")


def get_db():
    """Get PostgreSQL database connection."""
    db = getattr(g, '_database', None)
    if db is None:
        try:
            db = g._database = psycopg2.connect(
                DATABASE_URL,
                cursor_factory=psycopg2.extras.RealDictCursor
            )
            print("Connected to PostgreSQL database")
        except Exception as e:
            print(f"Database connection error: {e}")
            return None
    return db


def init_db():
    """Initialize PostgreSQL tables."""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                from_domain TEXT,
                verdict TEXT,
                threat_score INTEGER,
                details JSONB
            )
        """)

        cursor.execute("""
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

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                org_name TEXT,
                domain TEXT,
                total_emails INTEGER
            )
        """)

        conn.commit()
        cursor.close()
        conn.close()

        print("PostgreSQL database initialization complete")
        return True

    except Exception as e:
        print(f"Database initialization error: {e}")
        traceback.print_exc()
        return False


@app.teardown_appcontext
def close_connection(exception):
    """Close database connection"""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


with app.app_context():
    init_db()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Error handler
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

import json
from datetime import datetime

def normalize_email_result(result):
    """Convert analyzer output into a consistent internal format."""
    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "from_domain": result.get("from_domain", "unknown"),
        "verdict": result.get("verdict", "unknown").lower(),
        "source_ip": result.get("sending_ip", "unknown"),
        "details": json.dumps(result)
    }

def process_scan_result(scan_data):
    """Store normalized scan result and create incident if risky."""
    db = get_db()
    if not db:
        raise Exception("Database connection not available")

    cur = db.cursor()

    # Simple threat score mapping
    verdict = scan_data["verdict"].lower()
    threat_score_map = {
        "pass": 0,
        "legitimate": 0,
        "neutral": 20,
        "suspicious": 50,
        "softfail": 60,
        "none": 70,
        "fail": 80,
        "spoofed": 90
    }
    threat_score = threat_score_map.get(verdict, 40)

    # Save scan
    cur.execute("""
        INSERT INTO scans (timestamp, from_domain, verdict, threat_score, details)
        VALUES (%s, %s, %s, %s, %s)
    """, (
        scan_data["timestamp"],
        scan_data["from_domain"],
        scan_data["verdict"],
        threat_score,
        scan_data["details"]
    ))

    # Create incident only for risky verdicts
    risky_verdicts = ["fail", "softfail", "none", "suspicious", "spoofed"]
    if verdict in risky_verdicts:
        severity = "high" if verdict in ["fail", "spoofed"] else "medium"

        try:
            cur.execute("""
                INSERT INTO incidents (timestamp, severity, domain, source_ip, title, message, status)
                VALUES (%s, %s, %s, %s, %s, %s, 'open')
            """, (
                scan_data["timestamp"],
                severity,
                scan_data["from_domain"],
                scan_data.get("source_ip", "unknown"),
                "DMARC anomaly detected",
                f"Verdict={scan_data['verdict']} for {scan_data['from_domain']}"
            ))
        except Exception as e:
            print(f"Incident creation skipped/error: {e}")

    db.commit()
    cur.close()
# ==================== ROUTES ====================

@app.route('/')
def index():
    """Home page"""
    try:
        return render_template('index.html')
    except Exception as e:
        return f"Error loading template: {e}"

@app.route("/api/incidents/<int:incident_id>/ack", methods=["POST"])
def ack_incident(incident_id):
    db = get_db()
    cur = db.cursor()

    cur.execute(
        "UPDATE incidents SET status='ack' WHERE id=%s",
        (incident_id,)
    )

    db.commit()
    cur.close()

    return jsonify({"ok": True})

@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze uploaded email file."""
    try:
        import uuid

        if 'email_file' not in request.files:
            flash('No file part')
            return redirect(url_for('index'))

        file = request.files['email_file']
        if file.filename == '':
            flash('No selected file')
            return redirect(url_for('index'))

        if not (file and allowed_file(file.filename)):
            flash('File type not allowed (use .eml, .txt, or .xml)')
            return redirect(url_for('index'))

        # Save uploaded file with a unique name
        original_name = secure_filename(file.filename)
        filename = f"{uuid.uuid4()}_{original_name}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        print(f"Original uploaded filename: {original_name}")
        print(f"Saved as: {filepath}")

        # Read file bytes
        with open(filepath, 'rb') as f:
            file_bytes = f.read()

        print(f"Read {len(file_bytes)} bytes from uploaded file")

        # Analyze email
        result = email_analyzer.analyze_email(file_bytes)

        # Add uploaded file info to result for easier debugging/display
        result["uploaded_filename"] = original_name
        result["saved_filename"] = filename

        if "error" in result:
            flash(result["error"])
            return redirect(url_for('index'))

        # Normalize result
        normalized_result = normalize_email_result(result)

        # Store scan + create incident if needed
        process_scan_result(normalized_result)
        print("Scan processed and stored successfully")

        return render_template('result.html', result=result)

    except Exception as e:
        print(f"Error in analyze route: {e}")
        traceback.print_exc()
        flash(f"Error: {str(e)}")
        return redirect(url_for('index'))

@app.route('/domain', methods=['GET', 'POST'])
def domain_lookup():
    """Look up domain DMARC/SPF records"""
    try:
        if request.method == 'POST':
            domain = request.form['domain'].strip()
            if not domain:
                flash('Please enter a domain')
                return redirect(url_for('domain_lookup'))
            
            dmarc_record = email_analyzer.get_dmarc_record(domain)
            dmarc_policy = email_analyzer.parse_dmarc(dmarc_record)
            spf_record = email_analyzer.get_spf_record(domain)
            
            return render_template('domain.html', domain=domain, 
                                   dmarc_record=dmarc_record,
                                   dmarc_policy=dmarc_policy, 
                                   spf_record=spf_record)
        return render_template('domain.html')
    except Exception as e:
        flash(f"Error: {str(e)}")
        return redirect(url_for('index'))


@app.route("/dashboard")
def dashboard():
    try:
        conn = get_db()
        cur = conn.cursor()

        # Recent scan history
        cur.execute("""
            SELECT id, timestamp, from_domain, verdict, threat_score, details
            FROM scans
            ORDER BY id DESC
            LIMIT 20
        """)
        rows = cur.fetchall()

        # Total scans
        cur.execute("SELECT COUNT(*) AS total FROM scans")
        total_scans = cur.fetchone()["total"]

        # Safe/authenticated emails
        cur.execute("""
            SELECT COUNT(*) AS pass_count
            FROM scans
            WHERE LOWER(verdict) IN ('pass', 'legitimate')
        """)
        pass_count = cur.fetchone()["pass_count"]

        # Risky emails
        cur.execute("""
            SELECT COUNT(*) AS fail_count
            FROM scans
            WHERE LOWER(verdict) IN ('fail', 'softfail', 'none', 'suspicious', 'spoofed')
        """)
        fail_count = cur.fetchone()["fail_count"]

        cur.close()

        return render_template(
            "dashboard.html",
            total_scans=total_scans,
            pass_count=pass_count,
            fail_count=fail_count,
            scans=rows
        )

    except Exception as e:
        traceback.print_exc()
        return f"Dashboard error: {e}", 500

# ==================== EXPORT ROUTES ====================

@app.route('/export/csv')
def export_csv_route():
    """Export scans as CSV"""
    try:
        db = get_db()
        scans = db.execute('SELECT * FROM scans ORDER BY timestamp DESC').fetchall()
        
        # Create CSV in memory
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['ID', 'Timestamp', 'From Domain', 'Verdict', 'Details'])
        
        # Write data
        for scan in scans:
            writer.writerow([scan['id'], scan['timestamp'], scan['from_domain'], 
                            scan['verdict'], scan['details']])
        
        # Create response
        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype='text/csv',
            download_name='dmarc_scans.csv',
            as_attachment=True
        )
    except Exception as e:
        return f"Export error: {str(e)}"

@app.route('/export/json')
def export_json_route():
    """Export scans as JSON"""
    try:
        db = get_db()
        scans = db.execute('SELECT * FROM scans ORDER BY timestamp DESC').fetchall()
        
        # Convert to list of dicts
        data = []
        for scan in scans:
            try:
                details = eval(scan['details']) if scan['details'] else {}
            except:
                details = {}
            
            data.append({
                'id': scan['id'],
                'timestamp': scan['timestamp'],
                'from_domain': scan['from_domain'],
                'verdict': scan['verdict'],
                'details': details
            })
        
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)})

# ==================== API ROUTES (Optional) ====================

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """API endpoint for real-time email analysis."""
    try:
        import base64

        # Get email content from file upload or JSON
        if 'email' in request.files:
            file = request.files['email']
            email_bytes = file.read()
        elif request.is_json and 'email' in request.json:
            email_bytes = base64.b64decode(request.json['email'])
        else:
            return jsonify({'error': 'No email provided'}), 400

        # Analyze email
        result = email_analyzer.analyze_email(email_bytes)

        if "error" in result:
            return jsonify({'error': result['error']}), 400

        # Normalize + store through pipeline
        normalized_result = normalize_email_result(result)
        process_scan_result(normalized_result)

        # Return JSON response
        return jsonify({
            'success': True,
            'verdict': result['verdict'],
            'details': {
                'from_domain': result.get('from_domain'),
                'spf_pass': result.get('spf_pass'),
                'dkim_pass': result.get('dkim_pass'),
                'dmarc_policy': result.get('dmarc_policy'),
                'spf_aligned': result.get('spf_aligned'),
                'dkim_aligned': result.get('dkim_aligned'),
                'reason': result.get('reason')
            }
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500



@app.route('/api/stats')
def api_stats():
    """Get statistics for monitoring"""
    try:
        db = get_db()
        if not db:
            return jsonify({'error': 'Database error'}), 500
        
        # Get stats
        stats = {
            'total_scans': db.execute('SELECT COUNT(*) FROM scans').fetchone()[0],
            'legitimate': db.execute("SELECT COUNT(*) FROM scans WHERE verdict='Legitimate'").fetchone()[0],
            'suspicious': db.execute("SELECT COUNT(*) FROM scans WHERE verdict='Suspicious'").fetchone()[0],
            'spoofed': db.execute("SELECT COUNT(*) FROM scans WHERE verdict='Spoofed'").fetchone()[0]
        }
        
        # Get recent scans
        recent = db.execute('SELECT * FROM scans ORDER BY timestamp DESC LIMIT 10').fetchall()
        stats['recent_scans'] = [
            {
                'timestamp': scan['timestamp'],
                'from_domain': scan['from_domain'],
                'verdict': scan['verdict']
            }
            for scan in recent
        ]
        
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/api/reports")
def api_reports():
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 5))
    offset = (page - 1) * per_page

    db = get_db()
    cur = db.cursor()

    cur.execute("""
        SELECT domain, timestamp, total_emails
        FROM reports
        ORDER BY timestamp DESC
        LIMIT %s OFFSET %s
    """, (per_page, offset))

    rows = cur.fetchall()
    cur.close()

    reports = []
    for r in rows:
        reports.append({
            "domain": r["domain"],
            "date_range_end": r["timestamp"],
            "total_records": r["total_emails"],
            "pass_rate": None
        })

    return jsonify({"reports": reports})

@app.route("/api/risky-domains")
def api_risky_domains():
    db = get_db()
    cur = db.cursor()

    cur.execute("""
        SELECT
            from_domain AS domain,
            COUNT(*) AS total,
            SUM(CASE WHEN LOWER(verdict)='pass' THEN 1 ELSE 0 END) AS pass_count,
            SUM(CASE WHEN LOWER(verdict) IN ('fail','softfail','none','neutral') THEN 1 ELSE 0 END) AS risky_count,
            (SUM(CASE WHEN LOWER(verdict)='fail' THEN 3 ELSE 0 END) +
             SUM(CASE WHEN LOWER(verdict)='softfail' THEN 2 ELSE 0 END) +
             SUM(CASE WHEN LOWER(verdict) IN ('none','neutral') THEN 1 ELSE 0 END)) AS risk_score
        FROM scans
        WHERE from_domain IS NOT NULL AND TRIM(from_domain) != ''
        GROUP BY from_domain
        ORDER BY risk_score DESC, risky_count DESC, total DESC
        LIMIT 10
    """)

    rows = cur.fetchall()
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

@app.route("/api/domains")
def api_domains():
    db = get_db()
    cur = db.cursor()

    cur.execute("""
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
    """)

    rows = cur.fetchall()
    cur.close()

    return jsonify({"domains": [dict(r) for r in rows]})



@app.route("/api/alerts")
def api_alerts():
    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
        SELECT from_domain, verdict, timestamp
        FROM scans
        WHERE verdict = 'fail'
        ORDER BY timestamp DESC
        LIMIT 10
    """)

    rows = cursor.fetchall()

    alerts = []
    for r in rows:
        alerts.append({
            "severity": "high",
            "domain": r["from_domain"],
            "source_ip": "unknown",
            "message": "DMARC failure detected",
            "detected": r["timestamp"]
        })

    return jsonify(alerts)

from datetime import datetime, timedelta
import random


@app.route("/dev/seed")
def dev_seed():
    db = get_db()
    cur = db.cursor()

    domains = ["example.com", "amazon.com", "google.com", "microsoft.com", "bank-secure.com", "paypal.com"]
    verdicts = ["pass", "pass", "pass", "softfail", "fail", "none"]  # weighted

    # ---- Seed scans (drives domains/timeline/pass-rate widgets) ----
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

        # threat score for demo realism
        threat_score_map = {
            "pass": 0,
            "softfail": 60,
            "fail": 90,
            "none": 70
        }
        threat_score = threat_score_map.get(verdict, 40)

        cur.execute("""
            INSERT INTO scans (timestamp, from_domain, verdict, threat_score, details)
            VALUES (%s, %s, %s, %s, %s)
        """, (ts, domain, verdict, threat_score, details))

        # ---- Seed incidents from risky verdicts ----
        if verdict in ("fail", "softfail", "none"):
            severity = "high" if verdict == "fail" else "medium"

            try:
                cur.execute("""
                    INSERT INTO incidents (timestamp, severity, domain, source_ip, title, message, status)
                    VALUES (%s, %s, %s, %s, %s, %s, 'open')
                """, (
                    ts,
                    severity,
                    domain,
                    f"203.0.113.{random.randint(1,254)}",
                    "DMARC anomaly detected",
                    f"Verdict={verdict}. Check SPF/DKIM alignment and DMARC policy."
                ))
            except Exception:
                pass

    # ---- Seed reports (Recent Reports widget) ----
    for _ in range(12):
        domain = random.choice(domains)
        ts = datetime.now() - timedelta(days=random.randint(0, 29))

        cur.execute("""
            INSERT INTO reports (timestamp, org_name, domain, total_emails)
            VALUES (%s, %s, %s, %s)
        """, (ts, "DemoOrg", domain, random.randint(50, 600)))

    db.commit()
    cur.close()

    return "Seeded demo data for scans + reports (+ incidents). Refresh /dashboard"

@app.route('/upload_report', methods=['POST'])
def upload_report():
    """Upload and parse DMARC XML report."""
    try:
        import uuid

        if 'report_file' not in request.files:
            flash('No file part')
            return redirect(url_for('index'))

        file = request.files['report_file']
        if file.filename == '':
            flash('No selected file')
            return redirect(url_for('index'))

        if not (file and allowed_file(file.filename)):
            flash('File type not allowed (use .xml)')
            return redirect(url_for('index'))

        # Save uploaded file with unique name
        original_name = secure_filename(file.filename)
        filename = f"{uuid.uuid4()}_{original_name}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        with open(filepath, 'rb') as f:
            xml_bytes = f.read()

        parsed = report_parser.parse_dmarc_report(xml_bytes)

        if "error" in parsed:
            flash(parsed["error"])
            return redirect(url_for('index'))

        # Save summary to PostgreSQL
        db = get_db()
        if db:
            try:
                cur = db.cursor()
                cur.execute("""
                    INSERT INTO reports (org_name, domain, total_emails)
                    VALUES (%s, %s, %s)
                """, (
                    parsed.get('org_name'),
                    parsed.get('domain'),
                    parsed.get('total_emails', 0)
                ))
                db.commit()
                cur.close()
                print("Report saved to database")
            except Exception as e:
                print(f"Error saving report: {e}")
                traceback.print_exc()
                flash(f"Database error: {e}")
                return redirect(url_for('index'))

        return render_template('report.html', report=parsed)

    except Exception as e:
        traceback.print_exc()
        flash(f"Error: {str(e)}")
        return redirect(url_for('index'))

def calculate_threat_score(verdict):
    verdict = verdict.lower()

    scores = {
        "pass": 0,
        "neutral": 20,
        "softfail": 40,
        "none": 60,
        "fail": 80
    }

    return scores.get(verdict, 50)
    score = calculate_threat_score(verdict)

def risk_level(score):
    if score < 20:
        return "Low"
    elif score < 50:
        return "Medium"
    else:
        return "High"



if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)