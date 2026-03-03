import os
import sqlite3
import traceback
import logging
import csv
import json
import io
from flask import Flask, render_template, request, redirect, url_for, flash, g, jsonify, send_file
from werkzeug.utils import secure_filename
from modules import email_analyzer, report_parser

# Enable logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'  # Change this in production!
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max
ALLOWED_EXTENSIONS = {'eml', 'txt', 'xml'}

# Create uploads folder
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database setup
DATABASE = 'database.db'

def get_db():
    """Get database connection"""
    db = getattr(g, '_database', None)
    if db is None:
        try:
            db = g._database = sqlite3.connect(DATABASE)
            db.row_factory = sqlite3.Row
            print(f"✅ Connected to database: {DATABASE}")
        except Exception as e:
            print(f"❌ Database connection error: {e}")
            return None
    return db

def init_db():
    """Initialize database tables"""
    try:
        # Connect to database (this will create the file if it doesn't exist)
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Create scans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                from_domain TEXT,
                verdict TEXT,
                details TEXT
            )
        ''')
        print("✅ Scans table created/verified")
        
        # Create reports table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                org_name TEXT,
                domain TEXT,
                total_emails INTEGER
            )
        ''')
        print("✅ Reports table created/verified")
        
        # Commit changes
        conn.commit()
        
        # Verify tables were created
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print(f"📊 Tables in database: {[table[0] for table in tables]}")
        
        conn.close()
        print("✅ Database initialization complete")
        return True
        
    except Exception as e:
        print(f"❌ Database initialization error: {e}")
        traceback.print_exc()
        return False

@app.teardown_appcontext
def close_connection(exception):
    """Close database connection"""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

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

# ==================== ROUTES ====================

@app.route('/')
def index():
    """Home page"""
    try:
        return render_template('index.html')
    except Exception as e:
        return f"Error loading template: {e}"

@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze uploaded email file"""
    try:
        if 'email_file' not in request.files:
            flash('No file part')
            return redirect(url_for('index'))
        
        file = request.files['email_file']
        if file.filename == '':
            flash('No selected file')
            return redirect(url_for('index'))
        
        if file and allowed_file(file.filename):
            # Save file
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            print(f"✅ File saved: {filepath}")
            
            # Read file
            with open(filepath, 'rb') as f:
                file_bytes = f.read()
            
            # Analyze email
            result = email_analyzer.analyze_email(file_bytes)
            
            if "error" in result:
                flash(result["error"])
                return redirect(url_for('index'))
            
            # Save to database
            db = get_db()
            if db:
                try:
                    db.execute(
                        'INSERT INTO scans (from_domain, verdict, details) VALUES (?, ?, ?)',
                        (result['from_domain'], result['verdict'], str(result))
                    )
                    db.commit()
                    print("✅ Results saved to database")
                except Exception as e:
                    print(f"❌ Error saving to database: {e}")
                    flash(f"Database error: {e}")
            
            return render_template('result.html', result=result)
        else:
            flash('File type not allowed (use .eml, .txt, or .xml)')
            return redirect(url_for('index'))
            
    except Exception as e:
        print(f"❌ Error in analyze route: {e}")
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

@app.route('/upload_report', methods=['POST'])
def upload_report():
    """Upload and parse DMARC XML report"""
    try:
        if 'report_file' not in request.files:
            flash('No file part')
            return redirect(url_for('index'))
        
        file = request.files['report_file']
        if file.filename == '':
            flash('No selected file')
            return redirect(url_for('index'))
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            with open(filepath, 'rb') as f:
                xml_bytes = f.read()
            
            parsed = report_parser.parse_dmarc_report(xml_bytes)
            
            if "error" in parsed:
                flash(parsed["error"])
                return redirect(url_for('index'))
            
            # Save to DB
            db = get_db()
            if db:
                try:
                    db.execute(
                        'INSERT INTO reports (org_name, domain, total_emails) VALUES (?, ?, ?)',
                        (parsed['org_name'], parsed['domain'], parsed['total_emails'])
                    )
                    db.commit()
                    print("✅ Report saved to database")
                except Exception as e:
                    print(f"❌ Error saving report: {e}")
            
            return render_template('report.html', report=parsed)
        else:
            flash('File type not allowed (use .xml)')
            return redirect(url_for('index'))
    except Exception as e:
        flash(f"Error: {str(e)}")
        return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    """Enhanced dashboard with charts and statistics"""
    try:
        db = get_db()
        if not db:
            return "Database error"
        
        # Get recent scans with parsed details
        scans_raw = db.execute('SELECT * FROM scans ORDER BY timestamp DESC LIMIT 50').fetchall()
        
        # Parse details string to dict and extract fields
        scans = []
        for scan in scans_raw:
            scan_dict = dict(scan)
            try:
                # Try to eval the details string back to dict
                details = eval(scan_dict['details'])
                scan_dict['spf_pass'] = details.get('spf_pass', 'N/A')
                scan_dict['dkim_pass'] = details.get('dkim_pass', 'N/A')
                scan_dict['dmarc_policy'] = details.get('dmarc_policy', 'N/A')
            except:
                scan_dict['spf_pass'] = 'N/A'
                scan_dict['dkim_pass'] = 'N/A'
                scan_dict['dmarc_policy'] = 'N/A'
            scans.append(scan_dict)
        
        # Get reports
        reports_raw = db.execute('SELECT * FROM reports ORDER BY timestamp DESC LIMIT 10').fetchall()
        
        # Calculate pass rate for reports (placeholder - you can enhance this)
        reports = []
        for rep in reports_raw:
            rep_dict = dict(rep)
            # Placeholder pass rate - you can calculate from actual data
            rep_dict['pass_rate'] = 75  
            reports.append(rep_dict)
        
        # Calculate statistics
        total_scans = db.execute('SELECT COUNT(*) FROM scans').fetchone()[0]
        legitimate_count = db.execute("SELECT COUNT(*) FROM scans WHERE verdict='Legitimate'").fetchone()[0]
        suspicious_count = db.execute("SELECT COUNT(*) FROM scans WHERE verdict='Suspicious'").fetchone()[0]
        spoofed_count = db.execute("SELECT COUNT(*) FROM scans WHERE verdict='Spoofed'").fetchone()[0]
        
        # Get top suspicious domains
        top_domains_data = db.execute('''
            SELECT from_domain, COUNT(*) as count 
            FROM scans 
            WHERE verdict='Suspicious' OR verdict='Spoofed'
            GROUP BY from_domain 
            ORDER BY count DESC 
            LIMIT 10
        ''').fetchall()
        
        top_domains = [d[0] for d in top_domains_data] if top_domains_data else ['No data']
        domain_counts = [d[1] for d in top_domains_data] if top_domains_data else [0]
        
        return render_template('dashboard.html', 
                             scans=scans, 
                             reports=reports,
                             total_scans=total_scans,
                             legitimate_count=legitimate_count,
                             suspicious_count=suspicious_count,
                             spoofed_count=spoofed_count,
                             top_domains=top_domains,
                             domain_counts=domain_counts)
    except Exception as e:
        return f"Dashboard error: {str(e)}"

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
    """API endpoint for real-time email analysis"""
    try:
        # Get email from request
        if 'email' in request.files:
            file = request.files['email']
            email_bytes = file.read()
        elif request.is_json and 'email' in request.json:
            import base64
            email_bytes = base64.b64decode(request.json['email'])
        else:
            return jsonify({'error': 'No email provided'}), 400
        
        # Analyze
        result = email_analyzer.analyze_email(email_bytes)
        
        if "error" in result:
            return jsonify({'error': result['error']}), 400
        
        # Save to database
        db = get_db()
        if db:
            db.execute('INSERT INTO scans (from_domain, verdict, details) VALUES (?, ?, ?)',
                      (result['from_domain'], result['verdict'], str(result)))
            db.commit()
        
        # Return JSON response
        return jsonify({
            'success': True,
            'verdict': result['verdict'],
            'details': {
                'from_domain': result['from_domain'],
                'spf_pass': result['spf_pass'],
                'dkim_pass': result['dkim_pass'],
                'dmarc_policy': result['dmarc_policy'],
                'spf_aligned': result['spf_aligned'],
                'dkim_aligned': result['dkim_aligned'],
                'reason': result['reason']
            }
        })
        
    except Exception as e:
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
            'spoofed': db.execute("SELECT COUNT(*) FROM scans WHERE verdict='Spoofed'").fetchone()[0],
            'recent_scans': []
        }
        
        # Get recent scans
        recent = db.execute('SELECT * FROM scans ORDER BY timestamp DESC LIMIT 10').fetchall()
        for scan in recent:
            stats['recent_scans'].append({
                'timestamp': scan['timestamp'],
                'from_domain': scan['from_domain'],
                'verdict': scan['verdict']
            })
        
        return jsonify(stats)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== MAIN ====================

if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("🚀 DMARC Analyzer Starting...")
    print("=" * 60)
    
    # Initialize database
    if init_db():
        print("✅ Database ready")
    else:
        print("❌ Database initialization failed")
    
    print("\n🌐 Server will be available at: http://127.0.0.1:5000")
    print("📝 Press CTRL+C to stop the server")
    print("=" * 60 + "\n")
    
    # Run the app
    app.run(debug=True, host='127.0.0.1', port=5000)
    