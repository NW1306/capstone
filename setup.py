import os
import sqlite3
import shutil

print("=" * 60)
print(" DMARC ANALYZER - FINAL SETUP")
print("=" * 60)

# Show current directory
current_dir = os.getcwd()
print(f"\nWorking directory: {current_dir}")

# Check if we can write here
test_file = 'test_write.txt'
try:
    with open(test_file, 'w') as f:
        f.write('test')
    os.remove(test_file)
    print("Directory is writable")
except:
    print("Cannot write to this directory. Run as Administrator!")
    input("Press Enter to exit...")
    exit()

# Delete old database if exists
db_path = 'database.db'
if os.path.exists(db_path):
    os.remove(db_path)
    print("Old database deleted")

# Create uploads folder if not exists
if not os.path.exists('uploads'):
    os.makedirs('uploads')
    print("Uploads folder created")

# Create fresh database
print("\n Creating fresh database...")
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Create scans table
cursor.execute('''
    CREATE TABLE scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        from_domain TEXT,
        verdict TEXT,
        details TEXT
    )
''')
print("scans table created")

# Create reports table
cursor.execute('''
    CREATE TABLE reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        org_name TEXT,
        domain TEXT,
        total_emails INTEGER
    )
''')
print(" reports table created")

# Add test data
test_scans = [
    ('google.com', 'Legitimate', '{"spf_pass": true, "dkim_pass": true, "dmarc_policy": "reject"}'),
    ('paypal.com', 'Spoofed', '{"spf_pass": false, "dkim_pass": false, "dmarc_policy": "reject"}'),
    ('microsoft.com', 'Suspicious', '{"spf_pass": false, "dkim_pass": true, "dmarc_policy": "quarantine"}'),
]

for domain, verdict, details in test_scans:
    cursor.execute(
        'INSERT INTO scans (from_domain, verdict, details) VALUES (?, ?, ?)',
        (domain, verdict, details)
    )
print("Test data added to scans")

# Add test report
cursor.execute(
    'INSERT INTO reports (org_name, domain, total_emails) VALUES (?, ?, ?)',
    ('Google Inc.', 'google.com', 1250)
)
print("Test data added to reports")

conn.commit()

# Verify data
cursor.execute("SELECT COUNT(*) FROM scans")
scan_count = cursor.fetchone()[0]
cursor.execute("SELECT COUNT(*) FROM reports")
report_count = cursor.fetchone()[0]

print(f"\n Database Summary:")
print(f"   - Database path: {os.path.abspath(db_path)}")
print(f"   - Database size: {os.path.getsize(db_path)} bytes")
print(f"   - Scans table: {scan_count} records")
print(f"   - Reports table: {report_count} records")

# Show data
print("\n📋 Scans in database:")
cursor.execute("SELECT id, timestamp, from_domain, verdict FROM scans")
for row in cursor.fetchall():
    print(f"   - {row[0]}: {row[1]} | {row[2]} | {row[3]}")

conn.close()

print("\n" + "=" * 60)
print("SETUP COMPLETE!")
print("=" * 60)
print("\n Next steps:")
print("1. Make sure your virtual environment is activated:")
print("   venv\\Scripts\\activate")
print("2. Run the app:")
print("   python app.py")
print("3. Open browser:")
print("   http://127.0.0.1:5000/dashboard")
input("\nPress Enter to exit...")