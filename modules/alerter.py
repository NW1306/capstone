import smtplib
import sqlite3
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import threading
import time

class AlertSystem:
    def __init__(self, db_path='database.db'):
        self.db_path = db_path
        self.alert_email = "admin@yourdomain.com"  # Change this
        self.smtp_server = "smtp.gmail.com"  # Configure your SMTP
        self.smtp_port = 587
        self.smtp_user = "your-email@gmail.com"
        self.smtp_password = "your-password"
        
    def check_and_alert(self):
        """Check for suspicious activity and send alerts"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check for spoofed emails in last hour
        cursor.execute('''
            SELECT COUNT(*), from_domain 
            FROM scans 
            WHERE verdict='Spoofed' 
            AND timestamp > datetime('now', '-1 hour')
            GROUP BY from_domain
        ''')
        
        results = cursor.fetchall()
        conn.close()
        
        for count, domain in results:
            if count >= 5:  # Threshold: 5 spoofed emails from same domain in 1 hour
                self.send_alert(domain, count)
    
    def send_alert(self, domain, count):
        """Send email alert"""
        msg = MIMEMultipart()
        msg['From'] = self.smtp_user
        msg['To'] = self.alert_email
        msg['Subject'] = f"🚨 DMARC Alert: Multiple Spoofed Emails Detected"
        
        body = f"""
        <h2>DMARC Security Alert</h2>
        <p><strong>Domain:</strong> {domain}</p>
        <p><strong>Spoofed emails detected:</strong> {count} in the last hour</p>
        <p><strong>Time:</strong> {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Please investigate immediately.</p>
        """
        
        msg.attach(MIMEText(body, 'html'))
        
        try:
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.smtp_user, self.smtp_password)
            server.send_message(msg)
            server.quit()
            print(f"✅ Alert sent for {domain}")
        except Exception as e:
            print(f"❌ Failed to send alert: {e}")
    
    def start_monitoring(self, interval=3600):
        """Start background monitoring thread"""
        def monitor():
            while True:
                self.check_and_alert()
                time.sleep(interval)  # Check every hour
        
        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
        print("✅ Alert monitoring started")