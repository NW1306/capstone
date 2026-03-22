from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime)
    org_name = db.Column(db.Text)
    domain = db.Column(db.Text)
    total_emails = db.Column(db.Integer)

class Incident(db.Model):
    __tablename__ = "incidents"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime)
    severity = db.Column(db.Text)
    domain = db.Column(db.Text)
    source_ip = db.Column(db.Text)
    title = db.Column(db.Text)
    message = db.Column(db.Text)
    status = db.Column(db.Text)