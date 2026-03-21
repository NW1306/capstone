from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False)
    record_count = db.Column(db.Integer, default=0)
    pass_rate = db.Column(db.Float, default=0)

class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    severity = db.Column(db.String(50))
    domain = db.Column(db.String(255))
    title = db.Column(db.String(255))
    status = db.Column(db.String(50), default="Open")