from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)

class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)