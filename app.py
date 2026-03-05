# app.py
import os
import json
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, abort
from sqlalchemy import func, desc
from config import config
from models import db, DmarcReport, DmarcRecord, SpoofingAlert, DomainStats

# Create Flask app
app = Flask(__name__)

# Load configuration
env = os.getenv('FLASK_ENV', 'development')
app.config.from_object(config[env])

# Initialize database
db.init_app(app)

# Create tables if they don't exist
with app.app_context():
    db.create_all()
    print(f"✅ Database connected: {app.config['SQLALCHEMY_DATABASE_URI']}")


# ==================== Routes ====================

@app.route('/')
def index():
    """Home page - redirect to dashboard"""
    return render_template('dashboard.html')


@app.route('/dashboard')
def dashboard():
    """Main dashboard view"""
    return render_template('dashboard.html')


@app.route('/health')
def health():
    """Health check endpoint"""
    try:
        # Test database connection
        db.engine.execute('SELECT 1')
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'environment': env
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'database': 'disconnected',
            'error': str(e)
        }), 500


# ==================== API Endpoints ====================

@app.route('/api/stats/summary')
def get_summary_stats():
    """Get summary statistics for dashboard"""
    try:
        # Total domains monitored
        total_domains = DomainStats.query.count()
        
        # Total reports processed
        total_reports = DmarcReport.query.count()
        
        # Total records (emails) processed
        total_emails = DmarcRecord.query.count()
        
        # Active spoofing alerts
        active_alerts = SpoofingAlert.query.filter_by(resolved=False).count()
        
        # Pass rate (last 30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_records = DmarcRecord.query.filter(
            DmarcRecord.created_at >= thirty_days_ago
        ).all()
        
        if recent_records:
            passed = sum(1 for r in recent_records if r.passed)
            pass_rate = (passed / len(recent_records)) * 100
        else:
            pass_rate = 0
        
        # Top domains by email volume
        top_domains = db.session.query(
            DmarcRecord.header_from,
            func.count(DmarcRecord.id).label('count')
        ).group_by(DmarcRecord.header_from).order_by(desc('count')).limit(5).all()
        
        return jsonify({
            'total_domains': total_domains,
            'total_reports': total_reports,
            'total_emails': total_emails,
            'active_alerts': active_alerts,
            'pass_rate': round(pass_rate, 2),
            'top_domains': [{'domain': d[0], 'count': d[1]} for d in top_domains]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/reports')
def get_reports():
    """Get DMARC reports with pagination"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = app.config.get('DMARC_RECORDS_PER_PAGE', 50)
        
        pagination = DmarcReport.query.order_by(
            desc(DmarcReport.date_range_end)
        ).paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify({
            'reports': [r.to_dict() for r in pagination.items],
            'total': pagination.total,
            'pages': pagination.pages,
            'current_page': pagination.page,
            'has_next': pagination.has_next,
            'has_prev': pagination.has_prev
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/reports/<int:report_id>')
def get_report(report_id):
    """Get detailed report information"""
    try:
        report = DmarcReport.query.get_or_404(report_id)
        
        # Get records for this report with pagination
        page = request.args.get('page', 1, type=int)
        per_page = 20
        
        records_pagination = report.records.order_by(
            DmarcRecord.created_at.desc()
        ).paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify({
            'report': report.to_dict(),
            'records': [r.to_dict() for r in records_pagination.items],
            'records_total': records_pagination.total,
            'records_pages': records_pagination.pages,
            'current_page': records_pagination.page
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts')
def get_alerts():
    """Get spoofing alerts"""
    try:
        resolved = request.args.get('resolved', 'false').lower() == 'true'
        limit = request.args.get('limit', 50, type=int)
        
        query = SpoofingAlert.query
        if not resolved:
            query = query.filter_by(resolved=False)
        
        alerts = query.order_by(desc(SpoofingAlert.detected_at)).limit(limit).all()
        
        return jsonify({
            'alerts': [{
                'id': a.id,
                'domain': a.domain,
                'source_ip': a.source_ip,
                'severity': a.severity,
                'message': a.message,
                'detected_at': a.detected_at.isoformat() if a.detected_at else None,
                'resolved': a.resolved
            } for a in alerts]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts/<int:alert_id>/resolve', methods=['POST'])
def resolve_alert(alert_id):
    """Resolve a spoofing alert"""
    try:
        alert = SpoofingAlert.query.get_or_404(alert_id)
        alert.resolved = True
        alert.resolved_at = datetime.utcnow()
        db.session.commit()
        return jsonify({'success': True, 'message': 'Alert resolved'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/domains')
def get_domains():
    """Get domain statistics"""
    try:
        domains = DomainStats.query.order_by(desc(DomainStats.total_emails)).all()
        return jsonify({
            'domains': [{
                'domain': d.domain,
                'total_emails': d.total_emails,
                'passed_emails': d.passed_emails,
                'failed_emails': d.failed_emails,
                'spoofing_attempts': d.spoofing_attempts,
                'pass_rate': round(d.pass_rate, 2),
                'dmarc_policy': d.dmarc_policy,
                'last_email': d.last_email_received.isoformat() if d.last_email_received else None
            } for d in domains]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/domains/<domain>')
def get_domain_detail(domain):
    """Get detailed statistics for a specific domain"""
    try:
        stats = DomainStats.query.filter_by(domain=domain).first_or_404()
        
        # Get recent records for this domain
        recent_records = DmarcRecord.query.filter_by(header_from=domain).order_by(
            desc(DmarcRecord.created_at)
        ).limit(50).all()
        
        return jsonify({
            'domain_stats': {
                'domain': stats.domain,
                'total_emails': stats.total_emails,
                'passed_emails': stats.passed_emails,
                'failed_emails': stats.failed_emails,
                'spoofing_attempts': stats.spoofing_attempts,
                'pass_rate': round(stats.pass_rate, 2),
                'dmarc_policy': stats.dmarc_policy,
                'dmarc_record': stats.dmarc_record,
                'last_email': stats.last_email_received.isoformat() if stats.last_email_received else None,
                'last_alert': stats.last_alert_generated.isoformat() if stats.last_alert_generated else None
            },
            'recent_records': [r.to_dict() for r in recent_records]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/charts/timeline')
def get_timeline_data():
    """Get timeline data for charts"""
    try:
        days = request.args.get('days', 30, type=int)
        start_date = datetime.utcnow() - timedelta(days=days)
        
        # Daily counts
        daily_counts = db.session.query(
            func.date(DmarcRecord.created_at).label('date'),
            func.count(DmarcRecord.id).label('total'),
            func.sum(case([(DmarcRecord.passed, 1)], else_=0)).label('passed')
        ).filter(
            DmarcRecord.created_at >= start_date
        ).group_by(
            func.date(DmarcRecord.created_at)
        ).order_by('date').all()
        
        return jsonify({
            'dates': [str(d.date) for d in daily_counts],
            'total': [d.total for d in daily_counts],
            'passed': [d.passed for d in daily_counts],
            'failed': [d.total - d.passed for d in daily_counts]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Helper function for conditional sum
def case(conditions, else_=0):
    """Simple case implementation for SQLAlchemy"""
    from sqlalchemy.sql.expression import Case
    whens = [(conditions[0][1], conditions[0][2])]
    return Case(whens, else_=else_)


# ==================== Error Handlers ====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'error': 'Internal server error'}), 500


# ==================== Main Entry Point ====================

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=(env == 'development'))