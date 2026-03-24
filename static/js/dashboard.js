

let isRefreshing = false;

document.addEventListener('DOMContentLoaded', () => {
    showLoading();
    loadAllData();
    setInterval(refreshDashboardSafely, 10000);
});

async function refreshDashboardSafely() {
    if (isRefreshing) return;
    isRefreshing = true;
    try {
        await loadAllData();
    } finally {
        isRefreshing = false;
    }
}

function refreshData() {
    showLoading();
    loadAllData();
}

function showLoading() {
    const loading = document.getElementById('loading');
    if (loading) loading.style.display = 'block';
}

function hideLoading() {
    const loading = document.getElementById('loading');
    if (loading) loading.style.display = 'none';
}

async function fetchJson(url) {
    const response = await fetch(url);
    if (!response.ok) {
        throw new Error(`Failed to fetch ${url}: ${response.status}`);
    }
    return await response.json();
}

async function loadAllData() {
    try {
        await Promise.all([
            loadSummaryStats(),
            loadAlerts(),
            loadTimelineData(),
            loadRiskyDomains(),
            loadRecentReports(),
            loadIncidents()
        ]);

        const lastUpdated = document.getElementById('last-updated');
        if (lastUpdated) {
            lastUpdated.innerHTML = `<i class="bi bi-clock"></i> Updated: ${new Date().toLocaleTimeString()}`;
        }
    } catch (error) {
        console.error('Error loading dashboard data:', error);
    } finally {
        hideLoading();
    }
}

async function loadSummaryStats() {
    try {
        const data = await fetchJson('/api/stats/summary');

        const summary = document.getElementById('summary-stats');
        if (summary) {
            summary.innerHTML = `
                <div class="col-md-3">
                    <div class="stat-card">
                        <h6>Domains</h6>
                        <h2>${data.total_domains || 0}</h2>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card">
                        <h6> Reports</h6>
                        <h2>${data.total_reports || 0}</h2>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card">
                        <h6> Emails</h6>
                        <h2>${data.total_emails || 0}</h2>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card">
                        <h6>Active Alerts</h6>
                        <h2>${data.active_alerts || 0}</h2>
                    </div>
                </div>
            `;
        }

        updateAlertBadge(data.active_alerts || 0);

        const passRateText = document.getElementById('passRateText');
        if (passRateText) {
            const passRate = Number(data.pass_rate || 0);
            passRateText.innerHTML = `
                <h4 class="${getPassRateClass(passRate)}">${passRate}%</h4>
                <small>Pass Rate (30 days)</small>
            `;
        }
    } catch (error) {
        console.error('Error loading summary stats:', error);
    }
}

function updateIncidentBadge(count) {
    const badge = document.getElementById('incident-count');
    if (!badge) return;

    badge.textContent = count;
    badge.classList.remove('bg-success', 'bg-warning', 'bg-danger');

    if (count === 0) {
        badge.classList.add('bg-success');
    } else if (count <= 5) {
        badge.classList.add('bg-warning');
    } else {
        badge.classList.add('bg-danger');
    }
}

function updateAlertBadge(count) {
    const badge = document.getElementById('alert-count');
    if (!badge) return;

    badge.textContent = count;
    badge.classList.remove('bg-success', 'bg-warning', 'bg-danger');

    if (count === 0) {
        badge.classList.add('bg-success');
    } else if (count <= 5) {
        badge.classList.add('bg-warning');
    } else {
        badge.classList.add('bg-danger');
    }
}

async function loadAlerts() {
    try {
        const data = await fetchJson('/api/alerts?resolved=false&limit=20');
        const alerts = data.alerts || [];
        updateAlertBadge(alerts.length);

        const tbody = document.getElementById('alerts-table');
        if (!tbody) return;

        if (alerts.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center text-success">
                        <i class="bi bi-check-circle"></i> No active alerts
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = alerts.map(alert => `
            <tr class="alert-${alert.severity || 'low'}">
                <td><span class="badge bg-${getSeverityBadge(alert.severity)}">${alert.severity || 'low'}</span></td>
                <td>${alert.domain || 'Unknown'}</td>
                <td>${alert.source_ip || 'Unknown'}</td>
                <td>${alert.message || 'No message'}</td>
                <td>${alert.timestamp ? new Date(alert.timestamp).toLocaleString() : 'N/A'}</td>
                
            </tr>
        `).join('');
    } catch (error) {
        console.error('Error loading alerts:', error);
    }
}

async function loadTimelineData() {
    try {
        const res = await fetch('/api/charts/timeline?days=30');
        const data = await res.json();

        const dates = Array.isArray(data) ? data.map(d => d.date) : (data.labels || []);
        const counts = Array.isArray(data) ? data.map(d => d.count) : (data.values || []);

        Plotly.newPlot('timelineChart', [{
            x: dates,
            y: counts,
            type: 'scatter',
            mode: 'lines+markers',
            fill: 'tozeroy',
            name: 'DMARC Reports Over Time'
        }], {
            margin: { t: 30, r: 20, b: 40, l: 40 }
        }, {
            displayModeBar: false,
            responsive: true
        });

        const passRes = await fetch('/api/charts/pass-rate');
        const passData = await passRes.json();

        Plotly.newPlot('passRateChart', [{
            values: [passData.passed || 0, passData.failed || 0],
            labels: ['Passed', 'Failed'],
            type: 'pie',
            hole: 0.55,
            textinfo: 'label+percent'
        }], {
            margin: { t: 20, r: 20, b: 20, l: 20 },
            showlegend: true
        }, {
            displayModeBar: false,
            responsive: true
        });

    } catch (err) {
        console.error('Plotly chart error:', err);
    }
}

async function loadRiskyDomains() {
    try {
        const data = await fetchJson('/api/risky-domains');
        const tbody = document.getElementById('risky-domains-table');
        if (!tbody) return;

        const domains = data.domains || [];

        if (domains.length === 0) {
            tbody.innerHTML = `<tr><td colspan="4" class="text-center">No data yet</td></tr>`;
            return;
        }

        tbody.innerHTML = domains.map(d => `
            <tr>
                <td>${d.domain || 'Unknown'}</td>
                <td>${d.total || 0}</td>
                <td>${d.pass_rate ?? 0}%</td>
                <td>
                    <span class="badge ${
                        d.risk_score >= 6 ? 'bg-danger' :
                        d.risk_score >= 3 ? 'bg-warning text-dark' :
                        'bg-success'
                    }">
                        ${d.risk_score ?? 0}
                    </span>
                </td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Error loading risky domains:', error);
    }
}

async function loadRecentReports() {
    try {
        const data = await fetchJson('/api/reports?page=1&per_page=20');
        const tbody = document.getElementById('recent-reports-table');
        if (!tbody) return;

        const reports = data.reports || [];

        if (reports.length === 0) {
            tbody.innerHTML = `<tr><td colspan="4" class="text-center">No recent reports</td></tr>`;
            return;
        }

        tbody.innerHTML = reports.map(report => `
            <tr>
                <td>${report.domain || 'Unknown'}</td>
                <td>${report.date && report.date !== 'N/A' ? new Date(report.date).toLocaleDateString() : 'N/A'}</td>
                <td>${report.records || 0}</td>
                <td>
                    <span class="${getPassRateClass(Number(report.pass_rate || 0))}">
                        ${Number(report.pass_rate || 0).toFixed(1)}%
                    </span>
                </td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Error loading recent reports:', error);
    }
}

async function loadIncidents() {
    try {
        const items = await fetchJson('/api/latest-scans');
        const scans = Array.isArray(items) ? items : [];
        updateIncidentBadge(scans.length);

        const tbody = document.getElementById('incidentsTable');
        if (!tbody) return;

        if (scans.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" class="text-center">No scans</td></tr>`;
            return;
        }

        tbody.innerHTML = scans.map(i => `
            <tr>
                <td>${i.severity || 'N/A'}</td>
                <td>${i.domain || 'N/A'}</td>
                <td>${i.title || 'N/A'}</td>
                <td>${i.detected || 'N/A'}</td>
                <td>${i.status || 'N/A'}</td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Error loading latest scans:', error);
    }
}

async function resolveAlert(alertId) {
    try {
        const response = await fetch(`/api/alerts/${alertId}/resolve`, {
            method: 'POST'
        });
        const data = await response.json();
        if (data.success) {
            loadAlerts();
            loadSummaryStats();
        }
    } catch (error) {
        console.error('Error resolving alert:', error);
    }
}

async function resolveIncident(id) {
    try {
        const response = await fetch(`/api/incidents/${id}/resolve`, {
            method: 'POST'
        });
        const data = await response.json();
        if (data.success) {
            loadIncidents();
        }
    } catch (error) {
        console.error('Error resolving incident:', error);
    }
}

function getSeverityBadge(severity) {
    const badges = {
        critical: 'danger',
        high: 'warning',
        medium: 'info',
        low: 'secondary'
    };
    return badges[severity] || 'primary';
}

function getPassRateClass(rate) {
    if (rate >= 95) return 'pass-rate-good';
    if (rate >= 80) return 'pass-rate-warning';
    return 'pass-rate-bad';
}