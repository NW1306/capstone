let timelineChart = null;
let passRateChart = null;

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
                        <h6><i class="bi bi-globe"></i> Domains</h6>
                        <h2>${data.total_domains || 0}</h2>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card">
                        <h6><i class="bi bi-file-text"></i> Reports</h6>
                        <h2>${data.total_reports || 0}</h2>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card">
                        <h6><i class="bi bi-envelope"></i> Emails</h6>
                        <h2>${data.total_emails || 0}</h2>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card">
                        <h6><i class="bi bi-exclamation-triangle"></i> Active Alerts</h6>
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
        const data = await fetchJson('/api/alerts?resolved=false&limit=10');
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
        const data = await fetchJson('/api/charts/timeline?days=30');
        console.log("RAW API:", data);

        const canvas = document.getElementById('timelineChart');
        const passRateCanvas = document.getElementById('passRateChart');

        if (!canvas) {
            console.error("timelineChart canvas not found");
            return;
        }

        if (!Array.isArray(data) || data.length === 0) {
            console.warn("No timeline data returned");
            return;
        }

        const labels = data.map(d => d.date);
        const values = data.map(d => Number(d.count || 0));

        if (timelineChart) {
            timelineChart.destroy();
        }

        timelineChart = new Chart(canvas.getContext('2d'), {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'DMARC Activity',
                    data: values,
                    borderColor: '#0d6efd',
                    backgroundColor: 'rgba(13, 110, 253, 0.1)',
                    fill: true,
                    tension: 0.3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                scales: {
                    y: { beginAtZero: true }
                }
            }
        });

        if (passRateCanvas) {
            if (passRateChart) {
                passRateChart.destroy();
            }

            const total = values.reduce((a, b) => a + b, 0);

            passRateChart = new Chart(passRateCanvas.getContext('2d'), {
                type: 'doughnut',
                data: {
                    labels: ['Total Reports'],
                    datasets: [{
                        data: [total],
                        backgroundColor: ['#198754'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: false
                }
            });
        }

        console.log("CHART CREATED SUCCESSFULLY");
    } catch (err) {
        console.error("CHART ERROR:", err);
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
        const data = await fetchJson('/api/reports?page=1&per_page=5');
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
        const items = await fetchJson('/api/incidents');
        const incidents = Array.isArray(items) ? items : [];
        updateIncidentBadge(incidents.length);

        const tbody = document.getElementById('incidentsTable');
        if (!tbody) return;

        if (incidents.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="text-center">No incidents</td></tr>`;
            return;
        }

        tbody.innerHTML = incidents.map(i => `
            <tr>
                <td>${i.severity || 'N/A'}</td>
                <td>${i.domain || 'N/A'}</td>
                <td>${i.title || 'N/A'}</td>
                <td>${i.detected || 'N/A'}</td>
                <td>${i.status || 'N/A'}</td>
                
            </tr>
        `).join('');
    } catch (error) {
        console.error('Error loading incidents:', error);
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