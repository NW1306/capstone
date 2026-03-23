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
                <td>
                    <button class="btn btn-sm btn-success" onclick="resolveAlert(${alert.id})">
                        <i class="bi bi-check"></i> Resolve
                    </button>
                </td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Error loading alerts:', error);
    }
}

async function loadTimelineData() {
    try {
        const data = await fetchJson('/api/charts/timeline?days=30');
        const dates = data.dates || [];
        const passed = data.passed || [];
        const failed = data.failed || [];

        const timelineCanvas = document.getElementById('timelineChart');
        const passRateCanvas = document.getElementById('passRateChart');

        if (timelineCanvas) {
            if (timelineChart) timelineChart.destroy();

            timelineChart = new Chart(timelineCanvas.getContext('2d'), {
                type: 'line',
                data: {
                    labels: dates,
                    datasets: [
                        {
                            label: 'Failed',
                            data: failed,
                            borderColor: '#dc3545',
                            backgroundColor: 'rgba(220, 53, 69, 0.1)',
                            tension: 0.4
                        },
                        {
                            label: 'Passed',
                            data: passed,
                            borderColor: '#198754',
                            backgroundColor: 'rgba(25, 135, 84, 0.1)',
                            tension: 0.4
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'top' }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Number of Emails'
                            }
                        }
                    }
                }
            });
        }

        if (passRateCanvas) {
            const totalPassed = passed.reduce((a, b) => a + b, 0);
            const totalFailed = failed.reduce((a, b) => a + b, 0);

            if (passRateChart) passRateChart.destroy();

            passRateChart = new Chart(passRateCanvas.getContext('2d'), {
                type: 'doughnut',
                data: {
                    labels: ['Passed', 'Failed'],
                    datasets: [{
                        data: [totalPassed, totalFailed],
                        backgroundColor: ['#198754', '#dc3545'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'bottom' }
                    }
                }
            });
        }
    } catch (error) {
        console.error('Error loading timeline data:', error);
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
                <td>
                    ${(i.status || '').toLowerCase() === 'resolved'
                        ? '<span class="badge bg-success">Resolved</span>'
                        : `<button class="btn btn-sm btn-warning" onclick="resolveIncident(${i.id})">Resolve</button>`
                    }
                </td>
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