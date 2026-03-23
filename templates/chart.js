async function fetchChartData(url) {
    const response = await fetch(url);

    if (!response.ok) {
        throw new Error(`Failed to fetch ${url}: ${response.status}`);
    }

    return await response.json();
}

let severityChartInstance = null;
let trendChartInstance = null;
let authFailureChartInstance = null;
let domainChartInstance = null;
let ipChartInstance = null;

// ===================== SEVERITY CHART =====================
async function loadSeverityChart() {
    const data = await fetchChartData('/api/chart/classification');
    const canvas = document.getElementById('severityChart');
    if (!canvas) return;

    if (severityChartInstance) {
        severityChartInstance.destroy();
    }

    severityChartInstance = new Chart(canvas, {
        type: 'doughnut',
        data: {
            labels: data.labels || ['Low', 'Medium', 'High'],
            datasets: [{
                label: 'Severity Count',
                data: data.values || [0, 0, 0],
                backgroundColor: ['#4ade80', '#facc15', '#f87171']
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });
}

// ===================== TREND CHART =====================
async function loadTrendChart() {
    const data = await fetchChartData('/api/chart/trends');
    const canvas = document.getElementById('trendChart');
    if (!canvas) return;

    if (trendChartInstance) {
        trendChartInstance.destroy();
    }

    trendChartInstance = new Chart(canvas, {
        type: 'line',
        data: {
            labels: data.labels || [],
            datasets: [{
                label: 'Incidents Over Time',
                data: data.values || [],
                fill: false,
                tension: 0.3,
                borderColor: '#3b82f6',
                backgroundColor: '#3b82f6'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

// ===================== AUTH FAILURE CHART =====================
async function loadAuthFailureChart() {
    const data = await fetchChartData('/api/chart/auth-failures');
    const canvas = document.getElementById('authFailureChart');
    if (!canvas) return;

    if (authFailureChartInstance) {
        authFailureChartInstance.destroy();
    }

    authFailureChartInstance = new Chart(canvas, {
        type: 'bar',
        data: {
            labels: data.labels || ['Fail', 'Softfail', 'None'],
            datasets: [{
                label: 'Failure Count',
                data: data.values || [0, 0, 0],
                backgroundColor: ['#ef4444', '#f59e0b', '#6b7280']
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

// ===================== DOMAIN CHART =====================
async function loadDomainChart() {
    const data = await fetchChartData('/api/chart/top-domains');
    const canvas = document.getElementById('domainChart');
    if (!canvas) return;

    if (domainChartInstance) {
        domainChartInstance.destroy();
    }

    domainChartInstance = new Chart(canvas, {
        type: 'bar',
        data: {
            labels: data.labels || [],
            datasets: [{
                label: 'Incident Count by Domain',
                data: data.values || [],
                backgroundColor: '#3b82f6'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',
            scales: {
                x: {
                    beginAtZero: true
                }
            }
        }
    });
}

// ===================== IP CHART =====================
async function loadIpChart() {
    const data = await fetchChartData('/api/chart/top-ips');
    const canvas = document.getElementById('ipChart');
    if (!canvas) return;

    if (ipChartInstance) {
        ipChartInstance.destroy();
    }

    ipChartInstance = new Chart(canvas, {
        type: 'bar',
        data: {
            labels: data.labels || [],
            datasets: [{
                label: 'Incident Count by IP',
                data: data.values || [],
                backgroundColor: '#10b981'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',
            scales: {
                x: {
                    beginAtZero: true
                }
            }
        }
    });
}

// ===================== LOAD ALL =====================
async function loadAllCharts() {
    try { await loadSeverityChart(); } catch (e) { console.error('Severity chart failed:', e); }
    try { await loadTrendChart(); } catch (e) { console.error('Trend chart failed:', e); }
    try { await loadAuthFailureChart(); } catch (e) { console.error('Auth failure chart failed:', e); }
    try { await loadDomainChart(); } catch (e) { console.error('Domain chart failed:', e); }
    try { await loadIpChart(); } catch (e) { console.error('IP chart failed:', e); }
}

document.addEventListener('DOMContentLoaded', loadAllCharts);