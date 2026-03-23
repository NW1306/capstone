async function fetchChartData(url) {
    const response = await fetch(url);

    if (!response.ok) {
        throw new Error(`Failed to fetch ${url}`);
    }

    return await response.json();
}

// ===================== SEVERITY =====================
async function loadSeverityChart() {
    const data = await fetchChartData('/api/chart/classification');

    new Chart(document.getElementById('severityChart'), {
        type: 'doughnut',
        data: {
            labels: data.labels,
            datasets: [{
                label: 'Severity Count',
                data: data.values
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });
}

// ===================== TREND =====================
async function loadTrendChart() {
    const data = await fetchChartData('/api/chart/trends');

    new Chart(document.getElementById('trendChart'), {
        type: 'line',
        data: {
            labels: data.labels,
            datasets: [{
                label: 'Incidents Over Time',
                data: data.values,
                fill: false,
                tension: 0.3
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: { beginAtZero: true }
            }
        }
    });
}

// ===================== AUTH FAILURES =====================
async function loadAuthFailureChart() {
    const data = await fetchChartData('/api/chart/auth-failures');

    new Chart(document.getElementById('authFailureChart'), {
        type: 'bar',
        data: {
            labels: data.labels,
            datasets: [{
                label: 'Failure Count',
                data: data.values
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: { beginAtZero: true }
            }
        }
    });
}

// ===================== DOMAINS =====================
async function loadDomainChart() {
    const data = await fetchChartData('/api/chart/top-domains');

    new Chart(document.getElementById('domainChart'), {
        type: 'bar',
        data: {
            labels: data.labels,
            datasets: [{
                label: 'Incident Count by Domain',
                data: data.values
            }]
        },
        options: {
            responsive: true,
            indexAxis: 'y',
            scales: {
                x: { beginAtZero: true }
            }
        }
    });
}

// ===================== IPs =====================
async function loadIpChart() {
    const data = await fetchChartData('/api/chart/top-ips');

    new Chart(document.getElementById('ipChart'), {
        type: 'bar',
        data: {
            labels: data.labels,
            datasets: [{
                label: 'Incident Count by IP',
                data: data.values
            }]
        },
        options: {
            responsive: true,
            indexAxis: 'y',
            scales: {
                x: { beginAtZero: true }
            }
        }
    });
}

// ===================== SAFE LOADING =====================
document.addEventListener('DOMContentLoaded', async () => {
    try { await loadSeverityChart(); } catch (e) { console.error('Severity chart failed:', e); }
    try { await loadTrendChart(); } catch (e) { console.error('Trend chart failed:', e); }
    try { await loadAuthFailureChart(); } catch (e) { console.error('Auth chart failed:', e); }
    try { await loadDomainChart(); } catch (e) { console.error('Domain chart failed:', e); }
    try { await loadIpChart(); } catch (e) { console.error('IP chart failed:', e); }
});