const SEVERITY_COLORS = {
    'Critical': '#dc3545',
    'High': '#fd7e14',
    'Medium': '#ffc107',
    'Low': '#0dcaf0',
    'Info': '#6c757d',
};

function renderSeverityPie(canvasId, data) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    const labels = Object.keys(data);
    const values = Object.values(data);
    const colors = labels.map(l => SEVERITY_COLORS[l] || '#999');

    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: colors,
                borderWidth: 2,
                borderColor: '#fff',
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'bottom' },
            }
        }
    });
}

function renderTopVulnsBar(canvasId, vulns) {
    const ctx = document.getElementById(canvasId);
    if (!ctx || !vulns.length) return;

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: vulns.map(v => v.name),
            datasets: [{
                label: 'CVSS Score',
                data: vulns.map(v => v.cvss_score),
                backgroundColor: vulns.map(v => SEVERITY_COLORS[v.severity] || '#999'),
                borderWidth: 1,
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            scales: {
                x: { min: 0, max: 10, title: { display: true, text: 'CVSS Score' } }
            },
            plugins: {
                legend: { display: false },
            }
        }
    });
}
