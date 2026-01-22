char * tsdb_ui_html = (char *) R"HTML(
<!DOCTYPE html>
<html>
<head>
    <title>ProxySQL TSDB Dashboard</title>
    <link rel="stylesheet" href="/main-bundle.min.css"/>
    <link rel="stylesheet" href="/font-awesome.min.css"/>
    <script src="/Chart.bundle.js"></script>
    <style>
        body { font-family: 'Source Sans Pro', sans-serif; background: #f4f7f6; margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .chart-card { background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); padding: 20px; margin-bottom: 20px; }
        h1 { color: #2969a5; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>ProxySQL Observability Dashboard</h1>
        <div class="grid">
            <div class="chart-card">
                <h3>Total Queries (QPS)</h3>
                <canvas id="qpsChart"></canvas>
            </div>
            <div class="chart-card">
                <h3>Query Latency (ms)</h3>
                <canvas id="latencyChart"></canvas>
            </div>
            <div class="chart-card">
                <h3>Client Connections</h3>
                <canvas id="connChart"></canvas>
            </div>
            <div class="chart-card">
                <h3>Memory Usage (MB)</h3>
                <canvas id="memChart"></canvas>
            </div>
        </div>
    </div>
    <script>
        function fetchData(metric, elementId, label) {
            const to = Date.now();
            const from = to - 3600000; // Last 1 hour
            fetch(`/api/tsdb/query?metric=${metric}&from=${from}&to=${to}`)
                .then(r => r.json())
                .then(data => {
                    if (!data.series || data.series.length === 0) return;
                    const ctx = document.getElementById(elementId).getContext('2d');
                    const points = data.series[0].points;
                    new Chart(ctx, {
                        type: 'line',
                        data: {
                            labels: points.map(p => new Date(p[0]).toLocaleTimeString()),
                            datasets: [{
                                label: label,
                                data: points.map(p => p[1]),
                                borderColor: '#2969a5',
                                fill: false
                            }]
                        },
                        options: { scales: { yAxes: [{ ticks: { beginAtZero: true } }] } }
                    });
                });
        }
        
        fetchData('proxysql_queries_total', 'qpsChart', 'Queries');
        fetchData('proxysql_query_latency_ms', 'latencyChart', 'Latency p95');
        fetchData('proxysql_frontend_connections', 'connChart', 'Connections');
        fetchData('proxysql_memory_bytes', 'memChart', 'Memory RSS');
    </script>
</body>
</html>
)HTML";
