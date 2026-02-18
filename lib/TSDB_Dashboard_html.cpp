const char * TSDB_Dashboard_html_c = R"HTML(
<!DOCTYPE html>
<html>
<head>
    <title>ProxySQL TSDB Dashboard</title>
    <script src="/Chart.bundle.js"></script>
    <style>
        body { font-family: sans-serif; margin: 20px; background-color: #f9f9f9; }
        .container { max-width: 1100px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #eee; padding-bottom: 10px; }
        .controls { margin-bottom: 20px; padding: 15px; background: #f5f5f5; border-radius: 5px; display: flex; align-items: center; }
        .control-group { margin-right: 20px; }
        label { font-weight: bold; margin-right: 5px; }
        select, input, button { padding: 8px; border: 1px solid #ccc; border-radius: 4px; }
        button { background-color: #007bff; color: white; border: none; cursor: pointer; transition: background 0.2s; }
        button:hover { background-color: #0056b3; }
        #chart-container { height: 600px; position: relative; margin-top: 20px; }
        .footer { margin-top: 30px; font-size: 0.8em; color: #888; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h1>ProxySQL TSDB Dashboard</h1>
        <div class="controls">
            <div class="control-group">
                <label for="metric-select">Metric:</label>
                <select id="metric-select"><option>Loading...</option></select>
            </div>
            <div class="control-group">
                <label for="range-select">Range:</label>
                <select id="range-select">
                    <option value="3600">Last Hour</option>
                    <option value="14400">Last 4 Hours</option>
                    <option value="86400" selected>Last Day</option>
                    <option value="604800">Last Week</option>
                    <option value="2592000">Last Month</option>
                </select>
            </div>
            <button onclick="loadData()">Refresh</button>
        </div>
        <div id="chart-container">
            <canvas id="tsdbChart"></canvas>
        </div>
        <div class="footer">
            Powered by ProxySQL Embedded TSDB & Chart.js
        </div>
    </div>

    <script>
        let myChart = null;

        async function loadMetrics() {
            try {
                const resp = await fetch('/api/tsdb/metrics');
                if (!resp.ok) throw new Error('Failed to fetch metrics');
                const metrics = await resp.json();
                const select = document.getElementById('metric-select');
                select.innerHTML = '';
                metrics.sort().forEach(m => {
                    const opt = document.createElement('option');
                    opt.value = m;
                    opt.text = m;
                    if (m === 'proxysql_uptime_seconds_total') opt.selected = true;
                    select.appendChild(opt);
                });
                if (metrics.length > 0) loadData();
            } catch (err) {
                console.error(err);
                document.getElementById('metric-select').innerHTML = '<option>Error loading metrics</option>';
            }
        }

        async function loadData() {
            const metric = document.getElementById('metric-select').value;
            const range = document.getElementById('range-select').value;
            const now = Math.floor(Date.now() / 1000);
            const from = now - parseInt(range);

            try {
                const resp = await fetch(`/api/tsdb/query?metric=${encodeURIComponent(metric)}&from=${from}&to=${now}`);
                if (!resp.ok) throw new Error('Query failed');
                const data = await resp.json();
                
                const ctx = document.getElementById('tsdbChart').getContext('2d');
                if (myChart) myChart.destroy();

                if (!data || data.length === 0) {
                    ctx.clearRect(0, 0, ctx.canvas.width, ctx.canvas.height);
                    ctx.font = "20px Arial";
                    ctx.textAlign = "center";
                    ctx.fillText("No data available for selected range", ctx.canvas.width/2, ctx.canvas.height/2);
                    return;
                }

                const datasets = {};
                const colors = [
                    '#3498db', '#e74c3c', '#2ecc71', '#f1c40f', '#9b59b6', 
                    '#1abc9c', '#e67e22', '#34495e', '#95a5a6', '#d35400'
                ];
                let colorIdx = 0;

                data.forEach(d => {
                    const label = Object.keys(d.labels).length > 0 ? JSON.stringify(d.labels) : 'default';
                    if (!datasets[label]) {
                        datasets[label] = {
                            label: label,
                            data: [],
                            borderColor: colors[colorIdx % colors.length],
                            backgroundColor: colors[colorIdx % colors.length] + '22',
                            fill: false,
                            tension: 0.1,
                            pointRadius: 2
                        };
                        colorIdx++;
                    }
                    datasets[label].data.push({ x: d.ts * 1000, y: d.value });
                });

                myChart = new Chart(ctx, {
                    type: 'line',
                    data: { datasets: Object.values(datasets) },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            xAxes: [{
                                type: 'time',
                                time: {
                                    displayFormats: {
                                        minute: 'HH:mm',
                                        hour: 'HH:mm',
                                        day: 'MMM D HH:mm'
                                    }
                                },
                                scaleLabel: { display: true, labelString: 'Time' }
                            }],
                            yAxes: [{
                                scaleLabel: { display: true, labelString: 'Value' },
                                ticks: { beginAtZero: false }
                            }]
                        },
                        tooltips: {
                            mode: 'index',
                            intersect: false
                        },
                        hover: {
                            mode: 'nearest',
                            intersect: true
                        }
                    }
                });
            } catch (err) {
                console.error(err);
            }
        }

        window.onload = loadMetrics;
    </script>
</body>
</html>
)HTML";
