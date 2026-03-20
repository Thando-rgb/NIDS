# dashboard.py
# Web dashboard for the NIDS.
# Clean modern dark theme with live stats, charts and a table.
# Run this separately from nids.py.
# Open browser at http://localhost:5000 to view.

from flask import Flask, render_template_string
from config import LOG_FILE, DASHBOARD_PORT

app = Flask(__name__)

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="5">
    <title>NIDS Dashboard</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            background: #0f1117;
            color: #e0e0e0;
            font-family: 'Segoe UI', sans-serif;
            padding: 30px;
        }

        /* ── Header ── */
        .header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid #1e2130;
        }

        .header-left h1 {
            font-size: 1.6em;
            font-weight: 700;
            color: #ffffff;
            letter-spacing: 1px;
        }

        .header-left p {
            color: #555;
            font-size: 0.85em;
            margin-top: 4px;
        }

        .status-badge {
            background: #0d2b1f;
            border: 1px solid #00c853;
            color: #00c853;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 600;
            letter-spacing: 1px;
        }

        /* ── Stats Bar ── */
        .stats-bar {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 15px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: #161b27;
            border: 1px solid #1e2535;
            border-radius: 10px;
            padding: 18px 20px;
            display: flex;
            flex-direction: column;
            gap: 8px;
            transition: border-color 0.2s;
        }

        .stat-card:hover {
            border-color: #334;
        }

        .stat-label {
            font-size: 0.72em;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            color: #555;
            font-weight: 600;
        }

        .stat-value {
            font-size: 2em;
            font-weight: 700;
            line-height: 1;
        }

        .stat-sub {
            font-size: 0.75em;
            color: #444;
        }

        .val-red    { color: #ff4d4d; }
        .val-orange { color: #ff9800; }
        .val-blue   { color: #4da6ff; }
        .val-purple { color: #b388ff; }
        .val-green  { color: #00c853; }

        /* ── Chart and Table Row ── */
        .main-row {
            display: grid;
            grid-template-columns: 1fr 2fr;
            gap: 20px;
            margin-bottom: 25px;
        }

        /* ── Chart ── */
        .chart-card {
            background: #161b27;
            border: 1px solid #1e2535;
            border-radius: 10px;
            padding: 20px;
        }

        .card-title {
            font-size: 0.78em;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            color: #555;
            font-weight: 600;
            margin-bottom: 15px;
        }

        .chart-wrapper {
            position: relative;
            height: 220px;
        }

        /* ── Table ── */
        .table-card {
            background: #161b27;
            border: 1px solid #1e2535;
            border-radius: 10px;
            padding: 20px;
            overflow: hidden;
        }

        .table-wrapper {
            overflow-x: auto;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85em;
        }

        thead tr {
            border-bottom: 1px solid #1e2535;
        }

        th {
            text-align: left;
            padding: 10px 12px;
            font-size: 0.72em;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            color: #555;
            font-weight: 600;
        }

        td {
            padding: 10px 12px;
            border-bottom: 1px solid #111520;
            color: #ccc;
            vertical-align: middle;
        }

        tr:last-child td {
            border-bottom: none;
        }

        tr:hover td {
            background: #1a2030;
        }

        /* ── Severity Badge ── */
        .badge {
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.78em;
            font-weight: 600;
            display: inline-block;
        }

        .badge-alert {
            background: #2a0a0a;
            color: #ff4d4d;
            border: 1px solid #ff4d4d44;
        }

        .badge-info {
            background: #0a1a0a;
            color: #00c853;
            border: 1px solid #00c85344;
        }

        /* ── Attack type colour dots ── */
        .dot {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            margin-right: 6px;
        }

        .dot-portscan  { background: #ff4d4d; }
        .dot-synflood  { background: #ff9800; }
        .dot-pingsweep { background: #4da6ff; }
        .dot-info      { background: #00c853; }

        /* ── Footer ── */
        .footer {
            margin-top: 20px;
            color: #333;
            font-size: 0.75em;
            text-align: center;
        }
    </style>
</head>
<body>

    <!-- Header -->
    <div class="header">
        <div class="header-left">
            <h1>NIDS — Network Intrusion Detection System</h1>
            <p>Auto-refreshing every 5 seconds &nbsp;|&nbsp; Log: {{ log_file }}</p>
        </div>
        <div class="status-badge">LIVE MONITORING</div>
    </div>

    <!-- Stats Bar -->
    <div class="stats-bar">
        <div class="stat-card">
            <span class="stat-label">Total Alerts</span>
            <span class="stat-value val-red">{{ alert_count }}</span>
            <span class="stat-sub">Security events</span>
        </div>
        <div class="stat-card">
            <span class="stat-label">Port Scans</span>
            <span class="stat-value val-red">{{ port_scan_count }}</span>
            <span class="stat-sub">Detected</span>
        </div>
        <div class="stat-card">
            <span class="stat-label">SYN Floods</span>
            <span class="stat-value val-orange">{{ syn_flood_count }}</span>
            <span class="stat-sub">Detected</span>
        </div>
        <div class="stat-card">
            <span class="stat-label">Ping Sweeps</span>
            <span class="stat-value val-blue">{{ ping_sweep_count }}</span>
            <span class="stat-sub">Detected</span>
        </div>
        <div class="stat-card">
            <span class="stat-label">Total Events</span>
            <span class="stat-value val-green">{{ total_count }}</span>
            <span class="stat-sub">All log entries</span>
        </div>
    </div>

    <!-- Chart + Table Row -->
    <div class="main-row">

        <!-- Doughnut Chart -->
        <div class="chart-card">
            <div class="card-title">Attack Breakdown</div>
            <div class="chart-wrapper">
                <canvas id="attackChart"></canvas>
            </div>
        </div>

        <!-- Events Table -->
        <div class="table-card">
            <div class="card-title">Recent Events — Last 50</div>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Severity</th>
                            <th>Type</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for entry in entries %}
                        <tr>
                            <!-- Timestamp: first 19 characters of log line -->
                            <td style="white-space:nowrap; color:#555;">
                                {{ entry[:19] if entry|length > 19 else '—' }}
                            </td>

                            <!-- Severity badge -->
                            <td>
                                {% if 'ALERT' in entry or 'WARNING' in entry %}
                                    <span class="badge badge-alert">ALERT</span>
                                {% else %}
                                    <span class="badge badge-info">INFO</span>
                                {% endif %}
                            </td>

                            <!-- Attack type with colour dot -->
                            <td>
                                {% if 'Port scan' in entry %}
                                    <span class="dot dot-portscan"></span>Port Scan
                                {% elif 'SYN flood' in entry %}
                                    <span class="dot dot-synflood"></span>SYN Flood
                                {% elif 'Ping sweep' in entry %}
                                    <span class="dot dot-pingsweep"></span>Ping Sweep
                                {% else %}
                                    <span class="dot dot-info"></span>System
                                {% endif %}
                            </td>

                            <!-- Full details minus the timestamp prefix -->
                            <td style="color:#888;">
                                {{ entry[22:] if entry|length > 22 else entry }}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>

    </div>

    <div class="footer">
        NIDS Dashboard &nbsp;|&nbsp; Refreshes every 5 seconds
    </div>

    <!-- Chart.js Script -->
    <script>
        const ctx = document.getElementById('attackChart').getContext('2d');

        const portScans  = {{ port_scan_count }};
        const synFloods  = {{ syn_flood_count }};
        const pingSweeps = {{ ping_sweep_count }};
        const total = portScans + synFloods + pingSweeps;

        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Port Scans', 'SYN Floods', 'Ping Sweeps'],
                datasets: [{
                    data: total > 0
                        ? [portScans, synFloods, pingSweeps]
                        : [1, 1, 1],
                    backgroundColor: [
                        '#ff4d4d',
                        '#ff9800',
                        '#4da6ff'
                    ],
                    borderColor: '#0f1117',
                    borderWidth: 3,
                    hoverOffset: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '70%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#888',
                            padding: 15,
                            font: { size: 11 }
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                if (total === 0) return ' No attacks yet';
                                const val = context.parsed;
                                const pct = ((val / total) * 100).toFixed(1);
                                return ` ${context.label}: ${val} (${pct}%)`;
                            }
                        }
                    }
                }
            }
        });
    </script>

</body>
</html>
"""

@app.route("/")
def dashboard():
    try:
        with open(LOG_FILE, "r") as f:
            lines = [l.strip() for l in f.readlines() if l.strip()]

        entries = lines[-50:][::-1]

        alert_count      = sum(1 for e in entries if "WARNING" in e)
        port_scan_count  = sum(1 for e in entries if "Port scan" in e and "WARNING" in e)
        syn_flood_count  = sum(1 for e in entries if "SYN flood" in e and "WARNING" in e)
        ping_sweep_count = sum(1 for e in entries if ("Ping sweep" in e or "ARP sweep" in e) and "WARNING" in e)
        total_count      = len(entries)

    except FileNotFoundError:
        entries          = ["No log file found — start nids.py first"]
        alert_count      = 0
        port_scan_count  = 0
        syn_flood_count  = 0
        ping_sweep_count = 0
        total_count      = 0

    return render_template_string(
        DASHBOARD_HTML,
        entries=entries,
        alert_count=alert_count,
        port_scan_count=port_scan_count,
        syn_flood_count=syn_flood_count,
        ping_sweep_count=ping_sweep_count,
        total_count=total_count,
        log_file=LOG_FILE
    )

if __name__ == "__main__":
    print(f"[INFO] Dashboard running at http://localhost:{DASHBOARD_PORT}")
    app.run(debug=True, port=DASHBOARD_PORT)