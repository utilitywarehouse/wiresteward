package main

import (
	"encoding/json"
	"html/template"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

const timeFmt = "Mon Jan 2 15:04:05"

var htmlStatusTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Wiresteward Agent</title>
  <style>
    :root {
      --bg:         #f0f4f8;
      --card:       #ffffff;
      --border:     #e2e8f0;
      --text:       #1a202c;
      --muted:      #718096;
      --green:      #276749;
      --green-bg:   #f0fff4;
      --red:        #c53030;
      --red-bg:     #fff5f5;
      --accent:     #3182ce;
      --th-bg:      #2d3748;
      --th-fg:      #edf2f7;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                   "Helvetica Neue", sans-serif;
      background: var(--bg);
      color: var(--text);
      padding: 2rem;
      line-height: 1.5;
    }
    h1 { font-size: 1.4rem; font-weight: 700; color: var(--text); margin-bottom: 1.75rem; }
    .layout { display: grid; grid-template-columns: 300px 1fr; gap: 1.25rem; align-items: start; }
    @media (max-width: 700px) { .layout { grid-template-columns: 1fr; } }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.25rem 1.5rem;
      box-shadow: 0 1px 4px rgba(0,0,0,0.06);
    }
    .card-label {
      font-size: 0.7rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.07em;
      color: var(--muted);
      margin-bottom: 0.85rem;
    }
    .status-row { display: flex; align-items: center; gap: 0.55rem; margin-bottom: 0.3rem; }
    .dot { width: 9px; height: 9px; border-radius: 50%; flex-shrink: 0; }
    .dot-green { background: #38a169; }
    .dot-red   { background: #e53e3e; }
    .dot-grey  { background: #a0aec0; }
    .status-label { font-size: 1rem; font-weight: 600; }
    .status-sub { font-size: 0.8rem; color: var(--muted); margin-bottom: 1rem; }
    .btn {
      display: inline-block;
      padding: 0.38rem 0.9rem;
      border-radius: 6px;
      border: none;
      font-size: 0.82rem;
      font-weight: 600;
      cursor: pointer;
      text-decoration: none;
      background: var(--accent);
      color: #fff;
    }
    .btn:hover { filter: brightness(0.9); }
    .routes-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 0.85rem;
    }
    .refresh-note { font-size: 0.75rem; color: var(--muted); }
    #countdown { color: var(--accent); font-weight: 600; }
    table { width: 100%; border-collapse: collapse; font-size: 0.855rem; }
    thead tr { background: var(--th-bg); color: var(--th-fg); }
    th { padding: 0.6rem 0.9rem; font-weight: 600; text-align: left; }
    td { padding: 0.6rem 0.9rem; }
    tbody tr { border-bottom: 1px solid var(--border); }
    tbody tr:last-child { border-bottom: none; }
    tbody tr:hover { background: #f7fafc; }
    .badge {
      display: inline-flex; align-items: center; gap: 0.3rem;
      font-size: 0.78rem; font-weight: 600;
      padding: 0.18rem 0.55rem; border-radius: 999px;
    }
    .badge-green { color: var(--green); background: var(--green-bg); }
    .badge-red   { color: var(--red);   background: var(--red-bg); }
    .badge-grey  { color: var(--muted); background: #edf2f7; }
    #routes-body tr { animation: fadeIn 0.25s ease; }
    @keyframes fadeIn { from { opacity: 0.3; } to { opacity: 1; } }
  </style>
</head>
<body>
  <h1>Wiresteward Agent</h1>
  <div class="layout">

    <div class="card">
      <div class="card-label">Token</div>
      {{ if .TokenMissing }}
        <div class="status-row">
          <span class="dot dot-grey"></span>
          <span class="status-label">No token</span>
        </div>
        <p class="status-sub">Authenticate to get started.</p>
      {{ else if .TokenActive }}
        <div class="status-row">
          <span class="dot dot-green"></span>
          <span class="status-label">Active</span>
        </div>
        <p class="status-sub">Expires: {{.TokenExpiry}}</p>
      {{ else }}
        <div class="status-row">
          <span class="dot dot-red"></span>
          <span class="status-label">Expired</span>
        </div>
        <p class="status-sub">Since: {{.TokenExpiry}}</p>
      {{ end }}
      <a class="btn" href="/renew">Renew token</a>
    </div>

    <div class="card">
      <div class="routes-header">
        <div class="card-label" style="margin-bottom:0">Routes</div>
        <span class="refresh-note">
          Refreshes in <span id="countdown">5</span>s &nbsp;·&nbsp;
          Last updated: <span id="last-updated">{{.Time}}</span>
        </span>
      </div>
      <table>
        <thead>
          <tr><th>Device</th><th>Subnet</th><th>Gateway</th><th>Health</th></tr>
        </thead>
        <tbody id="routes-body">
          {{range .Routes}}
          <tr>
            <td>{{.Device}}</td>
            <td>{{.Dst}}</td>
            <td>{{.GW}}</td>
            <td>
              {{if .IsHealthChecked}}
                {{if .Healthy}}
                  <span class="badge badge-green">&#9679; ok</span>
                {{else}}
                  <span class="badge badge-red">&#9679; unhealthy</span>
                {{end}}
              {{else}}
                <span class="badge badge-grey">N/A</span>
              {{end}}
            </td>
          </tr>
          {{end}}
        </tbody>
      </table>
    </div>

  </div>
  <script>
    const INTERVAL = 5;
    let remaining = INTERVAL;

    function esc(s) {
      return String(s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function badge(r) {
      if (!r.is_health_checked) return '<span class="badge badge-grey">N/A</span>';
      return r.healthy
        ? '<span class="badge badge-green">&#9679; ok</span>'
        : '<span class="badge badge-red">&#9679; unhealthy</span>';
    }

    async function refreshRoutes() {
      try {
        const resp = await fetch('/api/status');
        if (!resp.ok) return;
        const data = await resp.json();
        document.getElementById('routes-body').innerHTML =
          (data.routes || []).map(r =>
            '<tr><td>' + esc(r.device) + '</td><td>' + esc(r.dst) +
            '</td><td>' + esc(r.gw) + '</td><td>' + badge(r) + '</td></tr>'
          ).join('');
        document.getElementById('last-updated').textContent = data.time;
      } catch (_) {}
      remaining = INTERVAL;
    }

    setInterval(function() {
      remaining--;
      document.getElementById('countdown').textContent = remaining;
      if (remaining <= 0) refreshRoutes();
    }, 1000);
  </script>
</body>
</html>
`

type httpRoute struct {
	Device          string `json:"device"`
	Dst             string `json:"dst"`
	GW              string `json:"gw"`
	IsHealthChecked bool   `json:"is_health_checked"`
	Healthy         bool   `json:"healthy"`
}

type httpStatus struct {
	Time         string
	TokenMissing bool
	TokenActive  bool
	TokenExpiry  string
	Routes       []httpRoute
}

type jsonRoutesResponse struct {
	Time   string      `json:"time"`
	Routes []httpRoute `json:"routes"`
}

func buildRoutes(deviceManagers []*DeviceManager) []httpRoute {
	routes := []httpRoute{}
	for _, dm := range deviceManagers {
		if dm.config != nil {
			for _, ip := range dm.config.AllowedIPs {
				routes = append(routes, httpRoute{
					Device:          dm.Name(),
					Dst:             ip.String(),
					GW:              dm.config.LocalAddress.String(),
					IsHealthChecked: dm.isHealthChecked(),
					Healthy:         dm.healthCheck.healthy,
				})
			}
		}
	}
	return routes
}

func statusHTTPWriter(w http.ResponseWriter, r *http.Request, deviceManagers []*DeviceManager, token *oauth2.Token) {
	status := httpStatus{
		Time:         time.Now().Format(timeFmt),
		TokenMissing: true,
		TokenActive:  true,
	}
	if token != nil {
		status.TokenMissing = false
		if token.Expiry.Before(time.Now()) {
			status.TokenActive = false
		}
		status.TokenExpiry = token.Expiry.Format(timeFmt)
	}
	status.Routes = buildRoutes(deviceManagers)

	tmpl, err := template.New("status").Parse(htmlStatusTemplate)
	if err != nil {
		logger.Errorf("Failed to parse template: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err = tmpl.Execute(w, status); err != nil {
		logger.Errorf("Failed to write template: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func statusJSONWriter(w http.ResponseWriter, deviceManagers []*DeviceManager) {
	resp := jsonRoutesResponse{
		Time:   time.Now().Format(timeFmt),
		Routes: buildRoutes(deviceManagers),
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		logger.Errorf("Failed to encode status JSON: %v", err)
	}
}
