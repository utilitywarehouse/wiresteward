package main

import (
	"html/template"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

const timeFmt = "Mon Jan 2 15:04:05"

var htmlStatusTemplate = `
<!doctype html>
<html>
<style>
.styled-table {
    border-collapse: collapse;
    margin: 25px 0;
    font-size: 0.9em;
    font-family: sans-serif;
    min-width: 400px;
    box-shadow: 0 0 20px rgba(0, 0, 0, 0.15);
}
.styled-table thead tr {
    background-color: #009879;
    color: #ffffff;
    text-align: left;
}
.styled-table th,
.styled-table td {
    padding: 12px 15px;
}
.styled-table tbody tr {
    border-bottom: 1px solid #dddddd;
}
.styled-table tbody tr:nth-of-type(even) {
    background-color: #f3f3f3;
}
.styled-table tbody tr:last-of-type {
    border-bottom: 2px solid #009879;
}
.styled-table tbody tr.active-row {
    font-weight: bold;
    color: #009879;
}
</style>
<head>
  <meta charset="utf-8">
  <title>Wiresteward Agent Status</title>
</head>
<body>
    <h2 class="text-center">Wiresteward Agent Status</h2>
    <div>
      <h3 class="text-left">Token Info</h2>
      {{ if .TokenMissing }}
        <p>No token found, please hit Renew button below.</p>
      {{else}}
        {{ if .TokenActive }}
          <p><b style="color:green;">Active</b><b> until: {{.TokenExpiry}}</b></p>
	{{else}}
          <p><b style="color:red;">Expired</b><b> since: {{.TokenExpiry}}</b></p>
	  <p>Please use renew button bellow.</p>
	{{end}}
      {{end}}
      <i>Fetches a new token before renewing leases.</i>
      <form action="/renew" method="get">
        <button type="submit">Renew</button>
      </form>
    </div>
    <div>
      <h3 class="text-left">Routes Info</h2>
      <i>Last update at: {{.Time}}.</i>
      <form action="/" method="get">
        <button type="submit">Refresh</button>
      </form>
      <table class="styled-table">
          <caption>Route Map</caption>
          <thead>
            <tr>
              {{range .RouteTableHeaders}}
                <th>{{.}}</th>
              {{end}}
            </tr>
          </thead>
          <tbody>
          {{range .Routes}}<tr>
            <td>{{.Device}}</td>
            <td>{{.Dst}}</td>
            <td>{{.GW}}</td>
	    {{ if .IsHealthChecked }}
              {{ if .Healthy }}
              <td style="color:green;">ok</td>
              {{else}}
              <td style="color:red;">unhealthy</td>
              {{end}}
	    {{else}}
	      <td>N/A</td>
	    {{end}}
          {{end}}</tr>
          </tbody>
      </table>
    </div>
</body>
</html>
`

type httpRoute struct {
	Device          string
	Dst             string
	GW              string
	IsHealthChecked bool
	Healthy         bool
}
type httpStatus struct {
	Time              string
	TokenMissing      bool
	TokenActive       bool
	TokenExpiry       string
	RouteTableHeaders []string
	Routes            []httpRoute
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

	status.RouteTableHeaders = []string{"Device", "Subnet", "Gateway", "Health"}
	routes := []httpRoute{}
	for _, dm := range deviceManagers {
		if dm.config != nil {
			for _, ip := range dm.config.AllowedIPs {
				r := httpRoute{
					Device:          dm.Name(),
					Dst:             ip.String(),
					GW:              dm.config.LocalAddress.String(),
					IsHealthChecked: dm.isHealthChecked(),
					Healthy:         dm.healthCheck.healthy,
				}
				routes = append(routes, r)
			}
		}
	}
	status.Routes = routes

	tmpl, err := template.New("status").Parse(htmlStatusTemplate)
	if err != nil {
		logger.Errorf("Failed to parse template: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	err = tmpl.Execute(w, status)
	if err != nil {
		logger.Errorf("Failed to write template: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}
