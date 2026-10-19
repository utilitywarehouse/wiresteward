package agent

import "time"

// Status is a snapshot of the agent state.
type Status struct {
	Token   TokenStatus    `json:"token"`
	Devices []DeviceStatus `json:"devices"`
}

// TokenStatus describes the oauth token.
type TokenStatus struct {
	Present bool      `json:"present"`
	Active  bool      `json:"active"`
	Expiry  time.Time `json:"expiry"`
}

// DeviceStatus describes a configured device and the lease applied to it.
type DeviceStatus struct {
	Name          string   `json:"name"`
	Connected     bool     `json:"connected"`
	HealthChecked bool     `json:"healthChecked"`
	Healthy       bool     `json:"healthy"`
	Address       string   `json:"address,omitempty"`
	Routes        []string `json:"routes,omitempty"`
}

// Status returns the current token and device state.
func (a *Agent) Status() Status {
	var st Status
	token, refreshed, err := a.oa.GetToken()
	if err == nil {
		if refreshed {
			a.renewAllLeases(token.AccessToken)
		}
		st.Token = TokenStatus{
			Present: true,
			Active:  token.Expiry.After(time.Now()),
			Expiry:  token.Expiry,
		}
	}
	st.Devices = []DeviceStatus{}
	for _, dm := range a.deviceManagers {
		d := DeviceStatus{Name: dm.Name(), HealthChecked: dm.IsHealthChecked()}
		if cfg := dm.Config(); cfg != nil {
			d.Connected = true
			d.Healthy = dm.Healthy()
			d.Address = cfg.LocalAddress.String()
			for _, ip := range cfg.AllowedIPs {
				d.Routes = append(d.Routes, ip.String())
			}
		}
		st.Devices = append(st.Devices, d)
	}
	return st
}
