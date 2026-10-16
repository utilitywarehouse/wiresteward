package api

// LeaseRequest defines the payload of a lease HTTP request submitted by an
// agent.
type LeaseRequest struct {
	PubKey string
}

// LeaseResponse define the payload of a lease HTTP response returned by a
// server.
type LeaseResponse struct {
	Status            string
	IP                string
	ServerWireguardIP string
	AllowedIPs        []string
	PubKey            string
	Endpoint          string
}
