package api

// LeaseRequest defines the payload of a lease HTTP request submitted by an
// agent.
type LeaseRequest struct {
	PubKey string
	// DeviceID optionally identifies the installation of the agent that
	// sends the request, a UUID that it keeps on disk. Servers keep a
	// separate lease per user and device id. Requests without one share a
	// single lease per user.
	DeviceID string `json:",omitempty"`
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
