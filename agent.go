package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Agent struct {
	device        string
	pubKey        string
	privKey       string
	netlinkHandle *netlinkHandle
	tokenHandler  *OauthTokenHandler
	stop          chan bool
	tundev        *TunDevice
}

// NewAgent: Creates an agent associated with a net device
func NewAgent(deviceName string, tHandler *OauthTokenHandler) (*Agent, error) {
	a := &Agent{
		tokenHandler: tHandler,
	}
	a.netlinkHandle = NewNetLinkHandle()

	a.device = deviceName
	stop := make(chan bool)
	tundev, err := startTunDevice(deviceName, stop)
	if err != nil {
		return a, fmt.Errorf("Error starting wg device: %s: %v", deviceName, err)
	}

	a.stop = stop
	a.tundev = tundev

	go a.tundev.Run()

	// Bring device up
	if err := a.netlinkHandle.EnsureLinkUp(deviceName); err != nil {
		return a, err
	}

	// Check if there is a private key or generate one
	_, privKey, err := getKeys(deviceName)
	if err != nil {
		return a, fmt.Errorf("Cannot get keys for device: %s: %v", deviceName, err)
	}
	// the base64 value of an empty key will come as
	// AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
	if privKey == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" {
		newKey, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return a, err
		}
		a.privKey = newKey.String()
		if err := a.SetPrivKey(); err != nil {
			return a, err
		}
	}

	// Fetch keys from interface and save them
	a.pubKey, a.privKey, err = getKeys(deviceName)
	if err != nil {
		return a, err
	}

	return a, nil
}

func (a *Agent) requestWgConfig(serverUrl string) (*Response, error) {
	// Marshal key int json
	r, err := json.Marshal(&Request{PubKey: a.pubKey})
	if err != nil {
		return &Response{}, err
	}

	// Get a token
	token, err := a.tokenHandler.GetToken()
	if err != nil {
		return &Response{}, err
	}

	// Prepare the request
	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/newPeerLease", serverUrl),
		bytes.NewBuffer(r),
	)
	req.Header.Set("Content-Type", "application/json")

	var bearer = "Bearer " + token
	req.Header.Set("Authorization", bearer)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return &Response{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return &Response{}, fmt.Errorf(
			"Response status: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return &Response{}, fmt.Errorf(
			"error reading response body: %s,", err.Error())
	}

	response := &Response{}
	if err := json.Unmarshal(body, response); err != nil {
		return response, err
	}

	return response, nil

}

func (a *Agent) SetPrivKey() error {
	return setPrivateKey(a.device, a.privKey)
}

func (a *Agent) addIpToDev(ip string) error {
	devIP, err := netlink.ParseIPNet(ip)
	if err != nil {
		return fmt.Errorf("Cannot parse offered ip net: %v", err)
	}
	fmt.Printf(
		"Configuring offered ip: %v on dev: %s\n",
		devIP,
		a.device,
	)
	if err := a.netlinkHandle.UpdateIP(a.device, devIP); err != nil {
		return err
	}
	return nil
}

func (a *Agent) addRoutesForAllowedIps(allowed_ips []string) error {
	for _, aip := range allowed_ips {
		dst, err := netlink.ParseIPNet(aip)
		if err != nil {
			return err
		}

		fmt.Printf("Adding route: %v on dev %s\n", dst, a.device)
		if err := a.netlinkHandle.AddRoute(a.device, dst); err != nil {
			return err
		}
	}
	return nil
}

func (a *Agent) setNewPeer(pubKey, endpoint string, allowed_ips []string) error {
	peer, err := newPeerConfig(pubKey, "", endpoint, allowed_ips)
	if err != nil {
		return err
	}

	if err := setPeers(a.device, []wgtypes.PeerConfig{*peer}); err != nil {
		return err
	}
	return nil
}

// GetNewWgLease: talks to the peer server to ask for a new lease
func (a *Agent) GetNewWgLease(serverUrl string) error {
	resp, err := a.requestWgConfig(serverUrl)
	if err != nil {
		return err
	}

	if err := a.addIpToDev(resp.IP); err != nil {
		return err
	}

	allowed_ips := strings.Split(resp.AllowedIPs, ",")
	if err := a.setNewPeer(resp.PubKey, resp.Endpoint, allowed_ips); err != nil {
		return err
	}

	if err := a.addRoutesForAllowedIps(allowed_ips); err != nil {
		return err
	}

	return nil
}

func (a *Agent) Stop() {
	a.stop <- true
}
