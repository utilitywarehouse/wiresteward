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
	device        netlink.Link
	pubKey        string
	privKey       string
	netlinkHandle *netlinkHandle
	tokenHandler  *OauthTokenHandler
}

func NewAgent(deviceName string, tHandler *OauthTokenHandler) (*Agent, error) {
	a := &Agent{
		tokenHandler: tHandler,
	}
	a.netlinkHandle = NewNetLinkHandle()

	// Get or create device
	dev, err := a.getWgDevice(deviceName)
	if err != nil {
		return a, err
	}
	a.device = dev

	// Bring device up
	if err := a.netlinkHandle.EnsureLinkUp(dev); err != nil {
		return a, err
	}

	// Check if there is a private key or generate one
	_, privKey, err := getKeys(deviceName)
	if err != nil {
		return a, err
	}
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

func (a *Agent) getWgDevice(devName string) (netlink.Link, error) {
	return a.netlinkHandle.GetDevice(devName)
}

func (a *Agent) FlushDeviceIPs() error {
	return a.netlinkHandle.FlushIPs(a.device)
}

func (a *Agent) SetPrivKey() error {
	return setPrivateKey(a.device.Attrs().Name, a.privKey)
}

// GetNewWgLease: talks to the peer server to ask for a new lease
func (a *Agent) GetNewWgLease(serverUrl string) error {
	resp, err := a.requestWgConfig(serverUrl)
	if err != nil {
		return err
	}

	devIP, err := netlink.ParseIPNet(resp.IP)
	if err != nil {
		return fmt.Errorf("Cannot parse offered ip net: %v", err)
	}
	fmt.Printf("Offered ip: %v\n", devIP)

	if err := a.netlinkHandle.UpdateIP(a.device, devIP); err != nil {
		return err
	}

	allowed_ips := strings.Split(resp.AllowedIPs, ",")
	peer, err := newPeerConfig(resp.PubKey, "", resp.Endpoint, allowed_ips)
	if err != nil {
		return err
	}

	if err := setPeers(a.device.Attrs().Name, []wgtypes.PeerConfig{*peer}); err != nil {
		return err
	}

	for _, aip := range allowed_ips {
		dst, err := netlink.ParseIPNet(aip)
		if err != nil {
			return err
		}

		fmt.Printf("Adding route: %v on dev %s\n", dst, a.device.Attrs().Name)
		if err := a.netlinkHandle.AddRoute(a.device, dst); err != nil {
			return err
		}
	}
	return nil
}
