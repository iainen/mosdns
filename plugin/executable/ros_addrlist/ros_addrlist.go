/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package ros_addrlist

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/IrineSistiana/mosdns/v5/pkg/cache"
	"net"
	"strconv"
	"strings"
	"time"

	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/netip"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

const (
	PluginType             = "ros_addrlist"
	DefaultSize            = 64 * 1024
	DefaultTimeoutInterval = time.Second * 1000
)

var (
	ErrAlreadyExists = fmt.Errorf("failure: already have such entry")
)

func init() {
	sequence.MustRegExecQuickSetup(PluginType, QuickSetup)
}

func parseRosTimeout(t string) time.Duration {
	d := time.Duration(0)
	if len(t) == 0 {
		return d
	}
	num := ""
	for _, r := range t {
		v := string(r)
		if r < '0' || r > '9' {
			value, _ := strconv.Atoi(num)
			switch v {
			case "d":
				d += time.Duration(value) * time.Hour * 24
			case "h":
				d += time.Duration(value) * time.Hour
			case "m":
				d += time.Duration(value) * time.Minute
			case "s":
				d += time.Duration(value) * time.Second
			}
			num = ""
		} else {
			num += v
		}
	}
	return d
}

type Args struct {
	AddrList        string        `yaml:"addrlist"`
	Server          string        `yaml:"server"`
	User            string        `yaml:"user"`
	Passwd          string        `yaml:"passwd"`
	Timeout         string        `yaml:"timeout"`
	TimeoutInterval time.Duration `yaml:"-"` // default time.Second * 1000
}

type rosAddrlistPlugin struct {
	args   *Args
	client *http.Client
	c      *cache.Cache[key, string]
}

func newRosAddrlistPlugin(args *Args) (*rosAddrlistPlugin, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		IdleConnTimeout: 30 * time.Second,
		MaxIdleConns:    10,
	}
	client := &http.Client{
		Timeout:   time.Second * 2,
		Transport: tr,
	}
	c := cache.New[key, string](cache.Opts{Size: DefaultSize})
	return &rosAddrlistPlugin{
		args:   args,
		client: client,
		c:      c,
	}, nil
}

func (p *rosAddrlistPlugin) Exec(ctx context.Context, qCtx *query_context.Context) error {
	r := qCtx.R()
	if r != nil {
		if err := p.addIP(r); err != nil {
			fmt.Printf("ros_addrlist addip failed but ignored: %v\n", err)
		}
	}
	return nil
}

func (p *rosAddrlistPlugin) addIPViaHTTPRequest(ip *net.IP, v6 bool, from string) (*rosAddResponse, error) {
	// request to add ips via http request routeros RESTFul API
	t := "ip"
	if v6 {
		t = "ipv6"
	}
	routerURL := p.args.Server + "/rest/" + t + "/firewall/address-list/add"
	payload := map[string]interface{}{
		"address": ip.String(),
		"list":    p.args.AddrList,
		"comment": "[mosdns] domain: " + from,
	}

	if len(p.args.Timeout) > 0 {
		payload["timeout"] = p.args.Timeout
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal json data: %w", err)
	}

	req, err := http.NewRequest("POST", routerURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(p.args.User, p.args.Passwd)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusBadRequest {
		respData := new(rosAdd400Response)
		err = json.NewDecoder(resp.Body).Decode(respData)
		if err != nil {
			return nil, fmt.Errorf("failed to decode json body: %v", err)
		}
		if respData.Detail == ErrAlreadyExists.Error() {
			return nil, ErrAlreadyExists
		}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	respData := new(rosAddResponse)
	err = json.NewDecoder(resp.Body).Decode(respData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode json body: %v", err)
	}

	return respData, nil
}

func (p *rosAddrlistPlugin) getIPViaHTTPRequest(ip *net.IP, v6 bool) (*rosGetResponse, error) {
	// request to add ips via http request routeros RESTFul API
	t := "ip"
	if v6 {
		t = "ipv6"
	}
	routerURL := p.args.Server + "/rest/" + t + "/firewall/address-list/print"
	payload := map[string]interface{}{
		".query": []string{"address=" + ip.String(), "list=" + p.args.AddrList},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal json data: %w", err)
	}

	req, err := http.NewRequest("POST", routerURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(p.args.User, p.args.Passwd)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	respData := make([]*rosGetResponse, 0)
	err = json.NewDecoder(resp.Body).Decode(&respData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode json body: %v", err)
	}

	return respData[0], nil
}

func (p *rosAddrlistPlugin) updateTimeoutViaHTTPRequest(id string, v6 bool) error {
	// request to add ips via http request routeros RESTFul API
	t := "ip"
	if v6 {
		t = "ipv6"
	}
	routerURL := p.args.Server + "/rest/" + t + "/firewall/address-list/set"
	payload := map[string]interface{}{
		".id":     id,
		"list":    p.args.AddrList,
		"timeout": p.args.Timeout,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal json data: %w", err)
	}

	req, err := http.NewRequest("POST", routerURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create http request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(p.args.User, p.args.Passwd)

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	return nil
}

func (p *rosAddrlistPlugin) addIP(r *dns.Msg) error {
	for i := range r.Answer {
		switch rr := r.Answer[i].(type) {
		case *dns.A:
			if len(p.args.AddrList) == 0 {
				continue
			}
			_, ok := netip.AddrFromSlice(rr.A.To4())
			if !ok {
				return fmt.Errorf("invalid A record with ip: %s", rr.A)
			}
			id, _, ok := p.c.Get(key(rr.A.String()))
			if ok {
				go func() {
					err := p.updateTimeoutViaHTTPRequest(id, false)
					if err != nil {
						fmt.Printf("failed to update timeout: %s, %v\n", rr.A, err)
						return
					}
					p.c.Store(key(rr.A.String()), id, time.Now().Add(p.args.TimeoutInterval))
				}()
				return nil
			}
			respData, err := p.addIPViaHTTPRequest(&rr.A, false, r.Question[0].Name)
			if errors.Is(err, ErrAlreadyExists) {
				go func() {
					getRespData, err := p.getIPViaHTTPRequest(&rr.A, false)
					if err != nil {
						fmt.Printf("failed to get ip: %s, %v\n", rr.A, err)
						return
					}
					fmt.Printf("get exist addr id: %s, addr: %s, timeout: %s\n", getRespData.Id, getRespData.Address, getRespData.Timeout)
					p.c.Store(key(rr.A.String()), getRespData.Id, time.Now().Add(parseRosTimeout(getRespData.Timeout)))
				}()
				return nil
			}
			if err != nil {
				fmt.Printf("failed to add ip: %s, %v\n", rr.A, err)
				return err
			}
			p.c.Store(key(rr.A.String()), respData.Ret, time.Now().Add(p.args.TimeoutInterval))

		case *dns.AAAA:
			if len(p.args.AddrList) == 0 {
				continue
			}
			_, ok := netip.AddrFromSlice(rr.AAAA.To16())
			if !ok {
				return fmt.Errorf("invalid AAAA record with ip: %s", rr.AAAA)
			}
			_, err := p.addIPViaHTTPRequest(&rr.AAAA, true, r.Question[0].Name)
			if err != nil {
				fmt.Printf("failed to add ip: %s, %v\n", rr.AAAA, err)
				return err
			}
		default:
			continue
		}
	}

	return nil
}

func (p *rosAddrlistPlugin) Close() error {
	return nil
}

// QuickSetup format: [set_name,{inet|inet6},mask] *2
// e.g. "http://192.168.111.1:8080,admin,password,gfwlist,1d"
func QuickSetup(_ sequence.BQ, s string) (any, error) {
	fs := strings.Fields(s)
	if len(fs) > 5 {
		return nil, fmt.Errorf("expect no more than 5 fields, got %d", len(fs))
	}

	args := new(Args)
	for _, argsStr := range fs {
		ss := strings.Split(argsStr, ",")
		if len(ss) != 5 {
			return nil, fmt.Errorf("invalid args, expect 5 fields, got %d", len(ss))
		}

		args.Server = ss[0]
		args.User = ss[1]
		args.Passwd = ss[2]
		args.AddrList = ss[3]
		args.Timeout = ss[4]
		args.TimeoutInterval = DefaultTimeoutInterval
		interval := parseRosTimeout(args.Timeout)
		if interval > 0 {
			args.TimeoutInterval = interval
		}
	}
	return newRosAddrlistPlugin(args)
}
