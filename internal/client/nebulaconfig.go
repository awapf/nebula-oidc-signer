package client

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"

	"go.yaml.in/yaml/v3"
)

// Network is the signer's description of the Nebula network: what a host
// needs besides its certificate.
type Network struct {
	Lighthouses []Lighthouse `json:"lighthouses"`
	Relays      []string     `json:"relays"`
}

// Lighthouse is a lighthouse's overlay address and public endpoints.
type Lighthouse struct {
	Address   string   `json:"address"`
	Endpoints []string `json:"endpoints"`
}

type fwRule struct {
	Port  string `yaml:"port"`
	Proto string `yaml:"proto"`
	Host  string `yaml:"host"`
}

type relayYAML struct {
	Relays    []string `yaml:"relays"`
	UseRelays bool     `yaml:"use_relays"`
}

// nebulaYAML is the generated config. Field order is the file's order.
type nebulaYAML struct {
	PKI struct {
		CA   string `yaml:"ca"`
		Cert string `yaml:"cert"`
		Key  string `yaml:"key"`
	} `yaml:"pki"`
	StaticHostMap map[string][]string `yaml:"static_host_map"`
	Lighthouse    struct {
		AmLighthouse bool     `yaml:"am_lighthouse"`
		Hosts        []string `yaml:"hosts"`
	} `yaml:"lighthouse"`
	Relay  *relayYAML `yaml:"relay,omitempty"`
	Punchy struct {
		Punch bool `yaml:"punch"`
	} `yaml:"punchy"`
	Listen struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
	} `yaml:"listen"`
	Firewall struct {
		Outbound []fwRule `yaml:"outbound"`
		Inbound  []fwRule `yaml:"inbound"`
	} `yaml:"firewall"`
}

const configHeader = `# Written by nebula-oidc-signer client; it is overwritten on every renewal.
# Put your own settings (e.g. firewall.inbound rules) in another file of the
# same directory and run nebula with -config <directory>: nebula merges the
# files in lexical order and appends lists.
`

// NebulaConfig renders a nebula config for network that uses the
// certificate files in outDir. Inbound traffic is denied except ICMP.
func NebulaConfig(n *Network, outDir string) ([]byte, error) {
	if n == nil {
		return nil, errors.New("the signer returned no network block; configure network: on the CA in the signer")
	}
	if len(n.Lighthouses) == 0 {
		return nil, errors.New("network: no lighthouses")
	}
	abs, err := filepath.Abs(outDir)
	if err != nil {
		return nil, err
	}
	var y nebulaYAML
	y.PKI.CA, y.PKI.Cert, y.PKI.Key = filepath.Join(abs, CAFile), filepath.Join(abs, CertFile), filepath.Join(abs, KeyFile)
	y.StaticHostMap = map[string][]string{}
	for _, l := range n.Lighthouses {
		a, err := netip.ParseAddr(l.Address)
		if err != nil {
			return nil, fmt.Errorf("network: invalid lighthouse address %q", l.Address)
		}
		if len(l.Endpoints) == 0 {
			return nil, fmt.Errorf("network: lighthouse %s has no endpoints", a)
		}
		for _, e := range l.Endpoints {
			if err := validEndpoint(e); err != nil {
				return nil, fmt.Errorf("network: lighthouse %s: %w", a, err)
			}
		}
		if _, dup := y.StaticHostMap[a.String()]; dup {
			return nil, fmt.Errorf("network: duplicate lighthouse %s", a)
		}
		y.StaticHostMap[a.String()] = l.Endpoints
		y.Lighthouse.Hosts = append(y.Lighthouse.Hosts, a.String())
	}
	if len(n.Relays) > 0 {
		y.Relay = &relayYAML{UseRelays: true}
		for _, r := range n.Relays {
			a, err := netip.ParseAddr(r)
			if err != nil {
				return nil, fmt.Errorf("network: invalid relay address %q", r)
			}
			y.Relay.Relays = append(y.Relay.Relays, a.String())
		}
	}
	y.Punchy.Punch = true
	y.Listen.Host, y.Listen.Port = "0.0.0.0", 0
	y.Firewall.Outbound = []fwRule{{Port: "any", Proto: "any", Host: "any"}}
	y.Firewall.Inbound = []fwRule{{Port: "any", Proto: "icmp", Host: "any"}}
	b, err := yaml.Marshal(&y)
	if err != nil {
		return nil, err
	}
	return append([]byte(configHeader), b...), nil
}

func validEndpoint(e string) error {
	host, port, err := net.SplitHostPort(e)
	if err == nil && host != "" {
		if p, perr := strconv.Atoi(port); perr == nil && p >= 1 && p <= 65535 {
			return nil
		}
	}
	return fmt.Errorf("endpoint %q is not host:port", e)
}
