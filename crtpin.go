package crtpin

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"sort"

	// Registers hash crypto.BLAKE2b_256
	_ "golang.org/x/crypto/blake2b"
	// Registers hash crypto.BLAKE2s_256
	_ "golang.org/x/crypto/blake2s"
	"math/big"
	"net"
	"strconv"
	"time"
)

// A CertInfo gives basic information about an X.509 certificate
type CertInfo struct {
	CommonName      string   `json:"commonName"`
	DaysUntilExpiry int      `json:"daysUntilExpiry"`
	DNSNames        []string `json:"dnsNames"`
	Issuer          string   `json:"issuer"`
	NotValidAfter   string   `json:"notValidAfter"`
	NotValidBefore  string   `json:"notValidBefore"`
	SerialNumber    big.Int  `json:"serialNumber"`
}

// Pins consists of various Base64-encoded hashes
type Pins struct {
	BLAKE2s256 string `json:"blake2s256"`
	BLAKE2b256 string `json:"blake2b256"`
	SHA256     string `json:"sha256"`
	SHA384     string `json:"sha384"`
	SHA512     string `json:"sha512"`
}

// A Request provides meta information about the query
type Request struct {
	Date       time.Time `json:"date"`
	Host       string    `json:"host"`
	IP         string    `json:"ip"`
	Port       int       `json:"port"`
	NameServer string    `json:"nameserver"`
}

// The Result is the final outcome
type Result struct {
	Cert    CertInfo `json:"cert"`
	Pins    Pins     `json:"pins"`
	Request Request  `json:"request"`
}

func hashSubjectPublicKeyInfo(certificate x509.Certificate, hash crypto.Hash, result chan<- string) {
	h := hash.New()
	h.Write(certificate.RawSubjectPublicKeyInfo)
	hashed := h.Sum(nil)
	result <- base64.StdEncoding.EncodeToString(hashed[:])
}

//calculatePins Compute the SubjectPublicKeyInfo using different hash algorithms, in parallel
func calculatePins(certificate x509.Certificate) Pins {
	blake2b256C := make(chan string)
	go hashSubjectPublicKeyInfo(certificate, crypto.BLAKE2b_256, blake2b256C)

	blake2s256C := make(chan string)
	go hashSubjectPublicKeyInfo(certificate, crypto.BLAKE2s_256, blake2s256C)

	sha256C := make(chan string)
	go hashSubjectPublicKeyInfo(certificate, crypto.SHA256, sha256C)

	sha384C := make(chan string)
	go hashSubjectPublicKeyInfo(certificate, crypto.SHA384, sha384C)

	sha512C := make(chan string)
	go hashSubjectPublicKeyInfo(certificate, crypto.SHA512, sha512C)

	return Pins{
		BLAKE2b256: <-blake2b256C,
		BLAKE2s256: <-blake2s256C,
		SHA256:     <-sha256C,
		SHA384:     <-sha384C,
		SHA512:     <-sha512C,
	}
}

func certInfo(certificate x509.Certificate) CertInfo {
	diff := time.Until(certificate.NotAfter)

	return CertInfo{
		CommonName:      certificate.Subject.CommonName,
		DaysUntilExpiry: int(diff.Hours() / 24),
		DNSNames:        certificate.DNSNames,
		Issuer:          certificate.Issuer.CommonName,
		NotValidAfter:   certificate.NotAfter.In(time.UTC).Format(time.RFC3339),
		NotValidBefore:  certificate.NotBefore.In(time.UTC).Format(time.RFC3339),
		SerialNumber:    *certificate.SerialNumber,
	}
}

func newDoTResolver(serverName string, addrs ...string) *net.Resolver {
	var d net.Dialer
	cfg := &tls.Config{
		ServerName:         serverName,
		ClientSessionCache: tls.NewLRUClientSessionCache(0),
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := d.DialContext(ctx, "tcp", addrs[rand.Intn(len(addrs))])
			if err != nil {
				return nil, err
			}
			_ = conn.(*net.TCPConn).SetKeepAlive(true)
			_ = conn.(*net.TCPConn).SetKeepAlivePeriod(3 * time.Minute)
			return tls.Client(conn, cfg), nil
		},
	}
}

var resolverServerName = "dns3.digitalcourage.de"
var resolver = newDoTResolver(resolverServerName, "5.9.164.112:853")

var dialer = &net.Dialer{
	Resolver: resolver,
	Timeout:  600 * time.Millisecond,
}

var privateIP4Networks = []net.IPNet{
	{
		IP:   net.ParseIP("0.0.0.0"),
		Mask: net.CIDRMask(8, 32),
	},
	{
		IP:   net.ParseIP("10.0.0.0"),
		Mask: net.CIDRMask(8, 32),
	},
	{
		IP:   net.ParseIP("127.0.0.0"),
		Mask: net.CIDRMask(8, 32),
	},
	{
		IP:   net.ParseIP("169.254.0.0"),
		Mask: net.CIDRMask(16, 32),
	},
	{
		IP:   net.ParseIP("172.16.0.0"),
		Mask: net.CIDRMask(12, 32),
	},
	{
		IP:   net.ParseIP("192.0.0.0"),
		Mask: net.CIDRMask(29, 32),
	},
	{
		IP:   net.ParseIP("192.0.0.170"),
		Mask: net.CIDRMask(31, 32),
	},
	{
		IP:   net.ParseIP("192.0.2.0"),
		Mask: net.CIDRMask(24, 32),
	},
	{
		IP:   net.ParseIP("192.168.0.0"),
		Mask: net.CIDRMask(16, 32),
	},
	{
		IP:   net.ParseIP("198.18.0.0"),
		Mask: net.CIDRMask(15, 32),
	},
	{
		IP:   net.ParseIP("198.51.100.0"),
		Mask: net.CIDRMask(24, 32),
	},
	{
		IP:   net.ParseIP("203.0.113.0"),
		Mask: net.CIDRMask(24, 32),
	},
	{
		IP:   net.ParseIP("240.0.0.0"),
		Mask: net.CIDRMask(4, 32),
	},
	{
		IP:   net.ParseIP("255.255.255.255"),
		Mask: net.CIDRMask(32, 32),
	},
}

var privateIP6Networks = []net.IPNet{
	{
		IP:   net.ParseIP("::1"),
		Mask: net.CIDRMask(128, 128),
	},
	{
		IP:   net.ParseIP("::"),
		Mask: net.CIDRMask(128, 128),
	},
	{
		IP:   net.ParseIP("::ffff:0:0"),
		Mask: net.CIDRMask(96, 128),
	},
	{
		IP:   net.ParseIP("100::"),
		Mask: net.CIDRMask(64, 128),
	},
	{
		IP:   net.ParseIP("2001::"),
		Mask: net.CIDRMask(23, 128),
	},
	{
		IP:   net.ParseIP("2001:2::"),
		Mask: net.CIDRMask(48, 128),
	},
	{
		IP:   net.ParseIP("2001:db8::"),
		Mask: net.CIDRMask(32, 128),
	},
	{
		IP:   net.ParseIP("2001:10::"),
		Mask: net.CIDRMask(28, 128),
	},
	{
		IP:   net.ParseIP("fc00::"),
		Mask: net.CIDRMask(7, 128),
	},
	{
		IP:   net.ParseIP("fe80::"),
		Mask: net.CIDRMask(10, 128),
	},
}

func ipPrivate(ip net.IP) bool {
	var networks *[]net.IPNet
	if ip.To4() != nil {
		networks = &privateIP4Networks
	} else {
		networks = &privateIP6Networks
	}

	for _, ipNet := range *networks {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// PreferIP6 implements sort.Interface for []net.IPAddr preferring IPv6
type PreferIP6 []net.IPAddr

func (a PreferIP6) Len() int           { return len(a) }
func (a PreferIP6) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a PreferIP6) Less(i, _ int) bool { return a[i].IP.To4() == nil }

func lookUpIPs(host string) ([]net.IPAddr, error) {
	ipAddrs, err := resolver.LookupIPAddr(context.Background(), host)
	if err != nil {
		return ipAddrs, err
	}

	var filteredIps []net.IPAddr
	for i := range ipAddrs {
		ipAddr := ipAddrs[i]
		if !ipPrivate(ipAddr.IP) {
			filteredIps = append(filteredIps, ipAddr)
		}
	}

	// Prefer IP6
	sort.Sort(PreferIP6(filteredIps))

	return filteredIps, nil
}

func dialWithDialerPreferTCP6(dialer *net.Dialer, addr string, config *tls.Config) (*tls.Conn, error) {

	conn, err := tls.DialWithDialer(dialer, "tcp6", addr, config)
	if err != nil {
		return tls.DialWithDialer(dialer, "tcp4", addr, config)
	}
	return conn, err
}

// Crtpin creates pins and meta information about a certificate used for host and port
func Crtpin(host string, port int, filterPrivateIPs bool) (*Result, error) {
	now := time.Now()

	var conn *tls.Conn
	var err error

	if filterPrivateIPs {
		ipAddrs, err := lookUpIPs(host)
		if len(ipAddrs) == 0 {
			return nil, &net.DNSError{Err: errors.New("no such host").Error(), Name: host, IsNotFound: true}
		}
		// Take the first successfully opened Conn
		for i := range ipAddrs {
			addr := fmt.Sprintf("[%s]:%d", ipAddrs[i].IP, port)
			conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
				ServerName:         host,
				InsecureSkipVerify: true,
			})
			if err == nil {
				break
			}
		}
	} else {
		conn, err = dialWithDialerPreferTCP6(dialer, host+":"+strconv.Itoa(port), &tls.Config{
			InsecureSkipVerify: true,
		})
	}

	if conn == nil {
		return nil, net.UnknownNetworkError("Could not connect")
	}

	if err != nil {
		return nil, err
	}
	defer conn.Close()

	addr := conn.RemoteAddr()
	ip, _, _ := net.SplitHostPort(addr.String())
	certChain := conn.ConnectionState().PeerCertificates

	leafCert := *certChain[0]

	pins := calculatePins(leafCert)
	cert := certInfo(leafCert)

	return &Result{
		Pins: pins,
		Cert: cert,
		Request: Request{
			Date:       now,
			Host:       host,
			IP:         ip,
			Port:       port,
			NameServer: resolverServerName + ":853",
		},
	}, nil
}
