package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
)

func main() {
	var addr, torAddr string
	var verbose bool

	flag.StringVar(&addr, "addr", "127.0.0.1:53", "Address to listen")
	flag.StringVar(&torAddr, "tor", "127.0.0.1:9050", "Address to tor")
	flag.BoolVar(&verbose, "verbose", false, "Verbose")
	flag.Parse()

	srv := &dns.Server{Addr: addr, Net: "udp"}
	srv.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		msg := dns.Msg{}
		msg.SetReply(r)
		switch r.Question[0].Qtype {
		case dns.TypeA:
			msg.Authoritative = true
			domain := msg.Question[0].Name
			address, err := resolve(torAddr, domain)
			if err == nil {
				if verbose {
					fmt.Printf("%s resolves to %s\r\n", domain, address)
				}
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP(address),
				})
			} else {
				logErr("unable to resolve %s: %v\r\n", domain, err)
			}
		}
		w.WriteMsg(&msg)
	})
	err := srv.ListenAndServe()
	if err != nil {
		logErr("server failed: %v", err)
		os.Exit(1)
	}
}

func resolve(host, address string) (string, error) {
	conn, err := net.Dial("tcp4", host)
	if err != nil {
		return "", errors.Wrapf(err, "unable to connect to tor at %s", host)
	}
	defer conn.Close()
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		return "", errors.Wrap(err, "unable to negotiate with the tor socks")
	}

	buff := make([]byte, 10, 10)
	_, err = io.ReadAtLeast(conn, buff, 2)
	if err != nil {
		return "", errors.Wrap(err, "unable to negotiate with the tor socks")
	}

	if buff[0] != 0x05 || buff[1] != 0x00 {
		return "", errors.New("unable to negotiate with the tor socks")
	}

	resBuff := append(append([]byte{0x05, 0xF0, 0x00, 0x03, byte(len(address))}, []byte(address)...), 0x00, 0x00)

	_, err = conn.Write(resBuff)
	if err != nil {
		return "", errors.New("unable to resolve with the tor socks")
	}

	_, err = io.ReadFull(conn, buff)
	if err != nil {
		return "", errors.New("unable to resolve with the tor socks")
	}

	if buff[0] != 0x05 || buff[1] != 0x00 || buff[2] != 0x00 || buff[3] != 0x01 || buff[8] != 0x00 || buff[9] != 0x00 {
		return "", errors.New("unable to resolve with the tor socks")
	}
	ip := net.IPv4(buff[4], buff[5], buff[6], buff[7])
	return ip.String(), nil
}

func logErr(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
}
