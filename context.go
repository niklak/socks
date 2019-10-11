package socks

import (
	"context"
	"errors"
	"fmt"
	"net"
)

func DialContext(proxyURI string) func(context.Context, string, string) (net.Conn, error) {
	cfg, err := parse(proxyURI)
	if err != nil {
		return dialContextError(err)
	}
	return cfg.dialContextFunc()
}

func (c *Config) dialContextFunc() func(context.Context, string, string) (net.Conn, error) {
	switch c.Proto {
	case SOCKS5:
		return func(ctx context.Context, _, targetAddr string) (conn net.Conn, err error) {
			return c.dialContextSocks5(ctx, targetAddr)
		}
	case SOCKS4, SOCKS4A:
		return func(ctx context.Context,_, targetAddr string) (conn net.Conn, err error) {
			return c.dialContextSocks4(ctx, targetAddr)
		}
	}
	return dialContextError(fmt.Errorf("unknown SOCKS protocol %v", c.Proto))
}


func (cfg *Config) dialContextSocks5(ctx context.Context,targetAddr string) (conn net.Conn, err error) {
	proxy := cfg.Host

	// dial TCP
	//conn, err = net.Dial("tcp", proxy)
	conn , err = (&net.Dialer{Timeout:cfg.Timeout}).DialContext(ctx,"tcp", proxy)
	if err != nil {
		return
	}
	// version identifier/method selection request
	req := []byte{
		5, // version number
		1, // number of methods
		0, // method 0: no authentication (only anonymous access supported for now)
	}
	resp, err := cfg.sendReceive(conn, req)
	if err != nil {
		return
	} else if len(resp) != 2 {
		err = errors.New("Server does not respond properly.")
		return
	} else if resp[0] != 5 {
		err = errors.New("Server does not support Socks 5.")
		return
	} else if resp[1] != 0 { // no auth
		err = errors.New("socks method negotiation failed.")
		return
	}

	// detail request
	host, port, err := splitHostPort(targetAddr)
	if err != nil {
		return nil, err
	}
	req = []byte{
		5,               // version number
		1,               // connect command
		0,               // reserved, must be zero
		3,               // address type, 3 means domain name
		byte(len(host)), // address length
	}
	req = append(req, []byte(host)...)
	req = append(req, []byte{
		byte(port >> 8), // higher byte of destination port
		byte(port),      // lower byte of destination port (big endian)
	}...)
	resp, err = cfg.sendReceive2(conn, req)
	if err != nil {
		return
	} else if len(resp) != 10 {
		err = errors.New("Server does not respond properly.")
	} else if resp[1] != 0 {
		err = errors.New("Can't complete SOCKS5 connection.")
	}

	return
}


func (cfg *Config) dialContextSocks4(ctx context.Context,targetAddr string) (conn net.Conn, err error) {
	socksType := cfg.Proto
	proxy := cfg.Host

	// dial TCP
	conn , err = (&net.Dialer{Timeout:cfg.Timeout}).DialContext(ctx,"tcp", proxy)
	//conn , err = (&net.Dialer{Deadline: time.Now().Add(cfg.Timeout)}).DialContext(ctx,"tcp", proxy)
	if err != nil {
		return
	}

	// connection request
	host, port, err := splitHostPort(targetAddr)
	if err != nil {
		return
	}
	ip := net.IPv4(0, 0, 0, 1).To4()
	if socksType == SOCKS4 {
		ip, err = lookupIP(host)
		if err != nil {
			return
		}
	}
	req := []byte{
		4,                          // version number
		1,                          // command CONNECT
		byte(port >> 8),            // higher byte of destination port
		byte(port),                 // lower byte of destination port (big endian)
		ip[0], ip[1], ip[2], ip[3], // special invalid IP address to indicate the host name is provided
		0, // user id is empty, anonymous proxy only
	}
	if socksType == SOCKS4A {
		req = append(req, []byte(host+"\x00")...)
	}

	resp, err := cfg.sendReceive2(conn, req)
	if err != nil {
		return
	} else if len(resp) != 8 {
		err = errors.New("Server does not respond properly.")
		return
	}
	switch resp[1] {
	case 90:
		// request granted
	case 91:
		err = errors.New("Socks connection request rejected or failed.")
	case 92:
		err = errors.New("Socks connection request rejected becasue SOCKS server cannot connect to identd on the client.")
	case 93:
		err = errors.New("Socks connection request rejected because the client program and identd report different user-ids.")
	default:
		err = errors.New("Socks connection request failed, unknown error.")
	}
	// clear the deadline before returning
	/*if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}*/
	return
}

func dialContextError(err error) func(context.Context, string, string) (net.Conn, error) {
	return func(_ context.Context, _, _ string) (net.Conn, error) {
		return nil, err
	}
}

func (cfg *Config) sendReceive2(conn net.Conn, req []byte) (resp []byte, err error) {
	if _, err = conn.Write(req);err != nil {
		return
	}
	resp, err = cfg.readAll2(conn)
	return
}

func (cfg *Config) readAll2(conn net.Conn) (resp []byte, err error) {
	resp = make([]byte, 1024)
	n, err := conn.Read(resp)
	resp = resp[:n]
	return
}