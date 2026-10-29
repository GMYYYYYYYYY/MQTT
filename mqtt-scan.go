package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	ProtoV311 byte = 0x04
	ProtoV50  byte = 0x05
)

const (
	CONNECT byte = iota + 1
	CONNACK
	PUBLISH
	PUBACK
	PUBREC
	PUBREL
	PUBCOMP
	SUBSCRIBE
	SUBACK
	UNSUBSCRIBE
	UNSUBACK
	PINGREQ
	PINGRESP
	DISCONNECT
	AUTH
)

const (
	ReasonSuccess             byte = 0x00
	ReasonUnsupportedProtoVer byte = 0x84
	ConnAccepted              byte = 0x00
	ConnBadProtoVersion       byte = 0x01
	flagMandatory             byte = 0b0010
)

var (
	ErrConnackRefused = errors.New("session: broker refused connection")
	ErrNoResponse     = errors.New("session: no response (timeout)")
	ErrConnClosed     = errors.New("session: connection closed by broker")
	ErrWrongPacket    = errors.New("session: unexpected packet type in response")
)

var v3ConnackNames = map[byte]string{
	0: "Accepted", 1: "UnacceptableProtocolVersion", 2: "IdentifierRejected",
	3: "ServerUnavailable", 4: "BadUserNameOrPassword", 5: "NotAuthorized",
}

var reasonNames = map[byte]string{
	0x00: "Success", 0x10: "NoMatchingSubscribers", 0x80: "UnspecifiedError",
	0x81: "MalformedPacket", 0x82: "ProtocolError", 0x84: "UnsupportedProtocolVersion",
	0x85: "ClientIDNotValid", 0x86: "BadUserNameOrPassword", 0x87: "NotAuthorized",
	0x88: "ServerUnavailable", 0x89: "ServerBusy", 0x8A: "Banned",
	0x8C: "BadAuthenticationMethod", 0x8E: "SessionTakenOver",
	0x9B: "QoSNotSupported", 0xA2: "WildcardSubsNotSupported",
}

func ReasonName(c byte) string {
	if s, ok := reasonNames[c]; ok {
		return s
	}
	return fmt.Sprintf("0x%02X", c)
}

func encodeVBI(n int) []byte {
	var out []byte
	for {
		b := byte(n % 128)
		n /= 128
		if n > 0 {
			b |= 0x80
		}
		out = append(out, b)
		if n == 0 {
			return out
		}
	}
}

func decodeVBI(buf []byte, off int) (int, int, error) {
	v, m := 0, 1
	for i := 0; i < 4; i++ {
		if off >= len(buf) {
			return 0, off, errors.New("vbi: incomplete")
		}
		b := buf[off]
		off++
		v += int(b&0x7F) * m
		if b&0x80 == 0 {
			return v, off, nil
		}
		m *= 128
	}
	return 0, off, errors.New("vbi: too long")
}

func encodeString(s string) []byte {
	out := make([]byte, 2, 2+len(s))
	binary.BigEndian.PutUint16(out, uint16(len(s)))
	return append(out, s...)
}

func decodeString(buf []byte, off int) (string, int, error) {
	if off+2 > len(buf) {
		return "", off, errors.New("string: truncated")
	}
	n := int(binary.BigEndian.Uint16(buf[off:]))
	if off+2+n > len(buf) {
		return "", off, errors.New("string: overruns buffer")
	}
	return string(buf[off+2 : off+2+n]), off + 2 + n, nil
}

func buildPacket(typ, flags byte, body []byte) []byte {
	out := append([]byte{typ<<4 | flags}, encodeVBI(len(body))...)
	return append(out, body...)
}

type packet struct {
	Type           byte
	Flags          byte
	Raw            []byte
	PacketID       uint16
	Reason         byte
	ReturnCode     byte
	SessionPresent bool
	Properties     []byte
}

func v5Trailer(body []byte, reasonOff int) (byte, []byte) {
	if reasonOff >= len(body) {
		return 0, nil
	}
	reason := body[reasonOff]
	off := reasonOff + 1
	if off >= len(body) {
		return reason, nil
	}
	propLen, n, err := decodeVBI(body, off)
	if err != nil || n+propLen > len(body) {
		return reason, nil
	}
	return reason, body[n : n+propLen]
}

func decodePacket(data []byte, proto byte) (*packet, error) {
	if len(data) < 2 {
		return nil, errors.New("packet: too short")
	}
	p := &packet{Type: data[0] >> 4, Flags: data[0] & 0x0F, Raw: append([]byte(nil), data...)}
	remLen, off, err := decodeVBI(data, 1)
	if err != nil {
		return nil, err
	}
	if off+remLen > len(data) {
		return nil, fmt.Errorf("packet truncated: need %d, have %d", off+remLen, len(data))
	}
	body := data[off : off+remLen]

	switch p.Type {
	case CONNACK:
		if len(body) < 2 {
			return nil, errors.New("connack: body < 2")
		}
		p.SessionPresent = body[0]&0x01 == 0x01
		if proto == ProtoV50 {
			p.Reason, p.Properties = v5Trailer(body, 1)
		} else {
			p.ReturnCode = body[1]
		}
	default: 
	}
	return p, nil
}

func encodeConnect(level byte, clientID, user, pass string, keepAlive uint16) []byte {
	var flags byte = 0x02 
	if user != "" {
		flags |= 0x80
	}
	if pass != "" {
		flags |= 0x40
	}
	vh := append(encodeString("MQTT"), level, flags)
	vh = append(vh, byte(keepAlive>>8), byte(keepAlive))
	payload := encodeString(clientID)
	if user != "" {
		payload = append(payload, encodeString(user)...)
	}
	if pass != "" {
		payload = append(payload, encodeString(pass)...)
	}
	return buildPacket(CONNECT, 0, append(vh, payload...))
}

func encodeDisconnect() []byte {
	return []byte{DISCONNECT << 4, 0x00}
}

type Options struct {
	ProtoLevel byte
	ClientID   string
	Username   string
	Password   string
	KeepAlive  uint16
	Timeout    time.Duration
	UseTLS     bool
}

type Session struct {
	conn         net.Conn
	host         string
	port         int
	opts         Options
	proto        byte
	tlsVerifyErr string
	tlsNotAfter  string
}

func dial(ctx context.Context, host string, port int, opts Options) (net.Conn, string, string, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := (&net.Dialer{Timeout: opts.Timeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, "", "", fmt.Errorf("dial %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(opts.Timeout))

	var verifyErr, notAfter string
	if opts.UseTLS {
		tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: host})
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, "", "", fmt.Errorf("tls handshake: %w", err)
		}
		conn = tc
		if st := tc.ConnectionState(); len(st.PeerCertificates) > 0 {
			leaf := st.PeerCertificates[0]
			notAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
			if _, verr := leaf.Verify(x509.VerifyOptions{DNSName: host}); verr != nil {
				verifyErr = verr.Error()
			}
		}
	}
	return conn, verifyErr, notAfter, nil
}

func New(ctx context.Context, host string, port int, opts Options) (*Session, error) {
	if opts.KeepAlive == 0 {
		opts.KeepAlive = 60
	}
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}
	conn, verifyErr, notAfter, err := dial(ctx, host, port, opts)
	if err != nil {
		return nil, err
	}
	return &Session{conn: conn, host: host, port: port,
		opts: opts, proto: opts.ProtoLevel, tlsVerifyErr: verifyErr, tlsNotAfter: notAfter}, nil
}

func (s *Session) reconnect(ctx context.Context) error {
	if s.conn != nil {
		_ = s.conn.Close()
	}
	conn, verifyErr, notAfter, err := dial(ctx, s.host, s.port, s.opts)
	if err != nil {
		return err
	}
	s.conn, s.tlsVerifyErr, s.tlsNotAfter = conn, verifyErr, notAfter
	return nil
}

func (s *Session) readPacket() ([]byte, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(s.conn, head); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, ErrConnClosed
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil, ErrNoResponse
		}
		return nil, err
	}
	lenBytes := []byte{head[1]}
	if head[1]&0x80 != 0 {
		buf := make([]byte, 1)
		for i := 0; i < 3; i++ {
			if _, err := io.ReadFull(s.conn, buf); err != nil {
				return nil, fmt.Errorf("read remaining length: %w", err)
			}
			lenBytes = append(lenBytes, buf[0])
			if buf[0]&0x80 == 0 {
				break
			}
		}
	}
	remLen, _, err := decodeVBI(lenBytes, 0)
	if err != nil {
		return nil, fmt.Errorf("decode remaining length: %w", err)
	}
	if remLen > 256*1024*1024 {
		return nil, fmt.Errorf("packet too large: %d", remLen)
	}
	raw := append([]byte{head[0]}, lenBytes...)
	if remLen > 0 {
		body := make([]byte, remLen)
		if _, err := io.ReadFull(s.conn, body); err != nil {
			return nil, fmt.Errorf("read body: %w", err)
		}
		raw = append(raw, body...)
	}
	return raw, nil
}

func (s *Session) recv() (*packet, error) {
	raw, err := s.readPacket()
	if err != nil {
		return nil, err
	}
	return decodePacket(raw, s.proto)
}

func (s *Session) send(data []byte) error {
	if _, err := s.conn.Write(data); err != nil {
		return fmt.Errorf("send: %w", err)
	}
	return nil
}

func (s *Session) tryConnect(clientID string, level byte) (*packet, error) {
	s.proto = level
	if err := s.send(encodeConnect(level, clientID, s.opts.Username, s.opts.Password, s.opts.KeepAlive)); err != nil {
		return nil, err
	}
	p, err := s.recv()
	if err != nil {
		return nil, err
	}
	if p.Type != CONNACK {
		return nil, fmt.Errorf("%w: got type %d", ErrWrongPacket, p.Type)
	}
	return p, nil
}

type ConnectOutcome struct {
	SessionPresent bool
	BrokerReason   string
	BrokerInfo     map[string]string
}

func (s *Session) Connect(ctx context.Context) (*ConnectOutcome, error) {
	if s.conn == nil {
		return nil, errors.New("session: not connected")
	}
	clientID := s.opts.ClientID
	if clientID == "" {
		clientID = fmt.Sprintf("mqttscan-%d", time.Now().UnixNano()%1_000_000)
	}

	p, err := s.tryConnect(clientID, s.opts.ProtoLevel)
	if err != nil {
		if s.opts.ProtoLevel == ProtoV50 && errors.Is(err, ErrConnClosed) {
			if rerr := s.reconnect(ctx); rerr != nil {
				return nil, rerr
			}
			if p, err = s.tryConnect(clientID, ProtoV311); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	if s.proto == ProtoV50 && (p.Reason == ReasonUnsupportedProtoVer || (p.Reason >= 0x01 && p.Reason <= 0x05)) {
		if rerr := s.reconnect(ctx); rerr != nil {
			return nil, rerr
		}
		if p, err = s.tryConnect(clientID, ProtoV311); err != nil {
			return nil, err
		}
	} else if s.proto == ProtoV311 && (p.ReturnCode == ConnBadProtoVersion || len(p.Raw) > 4) {
		if rerr := s.reconnect(ctx); rerr != nil {
			return nil, rerr
		}
		if p, err = s.tryConnect(clientID, ProtoV50); err != nil {
			return nil, err
		}
	}

	out := &ConnectOutcome{SessionPresent: p.SessionPresent}
	if s.proto == ProtoV50 {
		if p.Reason != ReasonSuccess {
			out.BrokerReason = ReasonName(p.Reason)
			return out, ErrConnackRefused
		}
		out.BrokerInfo = extractConnackInfo(p.Properties)
	} else if p.ReturnCode != ConnAccepted {
		out.BrokerReason = v3ConnackNames[p.ReturnCode]
		if out.BrokerReason == "" {
			out.BrokerReason = fmt.Sprintf("Unknown(%d)", p.ReturnCode)
		}
		return out, ErrConnackRefused
	}
	return out, nil
}

func extractConnackInfo(props []byte) map[string]string {
	getU8 := func(id byte) (byte, bool) {
		v, ok := getProp(props, id)
		if !ok || len(v) == 0 {
			return 0, false
		}
		return v[0], true
	}
	info := map[string]string{}
	if v, ok := getProp(props, 0x13); ok && len(v) == 2 { 
		info["server_keepalive"] = strconv.Itoa(int(uint16(v[0])<<8 | uint16(v[1])))
	}
	if v, ok := getU8(0x24); ok { 
		info["max_qos"] = strconv.Itoa(int(v))
	}
	if v, ok := getU8(0x25); ok { 
		info["retain_available"] = strconv.Itoa(int(v))
	}
	if v, ok := getU8(0x28); ok { 
		info["wildcard_available"] = strconv.Itoa(int(v))
	}
	if v, ok := getProp(props, 0x12); ok { 
		info["assigned_client_id"] = string(v)
	}
	return info
}

func getProp(props []byte, id byte) ([]byte, bool) {
	off := 0
	for off < len(props) {
		pid, n, err := decodeVBI(props, off)
		if err != nil {
			return nil, false
		}
		off = n
		
		if byte(pid) == id {
			if id == 0x12 { 
				v, n2, err := decodeString(props, off)
				if err != nil {
					return nil, false
				}
				return []byte(v), true
			}
			if off >= len(props) {
				return nil, false
			}
			return props[off : off+1], true
		}
		if id != byte(pid) || true {
			if byte(pid) == 0x12 {
				_, n2, err := decodeString(props, off)
				if err != nil {
					return nil, false
				}
				off = n2
			} else {
				off++
			}
		}
	}
	return nil, false
}

func (s *Session) Close() error {
	if s.conn == nil {
		return nil
	}
	_ = s.send(encodeDisconnect())
	err := s.conn.Close()
	s.conn = nil
	return err
}

func (s *Session) Proto() byte { return s.proto }

type Result struct {
	Host           string            `json:"host"`
	Port           int               `json:"port"`
	Proto          string            `json:"proto"`
	AuthStatus     string            `json:"auth_status"`
	TLSVerifyError string            `json:"tls_verify_error,omitempty"`
	TLSNotAfter    string            `json:"tls_not_after,omitempty"`
	RejectReason   string            `json:"reject_reason,omitempty"`
	Anonymous      bool              `json:"anonymous"`
	BrokerInfo     map[string]string `json:"broker_info,omitempty"`
}

func Probe(ctx context.Context, host string, port int, opts Options) (*Result, error) {
	res := &Result{Host: host, Port: port, BrokerInfo: map[string]string{}}

	anonOpts := opts
	anonOpts.Username, anonOpts.Password = "", "" 

	sess, err := New(ctx, host, port, anonOpts)
	if err != nil {
		return res, err 
	}
	res.TLSVerifyError, res.TLSNotAfter = sess.tlsVerifyErr, sess.tlsNotAfter

	outcome, err := sess.Connect(ctx)
	switch {
	case err == nil:
		res.Anonymous, res.AuthStatus = true, "anonymous"
		res.Proto = protoName(sess.Proto())
		res.BrokerInfo = outcome.BrokerInfo

	case isAuthFailure(err, outcome): 
		res.AuthStatus = "rejected"
		res.RejectReason = outcome.BrokerReason
		res.Proto = protoName(sess.Proto())

	default: 
		_ = sess.Close()
		return res, err
	}

	_ = sess.Close()
	return res, nil
}


func isAuthFailure(err error, outcome *ConnectOutcome) bool {
	if outcome == nil {
		return false
	}
	switch outcome.BrokerReason {
	case "NotAuthorized", "BadUserNameOrPassword", "ServerUnavailable", "Banned":
		return true
	}
	return strings.Contains(err.Error(), ErrConnackRefused.Error())
}

func protoName(p byte) string {
	if p == ProtoV50 {
		return "5.0"
	}
	return "3.1.1"
}

const (
	defaultPort = 1883
	workers     = 2000
	timeout     = 5 * time.Second
)

type target struct {
	host string
	port int
}

func (t target) String() string { return net.JoinHostPort(t.host, strconv.Itoa(t.port)) }

func parseAddr(line string) (string, int) {
	line = strings.TrimSpace(line)
	if h, p, err := net.SplitHostPort(line); err == nil {
		if n, err := strconv.Atoi(p); err == nil {
			return h, n
		}
	}
	if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
		line = line[1 : len(line)-1]
	}
	return line, defaultPort
}

type result struct {
	Target    string  `json:"target"`
	Status    string  `json:"status"`
	Error     string  `json:"error,omitempty"`
	ElapsedMs int64   `json:"elapsed_ms"`
	Scan      *Result `json:"scan,omitempty"`
}

func classify(err error) string {
	var nerr net.Error
	switch {
	case err == nil:
		return "mqtt"
	case errors.Is(err, ErrWrongPacket), errors.Is(err, ErrConnClosed):
		return "not_mqtt"
	case errors.Is(err, ErrNoResponse):
		return "timeout"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.ENETDOWN):
		return "unreachable"
	case errors.Is(err, syscall.ETIMEDOUT), errors.As(err, &nerr) && nerr.Timeout():
		return "timeout"
	}
	if msg := err.Error(); strings.Contains(msg, "tls") || strings.Contains(msg, "x509") {
		return "tls_error"
	}
	return "error"
}

func scan(t target) *result {
	r := &result{Target: t.String(), Status: "error"}
	start := time.Now()
	defer func() { r.ElapsedMs = time.Since(start).Milliseconds() }()

	opts := Options{ProtoLevel: ProtoV50, Timeout: timeout, UseTLS: t.port == 8883}
	res, err := Probe(context.Background(), t.host, t.port, opts)
	r.Scan = res
	if err != nil {
		r.Status = classify(err)
		r.Error = err.Error()
		return r
	}
	return r
}

func main() {
	in := io.Reader(os.Stdin)
	if len(os.Args) > 1 {
		f, err := os.Open(os.Args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "usage: mqtt-scan [addrfile] # 缺省读 stdin，每行 host[:port]")
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(2)
		}
		defer f.Close()
		in = f
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)

	jobs := make(chan target, workers)
	var wg, outWg sync.WaitGroup
	var mu sync.Mutex

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				r := scan(t)
				mu.Lock()
				_ = enc.Encode(r)
				mu.Unlock()
			}
		}()
	}

	n := 0
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		h, p := parseAddr(line)
		jobs <- target{h, p}
		n++
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
	}
	if n == 0 {
		fmt.Fprintln(os.Stderr, "error: no targets")
		os.Exit(2)
	}
	close(jobs)
	wg.Wait()
}
