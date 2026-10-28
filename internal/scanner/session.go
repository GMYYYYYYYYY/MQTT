package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509" 
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"mqtt-scan/internal/mqtt"
)

var (
	ErrNotConnected     = errors.New("session: not connected")
	ErrConnackRefused   = errors.New("session: broker refused connection")
	ErrUnsupportedProto = errors.New("session: broker does not support requested protocol version")
	ErrNoResponse       = errors.New("session: no response (timeout)")
	ErrConnClosed       = errors.New("session: connection closed by broker")
	ErrWrongPacketType  = errors.New("session: unexpected packet type in response")
)

type Options struct {
	ProtoLevel byte
	ClientID   string
	Username   string
	Password   string
	KeepAlive  uint16
	Timeout    time.Duration
	UseTLS     bool
	TLSNoVerify bool
}

func (o *Options) normalize() {
	if o.KeepAlive == 0 {
		o.KeepAlive = 60
	}
	if o.Timeout == 0 {
		o.Timeout = 5 * time.Second
	}
}

type Session struct {
	conn       net.Conn
	opts       Options
	proto      byte
	nextID     uint16
	transcript []TranscriptEntry
	tlsVerifyErr string
	tlsNotAfter  string
}

type TranscriptEntry struct {
	Dir  string `json:"dir"`
	Type string `json:"type"`
	Len  int    `json:"len"`
	Hex  string `json:"hex,omitempty"`
}

func New(ctx context.Context, host string, port int, opts Options) (*Session, error) {
	opts.normalize()
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	dialer := &net.Dialer{Timeout: opts.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(opts.Timeout))

	var tlsVerifyErr, tlsNotAfter string
	if opts.UseTLS {
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true, 
			ServerName:         host,
			NextProtos:         []string{"mqtt"},
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("tls handshake: %w", err)
		}
		conn = tlsConn

		st := tlsConn.ConnectionState()
		if len(st.PeerCertificates) > 0 {
			leaf := st.PeerCertificates[0]
			tlsNotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
			verifyOpts := x509.VerifyOptions{DNSName: host}
			if len(st.PeerCertificates) > 1 {
				presented := x509.NewCertPool()
				for _, c := range st.PeerCertificates[1:] {
					presented.AddCert(c)
				}
				verifyOpts.Roots = presented
				verifyOpts.Intermediates = presented
			}
			if _, verr := leaf.Verify(verifyOpts); verr != nil {
				tlsVerifyErr = verr.Error()
			}
		}
	}

	return &Session{
		conn:         conn,
		opts:         opts,
		proto:        opts.ProtoLevel,
		nextID:       1,
		tlsVerifyErr: tlsVerifyErr, // [NEW]
		tlsNotAfter:  tlsNotAfter,  // [NEW]
	}, nil
}

func (s *Session) send(data []byte) error {
	if _, err := s.conn.Write(data); err != nil {
		return fmt.Errorf("send: %w", err)
	}
	s.record("tx", data)
	return nil
}

func (s *Session) readPacket() ([]byte, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(s.conn, head); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, ErrConnClosed
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
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

	remLen, _, err := mqtt.DecodeVBI(lenBytes, 0)
	if err != nil {
		return nil, fmt.Errorf("decode remaining length: %w", err)
	}
	if remLen > 256*1024*1024 {
		return nil, fmt.Errorf("packet too large: %d", remLen)
	}

	raw := make([]byte, 0, 1+len(lenBytes)+remLen)
	raw = append(raw, head[0])
	raw = append(raw, lenBytes...)
	if remLen > 0 {
		body := make([]byte, remLen)
		if _, err := io.ReadFull(s.conn, body); err != nil {
			return nil, fmt.Errorf("read body: %w", err)
		}
		raw = append(raw, body...)
	}

	s.record("rx", raw)
	return raw, nil
}

func (s *Session) recv() (*mqtt.Packet, error) {
	raw, err := s.readPacket()
	if err != nil {
		return nil, err
	}
	return mqtt.Decode(raw, s.proto)
}

func (s *Session) record(dir string, raw []byte) {
	entry := TranscriptEntry{
		Dir:  dir,
		Type: mqtt.TypeName(raw[0] >> 4),
		Len:  len(raw),
	}
	if len(raw) <= 128 {
		entry.Hex = fmt.Sprintf("%X", raw)
	}
	s.transcript = append(s.transcript, entry)
}

func (s *Session) Transcript() []TranscriptEntry {
	return append([]TranscriptEntry(nil), s.transcript...)
}

func (s *Session) allocID() uint16 {
	id := s.nextID
	s.nextID++
	if s.nextID == 0 {
		s.nextID = 1
	}
	return id
}

type ConnectOutcome struct {
	SessionPresent bool
	BrokerReason   string
	BrokerInfo     map[string]string
}

func (s *Session) Connect(ctx context.Context) (*ConnectOutcome, error) {
	if s.conn == nil {
		return nil, ErrNotConnected
	}

	clientID := s.opts.ClientID
	if clientID == "" {
		clientID = fmt.Sprintf("mqttscan-%d", time.Now().UnixNano()%1000000)
	}

	// 一次握手（内层函数），版本调整由外层决定是否重试
	tryConnect := func(level byte) (*mqtt.Packet, error) {
		s.proto = level
		pkt := mqtt.EncodeConnect(level, clientID, s.opts.Username, s.opts.Password, s.opts.KeepAlive)
		if err := s.send(pkt); err != nil {
			return nil, err
		}
		p, err := s.recv()
		if err != nil {
			return nil, err
		}
		if p.Type != mqtt.CONNACK {
			return nil, fmt.Errorf("%w: got %s", ErrWrongPacketType, mqtt.TypeName(p.Type))
		}
		return p, nil
	}

	p, err := tryConnect(s.opts.ProtoLevel)
	if err != nil {
		return nil, err
	}

	if s.proto == mqtt.ProtoV50 && p.Reason == mqtt.ReasonUnsupportedProtoVer {
		p, err = tryConnect(mqtt.ProtoV311)
		if err != nil {
			return nil, err
		}
	} else if s.proto == mqtt.ProtoV311 && (p.ReturnCode == mqtt.ConnBadProtoVersion || len(p.Raw) > 4) {
		p, err = tryConnect(mqtt.ProtoV50)
		if err != nil {
			return nil, err
		}
	}

	out := &ConnectOutcome{SessionPresent: p.SessionPresent}

	// 提取失败原因
	if s.proto == mqtt.ProtoV50 {
		if p.Reason != mqtt.ReasonSuccess {
			out.BrokerReason = mqtt.ReasonName(p.Reason)
			return out, ErrConnackRefused
		}
		out.BrokerInfo = s.extractConnackInfo(p.Properties)
	} else {
		if p.ReturnCode != mqtt.ConnAccepted {
			out.BrokerReason = mqtt.V3ConnackName(p.ReturnCode)
			return out, ErrConnackRefused
		}
	}

	return out, nil
}

func (s *Session) extractConnackInfo(props []byte) map[string]string {
	info := map[string]string{}
	if v, ok := mqtt.GetProperty(props, mqtt.PropServerKeepAlive); ok && len(v) == 2 {
		info["server_keepalive"] = fmt.Sprintf("%d", uint16(v[0])<<8|uint16(v[1]))
	}
	if v, ok := mqtt.GetProperty(props, mqtt.PropMaximumQoS); ok && len(v) > 0 {
		info["max_qos"] = fmt.Sprintf("%d", v[0])
	}
	if v, ok := mqtt.GetProperty(props, mqtt.PropRetainAvailable); ok && len(v) > 0 {
		info["retain_available"] = fmt.Sprintf("%d", v[0])
	}
	if v, ok := mqtt.GetProperty(props, mqtt.PropWildcardSubAvailable); ok && len(v) > 0 {
		info["wildcard_available"] = fmt.Sprintf("%d", v[0])
	}
	if v, ok := mqtt.GetProperty(props, mqtt.PropAssignedClientID); ok {
		info["assigned_client_id"] = string(v)
	}
	return info
}

func (s *Session) Subscribe(ctx context.Context, qos byte, topics ...string) ([]byte, error) {
	if s.conn == nil {
		return nil, ErrNotConnected
	}
	id := s.allocID()
	if err := s.send(mqtt.EncodeSubscribe(s.proto, id, qos, topics...)); err != nil {
		return nil, err
	}
	p, err := s.recv()
	if err != nil {
		return nil, err
	}
	if p.Type != mqtt.SUBACK {
		return nil, fmt.Errorf("%w: want SUBACK, got %s", ErrWrongPacketType, mqtt.TypeName(p.Type))
	}
	if p.PacketID != id {
		return nil, fmt.Errorf("suback: packet id mismatch (want %d, got %d)", id, p.PacketID)
	}
	return p.SubCodes, nil
}

func (s *Session) Unsubscribe(ctx context.Context, topics ...string) error {
	if s.conn == nil {
		return ErrNotConnected
	}
	id := s.allocID()
	if err := s.send(mqtt.EncodeUnsubscribe(s.proto, id, topics...)); err != nil {
		return err
	}
	p, err := s.recv()
	if err != nil {
		return err
	}
	if p.Type != mqtt.UNSUBACK {
		return fmt.Errorf("%w: want UNSUBACK, got %s", ErrWrongPacketType, mqtt.TypeName(p.Type))
	}
	return nil
}

func (s *Session) PublishAsync(topic string, qos byte, retain bool, payload []byte) (uint16, error) {
	if s.conn == nil {
		return 0, ErrNotConnected
	}
	var id uint16
	if qos > 0 {
		id = s.allocID()
	}
	if err := s.send(mqtt.EncodePublish(s.proto, topic, qos, retain, id, payload)); err != nil {
		return 0, err
	}
	return id, nil
}

func (s *Session) WaitAck(ctx context.Context, id uint16, qos byte) error {
	if s.conn == nil {
		return ErrNotConnected
	}
	for {
		p, err := s.recv()
		if err != nil {
			return err
		}
		switch p.Type {
		case mqtt.PUBACK: // QoS 1 确认
			if p.PacketID == id {
				if s.proto == mqtt.ProtoV50 && p.Reason != mqtt.ReasonSuccess {
					return fmt.Errorf("publish rejected: %s", mqtt.ReasonName(p.Reason))
				}
				return nil
			}
		case mqtt.PUBREC: // QoS 2 第一阶段确认
			if p.PacketID == id {
				if err := s.send(mqtt.EncodePubrel(p.PacketID)); err != nil {
					return err
				}
			} else {
				_ = s.send(mqtt.EncodePubrel(p.PacketID))
			}
		case mqtt.PUBCOMP: // QoS 2 第二阶段确认
			if p.PacketID == id {
				return nil
			}
		case mqtt.PUBLISH: // broker 主动下发
			if p.QoS > 0 {
				_ = s.send(mqtt.EncodePuback(p.PacketID))
			}
		case mqtt.PINGRESP:
		}
	}
}

func (s *Session) Publish(ctx context.Context, topic string, qos byte, retain bool, payload []byte) error {
	id, err := s.PublishAsync(topic, qos, retain, payload)
	if err != nil {
		return err
	}
	if qos > 0 {
		return s.WaitAck(ctx, id, qos)
	}
	return nil
}

func (s *Session) Ping(ctx context.Context) error {
	if s.conn == nil {
		return ErrNotConnected
	}
	if err := s.send(mqtt.EncodePingreq()); err != nil {
		return err
	}
	p, err := s.recv()
	if err != nil {
		return err
	}
	if p.Type != mqtt.PINGRESP {
		return fmt.Errorf("%w: want PINGRESP, got %s", ErrWrongPacketType, mqtt.TypeName(p.Type))
	}
	return nil
}

func (s *Session) Close() error {
	if s.conn == nil {
		return nil
	}
	_ = s.send(mqtt.EncodeDisconnect())
	err := s.conn.Close()
	s.conn = nil
	return err
}

func (s *Session) Proto() byte {
	return s.proto
}

func (s *Session) TLSVerifyError() string { return s.tlsVerifyErr }

func (s *Session) TLSNotAfter() string { return s.tlsNotAfter }

func (s *Session) RecvPublish(timeout time.Duration) (*mqtt.Packet, error) {
	if s.conn == nil {
		return nil, ErrNotConnected
	}
	_ = s.conn.SetReadDeadline(time.Now().Add(timeout))
	for {
		p, err := s.recv()
		if err != nil {
			return nil, err
		}
		switch p.Type {
		case mqtt.PUBLISH:
			if p.QoS > 0 {
				_ = s.send(mqtt.EncodePuback(p.PacketID))
			}
			return p, nil
		case mqtt.PINGRESP, mqtt.PUBACK, mqtt.PUBCOMP:
			continue 
		case mqtt.SUBACK, mqtt.UNSUBACK:
			continue 
		default:
			continue
		}
	}
}