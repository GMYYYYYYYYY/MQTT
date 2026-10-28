package mqtt

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	ProtoV311 byte = 0x04 // "MQTT"
	ProtoV50  byte = 0x05 // "MQTT"
)

// 报文类型（固定头高 4 位）
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

var typeNames = [...]string{
	"", "CONNECT", "CONNACK", "PUBLISH", "PUBACK", "PUBREC", "PUBREL",
	"PUBCOMP", "SUBSCRIBE", "SUBACK", "UNSUBSCRIBE", "UNSUBACK",
	"PINGREQ", "PINGRESP", "DISCONNECT", "AUTH",
}

func TypeName(t byte) string {
	if int(t) < len(typeNames) {
		return typeNames[t]
	}
	return fmt.Sprintf("Unknown(%d)", t)
}

const flagMandatory byte = 0b0010

var v3ConnackNames = map[byte]string{
	0: "Accepted", 1: "UnacceptableProtocolVersion", 2: "IdentifierRejected",
	3: "ServerUnavailable", 4: "BadUserNameOrPassword", 5: "NotAuthorized",
}

const (
	ReasonSuccess       byte = 0x00
	ReasonNoMatchingSub byte = 0x10
	ReasonNotAuthorized byte = 0x87
	ReasonBadAuthMethod byte = 0x8C
	ReasonQoSNotSupport byte = 0x9B
	ReasonWildcardUnsup byte = 0xA2
)

var reasonNames = map[byte]string{
	0x00: "Success", 0x04: "DisconnectWithWill", 0x10: "NoMatchingSubscribers",
	0x11: "NoSubscriptionExisted", 0x18: "ContinueAuthentication", 0x80: "UnspecifiedError",
	0x81: "MalformedPacket", 0x82: "ProtocolError", 0x84: "UnsupportedProtocolVersion",
	0x85: "ClientIDNotValid", 0x86: "BadUserNameOrPassword", 0x87: "NotAuthorized",
	0x88: "ServerUnavailable", 0x89: "ServerBusy", 0x8A: "Banned",
	0x8C: "BadAuthenticationMethod", 0x8D: "KeepAliveTimeout", 0x8E: "SessionTakenOver",
	0x8F: "TopicFilterInvalid", 0x90: "TopicNameInvalid", 0x92: "PacketIDNotFound",
	0x95: "PacketTooLarge", 0x97: "QuotaExceeded", 0x99: "PayloadFormatInvalid",
	0x9A: "RetainNotSupported", 0x9B: "QoSNotSupported", 0x9E: "SharedSubsNotSupported",
	0x9F: "ConnectionRateExceeded", 0xA2: "WildcardSubsNotSupported",
}

func ReasonName(c byte) string {
	if s, ok := reasonNames[c]; ok {
		return s
	}
	return fmt.Sprintf("0x%02X", c)
}

func V3ConnackName(c byte) string {
	if s, ok := v3ConnackNames[c]; ok {
		return s
	}
	return fmt.Sprintf("Unknown(%d)", c)
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
	value, multiplier := 0, 1
	for i := 0; i < 4; i++ {
		if off >= len(buf) {
			return 0, off, errors.New("vbi: incomplete")
		}
		b := buf[off]
		off++
		value += int(b&0x7F) * multiplier
		if b&0x80 == 0 {
			return value, off, nil
		}
		multiplier *= 128
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

type Packet struct {
	Type  byte
	Flags byte
	Raw   []byte

	PacketID       uint16
	Reason         byte
	ReturnCode     byte
	SessionPresent bool
	SubCodes       []byte
	Topic          string // PUBLISH
	Payload        []byte // PUBLISH
	Properties     []byte
	QoS            byte 
}

func (p *Packet) Dup() bool    { return p.Flags&0b1000 != 0 }
func (p *Packet) Retain() bool { return p.Flags&0b0001 != 0 }

func EncodeConnect(level byte, clientID, user, pass string, keepAlive uint16) []byte {
	var flags byte = 0x02 // Clean Session
	if user != "" {
		flags |= 0x80
	}
	if pass != "" {
		flags |= 0x40
	}

	vh := append(encodeString("MQTT"), level, flags)
	vh = append(vh, byte(keepAlive>>8), byte(keepAlive))

	var payload []byte
	payload = append(payload, encodeString(clientID)...)
	if user != "" {
		payload = append(payload, encodeString(user)...)
	}
	if pass != "" {
		payload = append(payload, encodeString(pass)...)
	}
	return buildPacket(CONNECT, 0, append(vh, payload...))
}

func EncodePublish(level byte, topic string, qos byte, retain bool, id uint16, payload []byte) []byte {
	if qos > 2 {
		qos = 2
	}
	flags := qos << 1
	if retain {
		flags |= 0b0001
	}
	vh := encodeString(topic)
	if qos > 0 {
		vh = append(vh, byte(id>>8), byte(id))
	}
	return buildPacket(PUBLISH, flags, append(vh, payload...))
}

func EncodeSubscribe(level byte, id uint16, qos byte, topics ...string) []byte {
	vh := []byte{byte(id >> 8), byte(id)}
	var payload []byte
	for _, t := range topics {
		payload = append(payload, encodeString(t)...)
		opt := qos & 0x03
		if level == ProtoV50 {
			opt = qos
		}
		payload = append(payload, opt)
	}
	return buildPacket(SUBSCRIBE, flagMandatory, append(vh, payload...))
}

func EncodeUnsubscribe(level byte, id uint16, topics ...string) []byte {
	vh := []byte{byte(id >> 8), byte(id)}
	var _ = level 
	var payload []byte
	for _, t := range topics {
		payload = append(payload, encodeString(t)...)
	}
	return buildPacket(UNSUBSCRIBE, flagMandatory, append(vh, payload...))
}

func encodeAck(typ byte, id uint16) []byte {
	flags := byte(0)
	if typ == PUBREL {
		flags = flagMandatory
	}
	return buildPacket(typ, flags, []byte{byte(id >> 8), byte(id)})
}

func EncodePingreq() []byte { return []byte{PINGREQ << 4, 0x00} }

func EncodeDisconnect() []byte { return []byte{DISCONNECT << 4, 0x00} }

func EncodePuback(id uint16) []byte { return encodeAck(PUBACK, id) }

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

func Decode(data []byte, proto byte) (*Packet, error) {
	if len(data) < 2 {
		return nil, errors.New("packet: too short")
	}
	p := &Packet{Type: data[0] >> 4, Flags: data[0] & 0x0F, Raw: append([]byte(nil), data...)}
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
			p.Reason = body[1]
			_, p.Properties = v5Trailer(body, 1)
		} else {
			p.ReturnCode = body[1]
		}

	case PUBLISH:
		p.QoS = (p.Flags & 0b0110) >> 1
		if p.QoS == 3 {
			return nil, errors.New("publish: invalid QoS=3")
		}
		topic, n, err := decodeString(body, 0)
		if err != nil {
			return nil, err
		}
		p.Topic = topic
		off = n
		if p.QoS > 0 {
			if off+2 > len(body) {
				return nil, errors.New("publish: missing packet id")
			}
			p.PacketID = binary.BigEndian.Uint16(body[off:])
			off += 2
		}
		if proto == ProtoV50 {
			propLen, n2, err := decodeVBI(body, off)
			if err != nil {
				return nil, err
			}
			p.Properties = body[n2 : n2+propLen]
			off = n2 + propLen
		}
		p.Payload = append([]byte(nil), body[off:]...)

	case SUBACK:
		if len(body) < 2 {
			return nil, errors.New("suback: body < 2")
		}
		p.PacketID = binary.BigEndian.Uint16(body[:2])
		off = 2
		if proto == ProtoV50 {
			propLen, n, err := decodeVBI(body, off)
			if err != nil {
				return nil, err
			}
			p.Properties = body[n : n+propLen]
			off = n + propLen
		}
		p.SubCodes = append([]byte(nil), body[off:]...)

	case PUBACK, PUBREC, PUBREL, PUBCOMP, UNSUBACK:
		if len(body) < 2 {
			return nil, errors.New("ack: body < 2")
		}
		p.PacketID = binary.BigEndian.Uint16(body[:2])
		if proto == ProtoV50 {
			p.Reason, p.Properties = v5Trailer(body, 2)
		}

	case DISCONNECT:
		if proto == ProtoV50 {
			p.Reason, p.Properties = v5Trailer(body, 0)
		}

	case AUTH:
		p.Reason, p.Properties = v5Trailer(body, 0)

	case PINGRESP:

	default:
		p.Payload = append([]byte(nil), body...)
	}
	return p, nil
}

func DecodeVBI(buf []byte, off int) (int, int, error) { return decodeVBI(buf, off) }

var propSizes = map[byte]int{
	0x01: 1, 0x02: 4, 0x03: -1, 0x08: -1, 0x09: -1, 0x0B: -2, 0x11: 4,
	0x12: -1, 0x13: 2, 0x15: -1, 0x16: -1, 0x17: 1, 0x18: 4, 0x19: 1,
	0x1A: -1, 0x1C: -1, 0x1F: -1, 0x21: 2, 0x22: 2, 0x23: 2, 0x24: 1,
	0x25: 1, 0x26: -3, 0x27: 4, 0x28: 1, 0x29: 1, 0x2A: 1,
}

const (
	PropAssignedClientID   byte = 0x12
	PropServerKeepAlive    byte = 0x13
	PropServerReference    byte = 0x1C
	PropReasonString       byte = 0x1F
	PropTopicAliasMaximum  byte = 0x22
	PropMaximumQoS         byte = 0x24
	PropRetainAvailable    byte = 0x25
	PropWildcardSubAllowed byte = 0x28
	PropSharedSubAllowed   byte = 0x2A
)

func GetProperty(props []byte, id byte) ([]byte, bool) {
	off := 0
	for off < len(props) {
		pid, n, err := decodeVBI(props, off)
		if err != nil || pid > 0xFF {
			return nil, false
		}
		off = n
		sz := propSizes[byte(pid)]

		var val []byte
		switch {
		case sz > 0:
			if off+sz > len(props) {
				return nil, false
			}
			val = props[off : off+sz]
			off += sz
		case sz == -1:
			v, n2, err := decodeString(props, off)
			if err != nil {
				return nil, false
			}
			val, off = []byte(v), n2
		case sz == -2:
			_, n2, err := decodeVBI(props, off)
			if err != nil {
				return nil, false
			}
			val, off = props[off:n2], n2
		case sz == -3:
			_, n2, err := decodeString(props, off)
			if err != nil {
				return nil, false
			}
			v, n3, err := decodeString(props, n2)
			if err != nil {
				return nil, false
			}
			val, off = []byte(v), n3
		default:
			return nil, false
		}
		if byte(pid) == id {
			return val, true
		}
	}
	return nil, false
}

const ReasonUnsupportedProtoVer byte = 0x84

const (
	ConnAccepted        byte = 0x00 // 连接接受
	ConnBadProtoVersion byte = 0x01 // 不可接受的协议版本 —— v3 对端拒绝 v5 请求的信号
)

const PropWildcardSubAvailable byte = 0x28

func EncodePubrel(id uint16) []byte {
	return []byte{0x62, 0x02, byte(id >> 8), byte(id)}
}

func SubackCodeName(c byte) string {
	switch c {
	case 0x00:
		return "granted_qos0"
	case 0x01:
		return "granted_qos1"
	case 0x02:
		return "granted_qos2"
	case 0x80:
		return "failure"
	case 0x87:
		return "not_authorized"
	case 0xA1:
		return "wildcard_not_supported"
	}
	if c >= 0x80 {
		return fmt.Sprintf("failure_0x%02X", c)
	}
	return fmt.Sprintf("code_0x%02X", c)
}