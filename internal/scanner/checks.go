package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"mqtt-scan/internal/mqtt"
)

type ChecksConfig struct {
	SysWait     time.Duration
	RetainWait  time.Duration
	ProbeTopics []string
	RetainLimit int
	RunLoopback bool
}

func (c *ChecksConfig) normalize() {
	if c.SysWait == 0 {
		c.SysWait = 3 * time.Second
	}
	if c.RetainWait == 0 {
		c.RetainWait = 2 * time.Second
	}
	if len(c.ProbeTopics) == 0 {
		c.ProbeTopics = []string{"#"}
	}
	if c.RetainLimit == 0 {
		c.RetainLimit = 50
	}
}

type CheckResults struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Proto        string `json:"proto"`
	AuthStatus   string `json:"auth_status"`
	TLSVerifyError string `json:"tls_verify_error,omitempty"`
	TLSNotAfter    string `json:"tls_not_after,omitempty"`
	RejectReason string `json:"reject_reason,omitempty"`
	Anonymous    bool   `json:"anonymous"`

	BrokerInfo map[string]string `json:"broker_info,omitempty"`
	SysTopics  map[string]string `json:"sys_topics,omitempty"`
	Wildcard   map[string]string `json:"wildcard,omitempty"`
	Retained   *RetainedSummary  `json:"retained,omitempty"`
	PubSubOK   *bool             `json:"pubsub_ok,omitempty"`
	Errors     []string          `json:"errors,omitempty"`
}

type RetainedSummary struct {
	Count   int              `json:"count"`
	Samples []RetainedSample `json:"samples,omitempty"`
}

type RetainedSample struct {
	Topic   string `json:"topic"`
	Size    int    `json:"size"`
	Preview string `json:"preview,omitempty"`
}

func RunChecks(ctx context.Context, host string, port int, opts Options, cfg ChecksConfig) (*CheckResults, error) {
	cfg.normalize()
	res := &CheckResults{Host: host, Port: port, BrokerInfo: map[string]string{}}

	anonOpts := opts 
	anonOpts.Username, anonOpts.Password = "", ""

	sess, err := New(ctx, host, port, anonOpts)
	if err != nil {
		return res, err
	}

	recordTLS := func() {
		res.TLSVerifyError = sess.TLSVerifyError()
		res.TLSNotAfter = sess.TLSNotAfter()
	}
	recordTLS() 

	outcome, err := sess.Connect(ctx)
	if err == nil {
		res.Anonymous = true
		res.AuthStatus = "anonymous"
		res.Proto = protoName(sess.Proto())
		res.BrokerInfo = outcome.BrokerInfo
	} else if isAuthFailure(err, outcome) {
		if opts.Username != "" {
			_ = sess.Close()
			sess, err = New(ctx, host, port, opts)
			if err != nil {
				return res, err 
			}
			recordTLS()
			outcome, err = sess.Connect(ctx)
			if err == nil {
				res.AuthStatus = "credentials"
				res.Proto = protoName(sess.Proto())
				res.BrokerInfo = outcome.BrokerInfo
			}
		}
		if err != nil {
			res.AuthStatus = "rejected"
			res.RejectReason = outcome.BrokerReason
			_ = sess.Close()
			return res, nil
		}
	} else {
		_ = sess.Close()
		return res, err
	}

	defer sess.Close()

	checkRetained(ctx, sess, cfg, res)
	checkSysInfo(ctx, sess, cfg, res)
	checkWildcard(ctx, sess, res)
	checkLoopback(ctx, sess, cfg, res)

	return res, nil
}


func checkRetained(ctx context.Context, s *Session, cfg ChecksConfig, res *CheckResults) {
	codes, err := s.Subscribe(ctx, 0, cfg.ProbeTopics...)
	if err != nil {
		res.Errors = append(res.Errors, "retained subscribe: "+err.Error())
		return
	}
	if allSubsFailed(codes) {
		res.Retained = &RetainedSummary{}
		_ = s.Unsubscribe(ctx, cfg.ProbeTopics...)
		return
	}

	summary := &RetainedSummary{}
	deadline := time.Now().Add(cfg.RetainWait)
	for len(summary.Samples) < cfg.RetainLimit && time.Now().Before(deadline) {
		p, err := s.RecvPublish(cfg.RetainWait)
		if err != nil {
			break // 超时/断连 → 静默期结束
		}
		if !p.Retain() {
			continue
		}
		summary.Count++
		if summary.Count <= 10 {
			summary.Samples = append(summary.Samples, RetainedSample{
				Topic:   p.Topic,
				Size:    len(p.Payload),
				Preview: previewBytes(p.Payload, 64),
			})
		}
	}
	res.Retained = summary
	_ = s.Unsubscribe(ctx, cfg.ProbeTopics...)
}

func checkSysInfo(ctx context.Context, s *Session, cfg ChecksConfig, res *CheckResults) {
	codes, err := s.Subscribe(ctx, 0, "$SYS/#")
	if err != nil {
		res.Errors = append(res.Errors, "sysinfo subscribe: "+err.Error())
		return
	}
	if allSubsFailed(codes) {
		return
	}

	res.SysTopics = map[string]string{}
	deadline := time.Now().Add(cfg.SysWait)
	for time.Now().Before(deadline) {
		p, err := s.RecvPublish(cfg.SysWait)
		if err != nil {
			break
		}
		res.SysTopics[p.Topic] = previewBytes(p.Payload, 128)
	}
	_ = s.Unsubscribe(ctx, "$SYS/#")
}

func checkWildcard(ctx context.Context, s *Session, res *CheckResults) {
	filters := []string{"#", "+"}
	codes, err := s.Subscribe(ctx, 1, filters...)
	if err != nil {
		res.Errors = append(res.Errors, "wildcard subscribe: "+err.Error())
		return
	}
	res.Wildcard = map[string]string{}
	for i, f := range filters {
		if i < len(codes) {
			res.Wildcard[f] = mqtt.SubackCodeName(codes[i])
		}
	}
	_ = s.Unsubscribe(ctx, filters...)
}

func checkLoopback(ctx context.Context, s *Session, cfg ChecksConfig, res *CheckResults) {
	if !cfg.RunLoopback {
		return
	}
	topic := fmt.Sprintf("mqttscan/loop/%d", time.Now().UnixNano()%1_000_000)
	payload := []byte(fmt.Sprintf("loop-%d", time.Now().UnixNano()))

	if _, err := s.Subscribe(ctx, 0, topic); err != nil {
		res.Errors = append(res.Errors, "loopback subscribe: "+err.Error())
		return
	}
	defer func() { _ = s.Unsubscribe(ctx, topic) }()

	if err := s.Publish(ctx, topic, 1, false, payload); err != nil {
		res.Errors = append(res.Errors, "loopback publish: "+err.Error())
		res.PubSubOK = boolPtr(false)
		return
	}

	p, err := s.RecvPublish(3 * time.Second)
	if err != nil {
		res.PubSubOK = boolPtr(false)
		return
	}
	ok := p.Topic == topic && string(p.Payload) == string(payload)
	res.PubSubOK = &ok
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

func allSubsFailed(codes []byte) bool {
	if len(codes) == 0 {
		return true
	}
	for _, c := range codes {
		if c < 0x80 {
			return false
		}
	}
	return true
}

func protoName(p byte) string {
	if p == mqtt.ProtoV50 {
		return "5.0"
	}
	return "3.1.1"
}

func boolPtr(b bool) *bool { return &b }

func previewBytes(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7E {
			return fmt.Sprintf("%X", b)
		}
	}
	return string(b)
}