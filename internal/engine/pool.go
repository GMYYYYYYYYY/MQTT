package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"mqtt-scan/internal/scanner"
)

type Target struct {
	Host string
	Port int
}

func (t Target) String() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

func ParsePorts(spec string) ([]int, error) {
	var out []int
	seen := map[int]bool{}
	add := func(n int) error {
		if n <= 0 || n > 65535 {
			return fmt.Errorf("port %d out of range", n)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
		return nil
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			a, err1 := strconv.Atoi(strings.TrimSpace(lo))
			b, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("bad port range %q", part)
			}
			if a > b {
				a, b = b, a
			}
			if b-a > 1000 {
				return nil, fmt.Errorf("port range %q too large (>1000)", part)
			}
			for i := a; i <= b; i++ {
				if err := add(i); err != nil {
					return nil, err
				}
			}
		} else {
			n, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("bad port %q", part)
			}
			if err := add(n); err != nil {
				return nil, err
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("empty port spec")
	}
	return out, nil
}

func ParseTargets(line string, defaultPorts []int) ([]Target, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, nil
	}
	ports := defaultPorts
	hostPart := line
	if h, p, err := net.SplitHostPort(line); err == nil {
		hostPart = h
		ports, err = ParsePorts(p)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", line, err)
		}
	}
	if strings.Contains(hostPart, "/") {
		prefix, err := netip.ParsePrefix(hostPart)
		if err != nil {
			return nil, fmt.Errorf("bad CIDR %q: %w", hostPart, err)
		}
		prefix = prefix.Masked()
		var targets []Target
		for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
			for _, p := range ports {
				targets = append(targets, Target{Host: addr.String(), Port: p})
			}
		}
		return targets, nil
	}
	var targets []Target
	for _, p := range ports {
		targets = append(targets, Target{Host: hostPart, Port: p})
	}
	return targets, nil
}

func CountTargets(line string, defaultPorts []int) (uint64, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return 0, nil
	}
	ports := defaultPorts
	hostPart := line
	if h, p, err := net.SplitHostPort(line); err == nil {
		hostPart = h
		ports, err = ParsePorts(p)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", line, err)
		}
	}
	if strings.Contains(hostPart, "/") {
		prefix, err := netip.ParsePrefix(hostPart)
		if err != nil {
			return 0, fmt.Errorf("bad CIDR %q: %w", hostPart, err)
		}
		prefix = prefix.Masked()
		hostBits := prefix.Addr().BitLen() - prefix.Bits()

		if hostBits >= 48 {
			return 0, fmt.Errorf("CIDR %s too large to count (%d host bits)", prefix, hostBits)
		}
		return (uint64(1) << hostBits) * uint64(len(ports)), nil
	}
	return uint64(len(ports)), nil
}

func StreamTargets(ctx context.Context, line string, defaultPorts []int, out chan<- Target) error {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}
	ports := defaultPorts
	hostPart := line
	if h, p, err := net.SplitHostPort(line); err == nil {
		hostPart = h
		ports, err = ParsePorts(p)
		if err != nil {
			return fmt.Errorf("%s: %w", line, err)
		}
	}
	if strings.Contains(hostPart, "/") {
		prefix, err := netip.ParsePrefix(hostPart)
		if err != nil {
			return fmt.Errorf("bad CIDR %q: %w", hostPart, err)
		}
		prefix = prefix.Masked()
		for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
			for _, p := range ports {
				select {
				case out <- Target{Host: addr.String(), Port: p}:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}
		return nil
	}
	for _, p := range ports {
		out <- Target{Host: hostPart, Port: p}
	}
	return nil
}

func tlsFor(t Target, mode string) bool {
	switch mode {
	case "always":
		return true
	case "never":
		return false
	default: // auto
		return t.Port == 8883
	}
}

type Config struct {
	Concurrency int
	Timeout     time.Duration
	TLSMode     string
	Proto       byte
	Username    string
	Password    string
	ClientID    string
	Checks      scanner.ChecksConfig
}

type Result struct {
	Target    string                `json:"target"`
	Status    string                `json:"status"`
	Error     string                `json:"error,omitempty"`
	ElapsedMs int64                 `json:"elapsed_ms"`
	Scan      *scanner.CheckResults `json:"scan,omitempty"`
}

func classify(err error) string {
	var nerr net.Error
	switch {
	case err == nil:
		return "mqtt"
	case errors.Is(err, scanner.ErrWrongPacketType),
		errors.Is(err, scanner.ErrConnClosed):
		return "not_mqtt"
	case errors.Is(err, scanner.ErrNoResponse):
		return "timeout"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.EHOSTUNREACH),
		errors.Is(err, syscall.ENETUNREACH),
		errors.Is(err, syscall.ENETDOWN):
		return "unreachable"
	case errors.Is(err, syscall.ETIMEDOUT):
		return "timeout"
	case errors.As(err, &nerr) && nerr.Timeout():
		return "timeout"
	default:
		msg := err.Error()
		if strings.Contains(msg, "tls") || strings.Contains(msg, "x509") {
			return "tls_error"
		}
		if strings.Contains(msg, "decode") || strings.Contains(msg, "packet") {
			return "not_mqtt"
		}
		return "error"
	}
}

var clientIDSeq atomic.Uint64

func uniqueClientID(base string) string {
	if base == "" {
		return ""
	}

	return fmt.Sprintf("%s-%d", base, clientIDSeq.Add(1))
}

func scanOne(ctx context.Context, t Target, cfg Config) *Result {
	r := &Result{Target: t.String(), Status: "error"}
	start := time.Now()
	defer func() {
		r.ElapsedMs = time.Since(start).Milliseconds()
	}()

	opts := scanner.Options{
		ProtoLevel: cfg.Proto,
		ClientID:   uniqueClientID(cfg.ClientID),
		Username:   cfg.Username,
		Password:   cfg.Password,
		Timeout:    cfg.Timeout,
		UseTLS:     tlsFor(t, cfg.TLSMode),
	}

	scan, err := scanner.RunChecks(ctx, t.Host, t.Port, opts, cfg.Checks)
	r.Scan = scan
	if err != nil {
		r.Status = classify(err)
		r.Error = err.Error()
		return r
	}
	r.Status = "mqtt"
	return r
}

func RunStream(ctx context.Context, in <-chan Target, total uint64,
	cfg Config, out io.Writer, progress func(done, total uint64)) (errCount int) {

	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 100
	}
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)

	targetCh := make(chan Target, cfg.Concurrency)
	resultCh := make(chan *Result, cfg.Concurrency)
	var wg sync.WaitGroup

	// worker 池
	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range targetCh {
				select {
				case <-ctx.Done():
					return
				default:
				}
				resultCh <- scanOne(ctx, t, cfg)
			}
		}()
	}

	go func() {
		defer close(targetCh)
		for t := range in {
			select {
			case targetCh <- t:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	var done uint64
	for r := range resultCh {
		_ = enc.Encode(r)
		if f, ok := out.(interface{ Flush() error }); ok {
			_ = f.Flush()
		}
		if r.Status == "error" {
			errCount++
		}
		done++
		if progress != nil {
			progress(done, total)
		}
	}
	return errCount
}

func Run(ctx context.Context, targets []Target, cfg Config,
	out io.Writer, progress func(done, total int)) (errCount int) {

	ch := make(chan Target, len(targets))
	for _, t := range targets {
		ch <- t
	}
	close(ch)
	n := len(targets)
	return RunStream(ctx, ch, uint64(n), cfg, out,
		func(d, _ uint64) {
			if progress != nil {
				progress(int(d), n)
			}
		})
}