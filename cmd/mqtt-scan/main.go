package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"mqtt-scan/internal/engine"
	"mqtt-scan/internal/mqtt"
	"mqtt-scan/internal/scanner"
)

type targetsFlag []string

func (t *targetsFlag) String() string     { return strings.Join(*t, ",") }
func (t *targetsFlag) Set(v string) error { *t = append(*t, v); return nil }

var version = "dev"

func usage() {
	fmt.Fprint(os.Stderr, `mqtt-scan - MQTT broker scanner (v3.1.1 / 5.0)

Usage:
  mqtt-scan -target <host|cidr[:port]> [-target ...] [-f file|-] [options]

Target forms:
  10.0.0.5                 scan with default ports (-p)
  broker.example.com:8883  single host:port
  10.0.0.0/24:1883         CIDR expanded with given port
  0.0.0.0/0                [CHG] any CIDR size accepted, streamed (memory-safe)

Options:
`)
	flag.PrintDefaults()
}

func main() {
	os.Exit(run())
}

func run() int {
	var (
		targets     targetsFlag
		targetFile  string
		portSpec    = flag.String("p", "1883,8883", "ports to scan (nmap style)")
		concurrency = flag.Int("c", 100, "concurrent workers")
		timeout     = flag.Duration("timeout", 5*time.Second, "per-target network timeout")
		protoStr    = flag.String("proto", "5", "preferred protocol version: 3.1.1 or 5")
		username    = flag.String("u", "", "username (empty = anonymous probe only)")
		password    = flag.String("pass", "", "password")
		clientID    = flag.String("client-id", "", "MQTT client id (auto-generated if empty)")
		tlsMode     = flag.String("tls", "auto", "TLS mode: auto(8883) / always / never")
		outPath     = flag.String("o", "", "output file (JSON Lines, default stdout)")
		sysWait     = flag.Duration("sys-wait", 3*time.Second, "$SYS collection window")
		retainWait  = flag.Duration("retain-wait", 2*time.Second, "retained message quiet window")
		noLoopback  = flag.Bool("no-loopback", false, "skip publish loopback test")
		showVer     = flag.Bool("version", false, "print version")
	)
	flag.Usage = usage
	flag.Var(&targets, "target", "target host/cidr[:port], repeatable")
	flag.StringVar(&targetFile, "f", "", "targets file, one per line ('-' = stdin)")
	flag.Parse()

	if *showVer {
		fmt.Println("mqtt-scan", version)
		return 0
	}

	proto := mqtt.ProtoV50
	if *protoStr == "3.1.1" {
		proto = mqtt.ProtoV311
	}

	defaultPorts, err := engine.ParsePorts(*portSpec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}

	cfg := engine.Config{
		Concurrency: *concurrency,
		Timeout:     *timeout,
		TLSMode:     *tlsMode,
		Proto:       proto,
		Username:    *username,
		Password:    *password,
		ClientID:    *clientID,
		Checks: scanner.ChecksConfig{
			SysWait:     *sysWait,
			RetainWait:  *retainWait,
			RunLoopback: !*noLoopback,
		},
	}

	var rawLines []string
	rawLines = append(rawLines, targets...)
	if targetFile != "" {
		var f *os.File
		if targetFile == "-" {
			f = os.Stdin
		} else {
			if f, err = os.Open(targetFile); err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				return 2
			}
			defer f.Close()
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			rawLines = append(rawLines, sc.Text())
		}
	}
	if len(rawLines) == 0 {
		usage()
		return 2
	}

	var total uint64
	for _, line := range rawLines {
		n, err := engine.CountTargets(line, defaultPorts)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 2
		}
		total += n
	}
	if total == 0 {
		fmt.Fprintln(os.Stderr, "error: no targets")
		return 2
	}
	fmt.Fprintf(os.Stderr, "mqtt-scan: %d target(s), concurrency=%d\n", total, cfg.Concurrency)

	const hugeScan = 1 << 24
	if total > hugeScan {
		fmt.Fprintf(os.Stderr, "mqtt-scan: WARNING: %d targets — full TCP+MQTT probing is very slow at this scale; "+
			"consider -timeout 2s and higher -c, or pre-filter with masscan. Ctrl-C aborts cleanly.\n", total)
	}

	out := io.Writer(os.Stdout)
	if *outPath != "" {
		f, err := os.Create(*outPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 2
		}
		defer f.Close()
		out = bufio.NewWriter(f)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	targetCh := make(chan engine.Target, 4096)
	pumpDone := make(chan error, 1)
	go func() {
		defer close(targetCh)
		for _, line := range rawLines {
			if err := engine.StreamTargets(ctx, line, defaultPorts, targetCh); err != nil {
				pumpDone <- err
				return
			}
		}
		pumpDone <- nil
	}()

	start := time.Now()
	errCount := engine.RunStream(ctx, targetCh, total, cfg, out, func(done, t uint64) {
		pct := 0.0
		if t > 0 {
			pct = float64(done) / float64(t) * 100
		}
		fmt.Fprintf(os.Stderr, "\r[%d/%d %.3f%%]", done, t, pct)
	})

	if pumpErr := <-pumpDone; pumpErr != nil && !errors.Is(pumpErr, context.Canceled) {
		fmt.Fprintln(os.Stderr, "\nmqtt-scan: target pump error:", pumpErr)
		return 2
	}

	if ctx.Err() != nil {
		fmt.Fprintln(os.Stderr, "\nmqtt-scan: interrupted")
		return 130
	}

	fmt.Fprintf(os.Stderr, "\nmqtt-scan: done in %s\n", time.Since(start).Round(time.Millisecond))
	if errCount > 0 {
		fmt.Fprintf(os.Stderr, "mqtt-scan: %d target(s) failed at infrastructure level\n", errCount)
		return 1
	}
	return 0
}
