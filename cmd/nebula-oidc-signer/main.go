// Command nebula-oidc-signer issues short-lived Nebula host certificates in
// exchange for OIDC ID tokens (people) or Kubernetes service account tokens
// (workloads), signing with a CA key held in OpenBao/Vault transit.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/awapf/nebula-oidc-signer/internal/client"
	"github.com/awapf/nebula-oidc-signer/internal/config"
	"github.com/awapf/nebula-oidc-signer/internal/server"
)

type env struct {
	stdout, stderr io.Writer
	// openURL shows the login URL; nil prints it and tries a browser.
	openURL func(string) error
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], env{stdout: os.Stdout, stderr: os.Stderr}); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "nebula-oidc-signer:", err)
		os.Exit(1)
	}
}

const usage = `usage:
  nebula-oidc-signer serve --config FILE
  nebula-oidc-signer client --server URL --out-dir DIR (--token-file FILE | --issuer URL --client-id ID --device NAME) [flags]

Run "nebula-oidc-signer <command> -h" for the flags of a command.`

func run(ctx context.Context, args []string, e env) error {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(e.stderr, usage)
		return errors.New("no command")
	}
	switch args[0] {
	case "serve":
		return serve(ctx, args[1:], e)
	case "client":
		return runClient(ctx, args[1:], e)
	case "-h", "--help", "help":
		_, _ = fmt.Fprintln(e.stdout, usage)
		return nil
	}
	_, _ = fmt.Fprintln(e.stderr, usage)
	return fmt.Errorf("unknown command %q", args[0])
}

func serve(ctx context.Context, args []string, e env) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	cfgFile := fs.String("config", "", "configuration file (YAML)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgFile == "" {
		return errors.New("serve: --config is required")
	}
	cfg, err := config.Load(*cfgFile)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(e.stderr, nil))
	s, err := server.New(ctx, cfg, server.Options{Logger: log})
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	hs := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
	}
	errc := make(chan error, 1)
	go func() {
		if cfg.TLS != nil {
			hs.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			errc <- hs.ServeTLS(ln, cfg.TLS.CertFile, cfg.TLS.KeyFile)
		} else {
			errc <- hs.Serve(ln)
		}
	}()
	log.Info("listening", "addr", ln.Addr().String(), "tls", cfg.TLS != nil)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := hs.Shutdown(shutdown); err != nil {
		return err
	}
	if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func runClient(ctx context.Context, args []string, e env) error {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	var (
		serverURL   = fs.String("server", "", "signer base URL")
		serverCA    = fs.String("server-ca", "", "PEM file with CAs to trust for the signer's TLS certificate")
		outDir      = fs.String("out-dir", "", "directory for host.crt, host.key and ca.crt")
		tokenFile   = fs.String("token-file", "", "read the token from this file (e.g. a projected Kubernetes service account token)")
		issuer      = fs.String("issuer", "", "OIDC issuer URL (people)")
		clientID    = fs.String("client-id", "", "OIDC client ID (people)")
		secretFile  = fs.String("client-secret-file", "", "file with the OIDC client secret, for confidential clients")
		scopes      = fs.String("scopes", "openid,profile", "comma-separated OIDC scopes")
		acrValues   = fs.String("acr-values", "", "acr_values to request (e.g. the passkey ACR)")
		device      = fs.String("device", "", "device name for people certificates (a-z, 0-9, '-')")
		writeConfig = fs.String("write-config", "", "also write a nebula config (lighthouses from the signer, files from --out-dir) to this file")
		pidFile     = fs.String("pidfile", "", "send SIGHUP to the nebula process in this pid file after renewing")
		renewBefore = fs.Duration("renew-before", 0, "only renew when the current certificate expires within this duration")
		watch       = fs.Duration("watch", 0, "keep running and check every interval (use with --renew-before)")
		rotateKey   = fs.Bool("rotate-key", false, "generate a new key pair instead of reusing host.key")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *serverURL == "" || *outDir == "" {
		return errors.New("client: --server and --out-dir are required")
	}
	hc := &http.Client{Timeout: 30 * time.Second}
	if *serverCA != "" {
		b, err := os.ReadFile(*serverCA)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(b) {
			return fmt.Errorf("%s holds no PEM certificates", *serverCA)
		}
		hc.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	}

	var src client.TokenSource
	switch {
	case *tokenFile != "" && *issuer != "":
		return errors.New("client: use either --token-file or --issuer, not both")
	case *tokenFile != "":
		src = client.FileToken(*tokenFile)
	case *issuer != "" && *clientID != "":
		o := &client.OIDC{
			Issuer: *issuer, ClientID: *clientID, ACRValues: *acrValues,
			Scopes: strings.Split(*scopes, ","), OpenURL: e.openURL,
		}
		if o.OpenURL == nil {
			o.OpenURL = func(u string) error { return openBrowser(e.stderr, u) }
		}
		if *secretFile != "" {
			b, err := os.ReadFile(*secretFile)
			if err != nil {
				return err
			}
			o.ClientSecret = strings.TrimSpace(string(b))
		}
		src = o
	default:
		return errors.New("client: need --token-file, or --issuer and --client-id")
	}

	o := client.Options{
		Server: *serverURL, HTTPClient: hc, Token: src, Device: *device, OutDir: *outDir,
		ConfigFile: *writeConfig, PIDFile: *pidFile, RenewBefore: *renewBefore, RotateKey: *rotateKey,
	}
	if *watch > 0 {
		return client.Watch(ctx, o, *watch, func(err error) { _, _ = fmt.Fprintln(e.stderr, "renewal failed:", err) })
	}
	res, err := client.Run(ctx, o)
	if err != nil {
		return err
	}
	if res.Renewed {
		_, _ = fmt.Fprintf(e.stdout, "wrote %s, valid until %s\n", *outDir, res.NotAfter.UTC().Format(time.RFC3339))
	} else {
		_, _ = fmt.Fprintf(e.stdout, "certificate valid until %s, not renewed\n", res.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

// openBrowser prints the URL and tries to open it; failing to launch a
// browser is not an error.
func openBrowser(w io.Writer, u string) error {
	_, _ = fmt.Fprintf(w, "Open this URL to log in:\n\n  %s\n\n", u)
	// The URL comes from the IdP's discovery document: never hand anything
	// but http(s) to the system opener.
	if pu, err := url.Parse(u); err != nil || (pu.Scheme != "https" && pu.Scheme != "http") {
		return fmt.Errorf("refusing to open non-http(s) authorization URL")
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u) //nolint:gosec // http(s) URL checked above, no shell
	case "linux", "freebsd", "openbsd", "netbsd":
		cmd = exec.Command("xdg-open", u) //nolint:gosec // http(s) URL checked above, no shell
	default:
		return nil
	}
	if err := cmd.Start(); err == nil {
		go func() { _ = cmd.Wait() }()
	}
	return nil
}
