package integration_test

import (
	"context"
	"io"
	"net"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence"
	"github.com/shuntps/project_prometheus/services/core-api/internal/testsupport/postgresfixture"
)

// The image is pinned by digest so this evidence is reproducible. The credentials
// are fictitious, live only in the throwaway container and are never production.
const ()

var (
	storeOnce sync.Once
	storeDSN  string
	storeErr  error
	storeStop func()
)

func TestMain(m *testing.M) {
	code := m.Run()
	if storeStop != nil {
		storeStop()
	}
	os.Exit(code)
}

// realPostgres starts one PostgreSQL server for the whole package the first
// time a test asks for it, and returns its address and connection string.
func realPostgres(t *testing.T) (dsn string, address string) {
	t.Helper()
	storeOnce.Do(startPostgres)
	if storeErr != nil {
		t.Fatalf("starting PostgreSQL failed: %v", storeErr)
	}
	parsed, err := url.Parse(storeDSN)
	if err != nil {
		t.Fatalf("the container returned an unusable connection string")
	}
	return storeDSN, parsed.Host
}

func startPostgres() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// No extra argument is passed: the connection string must carry no sslmode,
	// because the typed setting is the single authority over that.
	instance, err := postgresfixture.Start(ctx)
	storeStop = instance.Terminate
	if err != nil {
		storeErr = err
		return
	}
	storeDSN = instance.DSN()
}

// testSettings mirrors the development posture: a local server over loopback.
func testSettings() persistence.Settings {
	return persistence.Settings{
		TLSMode:         persistence.TLSDisable,
		MaxConns:        4,
		MinConns:        0,
		MaxConnLifetime: time.Hour,
		MaxConnIdleTime: 30 * time.Minute,
		ConnectTimeout:  5 * time.Second,
		CheckTimeout:    2 * time.Second,
	}
}

// dsnFor rewrites the host of the container's connection string so a test can
// reach the same server through an address it controls.
func dsnFor(t *testing.T, dsn, host string) persistence.DSN {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("the connection string could not be rewritten")
	}
	parsed.Host = host
	return persistence.NewDSN(parsed.String())
}

// availableStore satisfies the boundary for constructor checks that are not
// about the store itself.
type availableStore struct{}

func (availableStore) Check(context.Context) error { return nil }

// gate forwards TCP to a real server and can be dropped and restored at a stable
// address, so an outage and its recovery need no restart of the server behind it.
type gate struct {
	listener net.Listener
	target   string
	up       atomic.Bool
	mu       sync.Mutex
	live     map[net.Conn]struct{}
	wg       sync.WaitGroup
}

func newGate(t *testing.T, target string) *gate {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not open the gate: %v", err)
	}
	g := &gate{listener: listener, target: target, live: map[net.Conn]struct{}{}}
	g.up.Store(true)
	g.wg.Add(1)
	go g.accept()
	t.Cleanup(g.close)
	return g
}

func (g *gate) addr() string { return g.listener.Addr().String() }

func (g *gate) accept() {
	defer g.wg.Done()
	for {
		client, err := g.listener.Accept()
		if err != nil {
			return
		}
		if !g.up.Load() {
			_ = client.Close()
			continue
		}
		server, err := net.DialTimeout("tcp", g.target, 2*time.Second)
		if err != nil {
			_ = client.Close()
			continue
		}
		g.track(client, server)
		g.wg.Add(2)
		go g.pipe(client, server)
		go g.pipe(server, client)
	}
}

func (g *gate) track(conns ...net.Conn) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, c := range conns {
		g.live[c] = struct{}{}
	}
}

func (g *gate) pipe(dst, src net.Conn) {
	defer g.wg.Done()
	_, _ = io.Copy(dst, src)
	_ = dst.Close()
	_ = src.Close()
	g.mu.Lock()
	delete(g.live, dst)
	delete(g.live, src)
	g.mu.Unlock()
}

// down refuses new connections and cuts the live ones, which is what a store
// becoming unreachable looks like to a pool holding open connections.
func (g *gate) down() {
	g.up.Store(false)
	g.mu.Lock()
	for c := range g.live {
		_ = c.Close()
	}
	g.live = map[net.Conn]struct{}{}
	g.mu.Unlock()
}

func (g *gate) raise() { g.up.Store(true) }

func (g *gate) close() {
	g.down()
	_ = g.listener.Close()
	g.wg.Wait()
}
