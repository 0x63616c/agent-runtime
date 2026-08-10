package sandboxcontrolprocess

import (
	"errors"
	"net"
	"testing"
)

func TestBindListenersAnnouncesOnlyAfterEveryDeclaredListenerIsBound(t *testing.T) {
	t.Parallel()

	public := &recordingListener{address: "127.0.0.1:41001"}
	host := &recordingListener{address: "0.0.0.0:41002"}
	var calls []string
	var observed BoundAddresses
	listeners, err := bindListeners("127.0.0.1:0", &hostControlConfig{listenAddress: "0.0.0.0:0"}, func(_, address string) (net.Listener, error) {
		calls = append(calls, address)
		switch address {
		case "127.0.0.1:0":
			return public, nil
		case "0.0.0.0:0":
			return host, nil
		default:
			t.Fatalf("unexpected listener address %q", address)
			return nil, nil
		}
	}, func(addresses BoundAddresses) { observed = addresses })
	if err != nil {
		t.Fatalf("bindListeners() error = %v", err)
	}
	if listeners.public != public || listeners.host != host {
		t.Fatalf("listeners = %#v, want both declared listeners", listeners)
	}
	if len(calls) != 2 || calls[0] != "127.0.0.1:0" || calls[1] != "0.0.0.0:0" {
		t.Fatalf("listen calls = %q, want public then host", calls)
	}
	if observed != (BoundAddresses{Public: "127.0.0.1:41001", HostControl: "0.0.0.0:41002"}) {
		t.Fatalf("ready addresses = %#v", observed)
	}
}

func TestBindListenersClosesPublicListenerAndDoesNotAnnounceWhenHostBindFails(t *testing.T) {
	t.Parallel()

	public := &recordingListener{address: "127.0.0.1:41001"}
	var announced bool
	_, err := bindListeners("127.0.0.1:0", &hostControlConfig{listenAddress: "0.0.0.0:0"}, func(_, address string) (net.Listener, error) {
		if address == "127.0.0.1:0" {
			return public, nil
		}
		return nil, errors.New("host listener already in use")
	}, func(BoundAddresses) { announced = true })
	if err == nil {
		t.Fatal("bindListeners() error = nil")
	}
	if announced {
		t.Fatal("bindListeners() announced readiness after host listener failure")
	}
	if !public.closed {
		t.Fatal("bindListeners() did not close public listener after host listener failure")
	}
}

type recordingListener struct {
	address string
	closed  bool
}

func (listener *recordingListener) Accept() (net.Conn, error) {
	return nil, errors.New("accept is not used")
}
func (listener *recordingListener) Close() error {
	listener.closed = true
	return nil
}
func (listener *recordingListener) Addr() net.Addr { return recordingAddress(listener.address) }

type recordingAddress string

func (address recordingAddress) Network() string { return "tcp" }
func (address recordingAddress) String() string  { return string(address) }
