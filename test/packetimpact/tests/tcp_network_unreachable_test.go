// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tcp_synsent_reset_test

import (
	"context"
	"flag"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.Initialize(flag.CommandLine)
}

// TestTCPSynSentUnreachable verifies that TCP connections fail immediately when
// an ICMP destination unreachable message is sent in response to the inital
// SYN.
func TestTCPSynSentUnreachable(t *testing.T) {
	for _, tt := range []struct {
		desc    string
		code    header.ICMPv4Code
		wantErr unix.Errno
	}{{desc: "host_unreachable", code: header.ICMPv4HostUnreachable, wantErr: unix.EHOSTUNREACH},
		{desc: "net_prohibited", code: header.ICMPv4NetProhibited, wantErr: unix.ENETUNREACH},
		{desc: "host_prohibited", code: header.ICMPv4HostProhibited, wantErr: unix.EHOSTUNREACH},
		{desc: "admin_prohibited", code: header.ICMPv4AdminProhibited, wantErr: unix.EHOSTUNREACH}} {
		t.Run(tt.desc, func(t *testing.T) {
			// Create the DUT and connection.
			dut := testbench.NewDUT(t)
			clientFD, clientPort := dut.CreateBoundSocket(t, unix.SOCK_STREAM|unix.SOCK_NONBLOCK, unix.IPPROTO_TCP, dut.Net.RemoteIPv4)
			port := uint16(9001)
			conn := dut.Net.NewTCPIPv4(t, testbench.TCP{SrcPort: &port, DstPort: &clientPort}, testbench.TCP{SrcPort: &clientPort, DstPort: &port})
			defer conn.Close(t)

			// Bring the DUT to SYN-SENT state with a non-blocking connect.
			sa := unix.SockaddrInet4{Port: int(port)}
			copy(sa.Addr[:], dut.Net.LocalIPv4)
			if _, err := dut.ConnectWithErrno(context.Background(), t, clientFD, &sa); err != unix.EINPROGRESS {
				t.Errorf("got connect() = %v, want EINPROGRESS", err)
			}

			// Get the SYN.
			tcp, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn)}, time.Second)
			if err != nil {
				t.Fatalf("expected SYN: %s", err)
			}

			// Send a host unreachable message.
			icmpPayload := testbench.Layers{tcp.Prev(), tcp}
			bytes, err := icmpPayload.ToBytes()
			if err != nil {
				t.Fatalf("got icmpPayload.ToBytes() = (_, %s), want = (_, nil)", err)
			}

			layers := conn.CreateFrame(t, nil)
			layers[len(layers)-1] = &testbench.ICMPv4{
				Type:    testbench.ICMPv4Type(header.ICMPv4DstUnreachable),
				Code:    testbench.ICMPv4Code(tt.code),
				Payload: bytes,
			}
			conn.SendFrameStateless(t, layers)

			if err := getConnectError(t, &dut, clientFD); err != tt.wantErr {
				t.Errorf("got connect() = %s(%d), want %s(%d)", err, err, tt.wantErr, tt.wantErr)
			}
		})
	}
}

// TestTCPSynSentUnreachable6 verifies that TCP connections fail immediately when
// an ICMP destination unreachable message is sent in response to the inital
// SYN.
func TestTCPSynSentUnreachable6(t *testing.T) {
	// Create the DUT and connection.
	dut := testbench.NewDUT(t)
	clientFD, clientPort := dut.CreateBoundSocket(t, unix.SOCK_STREAM|unix.SOCK_NONBLOCK, unix.IPPROTO_TCP, dut.Net.RemoteIPv6)
	conn := dut.Net.NewTCPIPv6(t, testbench.TCP{DstPort: &clientPort}, testbench.TCP{SrcPort: &clientPort})
	defer conn.Close(t)

	// Bring the DUT to SYN-SENT state with a non-blocking connect.
	sa := unix.SockaddrInet6{
		Port:   int(conn.SrcPort()),
		ZoneId: dut.Net.RemoteDevID,
	}
	copy(sa.Addr[:], dut.Net.LocalIPv6)
	if _, err := dut.ConnectWithErrno(context.Background(), t, clientFD, &sa); err != unix.EINPROGRESS {
		t.Errorf("got connect() = %v, want EINPROGRESS", err)
	}

	// Get the SYN.
	tcp, err := conn.Expect(t, &testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn)}, time.Second)
	if err != nil {
		t.Fatalf("expected SYN: %s", err)
	}

	// Send a host unreachable message.
	icmpPayload := testbench.Layers{tcp.Prev(), tcp}
	bytes, err := icmpPayload.ToBytes()
	if err != nil {
		t.Fatalf("got icmpPayload.ToBytes() = (_, %s), want = (_, nil)", err)
	}

	layers := conn.CreateFrame(t, nil)
	layers[len(layers)-1] = &testbench.ICMPv6{
		Type:    testbench.ICMPv6Type(header.ICMPv6DstUnreachable),
		Code:    testbench.ICMPv6Code(header.ICMPv6NetworkUnreachable),
		Payload: bytes,
	}
	conn.SendFrameStateless(t, layers)

	if err := getConnectError(t, &dut, clientFD); err != unix.ENETUNREACH {
		t.Errorf("got connect() = %v, want EHOSTUNREACH", err)
	}
}

// getConnectError gets the errno generated by the on-going connect attempt on
// fd. fd must be non-blocking and there must be a connect call to fd which
// returned EINPROGRESS before. These conditions are guaranteed in this test.
func getConnectError(t *testing.T, dut *testbench.DUT, fd int32) error {
	t.Helper()
	// We previously got EINPROGRESS form the connect call. We can
	// handle it as explained by connect(2):
	// EINPROGRESS:
	//     The socket is nonblocking and the connection cannot be
	// completed immediately. It is possible to select(2) or poll(2)
	// for completion by selecting the socket for writing.  After
	// select(2) indicates writability, use getsockopt(2) to read
	// the SO_ERROR option at level SOL_SOCKET to determine
	// whether connect() completed successfully (SO_ERROR is
	// zero) or unsuccessfully (SO_ERROR is one of the usual
	// error codes listed here, explaining the reason for the
	// failure).
	dut.PollOne(t, fd, unix.POLLOUT, 10*time.Second)
	if errno := dut.GetSockOptInt(t, fd, unix.SOL_SOCKET, unix.SO_ERROR); errno != 0 {
		return unix.Errno(errno)
	}
	return nil
}
