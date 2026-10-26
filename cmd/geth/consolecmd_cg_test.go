package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// TestConsoleCmdNetworkIdentities tests network identity variables at runtime for a geth instance.
// This provides a "production equivalent" integration test for consensus-relevant chain identity values which
// cannot be adequately unit tested because of reliance on cli context variables.
// These tests should cover the developer modes, the only ones with a built-in genesis.
func TestConsoleCmdNetworkIdentities(t *testing.T) {
	chainIdentityCases := []struct {
		flags       []string
		networkId   int
		chainId     int
		genesisHash string
	}{
		// No network is built in; only the developer modes have a built-in genesis.
		{[]string{"--dev"}, 1337, 1337, "0x0"},
		{[]string{"--dev.pow"}, 1337, 1337, "0x0"},
	}
	for i, p := range chainIdentityCases {
		// Disable networking, preventing false-negatives if in an environment without networking service
		// or collisions with an existing geth service.
		p.flags = append(p.flags, "--port", "0", "--maxpeers", "0", "--nodiscover", "--nat", "none")

		t.Run(fmt.Sprintf("%d/networkid", i),
			consoleCmdStdoutTest(p.flags, "admin.nodeInfo.protocols.eth.network", p.networkId))
		t.Run(fmt.Sprintf("%d/chainid", i),
			consoleCmdStdoutTest(p.flags, "admin.nodeInfo.protocols.eth.config.chainId", p.chainId))

		// The developer mode block has a dynamic genesis, depending on a parameterized address (coinbase) value.
		if p.genesisHash != "0x0" {
			t.Run(fmt.Sprintf("%d/genesis_hash", i),
				consoleCmdStdoutTest(p.flags, "eth.getBlock(0, false).hash", strconv.Quote(p.genesisHash)))
		}
	}
}

func consoleCmdStdoutTest(flags []string, execCmd string, want interface{}) func(t *testing.T) {
	return func(t *testing.T) {
		flags = append(flags, "--ipcpath", filepath.Join(os.TempDir(), "geth.ipc"), "--exec", execCmd, "console")
		t.Log("flags:", flags)
		geth := runGeth(t, flags...)
		geth.KillTimeout = 20 * time.Second
		geth.Expect(fmt.Sprintf(`%v
`, want))
		geth.ExpectExit()
		if status := geth.ExitStatus(); status != 0 {
			t.Errorf("expected exit status 0, got: %d", status)
		}
	}
}

// TestGethFailureToLaunch tests that geth fail immediately when given invalid run parameters (ie CLI args).
func TestGethFailureToLaunch(t *testing.T) {
	cases := []struct {
		flags            []string
		expectErrorReStr string
	}{
		{
			flags:            []string{"--badnet"},
			expectErrorReStr: "(?ism)incorrect usage.*",
		},
		{
			// The Ethereum network flags are gone.
			flags:            []string{"--mainnet"},
			expectErrorReStr: "(?ism)flag provided but not defined.*",
		},
	}
	for i, c := range cases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Log("flags:", c.flags)
			geth := runGeth(t, c.flags...)
			geth.ExpectRegexp(c.expectErrorReStr)
			geth.ExpectExit()
			if status := geth.ExitStatus(); status == 0 {
				t.Errorf("expected exit status != 0, got: %d", status)
			}
		})
	}
}
