# Installs a Ghost node on Windows for the current user and starts it mining,
# with no administrator rights. It asks nothing: paste the one line from the
# README into PowerShell,
#
#	irm https://get.ghostcoin.com/win | iex
#
# and when it finishes the node is installed, on the network, syncing and
# mining, and it prints the mining address and how to check on the node.
#
# This script only fetches ghost-setup-windows-<arch>.exe from the release,
# with curl.exe, which Windows 10 and 11 have, over https only, checks that its
# SHA-256 is the one pinned below for this computer, and runs it. On any other
# hash it stops and runs nothing. ghost-setup (install/winsetup) does the rest:
# it checks the release's ed25519 signature before unpacking anything,
# installs the node in %USERPROFILE%\.ghost-node as the per-user service,
# writes its config with a new mining address, starts it, and runs a signed
# update at most once a day at login. install.cmd does the same from CMD.
#
# GHOST_RELEASE_URL sets where the release is downloaded from, over https
# only, and GHOST_INSTALL_CA_FILE names a certificate file to trust for that
# server; ghost-setup reads both too. The tests use them for a local release
# server.
#
# GHOST_MINE_TO mines straight to a wallet address of your own, such as the
# Ghost pop-up wallet's, instead of a newly generated mining key:
#
#	$env:GHOST_MINE_TO='0x...'; irm https://get.ghostcoin.com/win | iex
#
# (on a Mac or Linux: curl -fsSL https://get.ghostcoin.com | GHOST_MINE_TO=0x... sh)
#
# It must be 0x followed by exactly 40 hex characters; anything else is
# refused with nothing installed. This script then writes the config with
# that address as Etherbase before ghost-setup runs, so ghost-setup keeps it
# and makes no mining key or password file; on a re-run it rewrites the
# config's Etherbase to the address, and ghost-setup restarts the node. Unset,
# the config is left to ghost-setup as before. Either way the script ends by
# printing the address the node mines to.
#
# The node mines on half this computer's logical cores, rounded down and at
# least 1. GHOST_MINE_THREADS chooses the number of cores instead:
#
#	$env:GHOST_MINE_THREADS='2'; irm https://get.ghostcoin.com/win | iex
#
# (on a Mac or Linux: curl -fsSL https://get.ghostcoin.com | GHOST_MINE_THREADS=2 sh)
#
# It must be a whole number from 1 to 9999; anything else is refused with
# nothing installed. ghost-setup keeps it as GETH_MINER_THREADS, which geth
# reads as --miner.threads, in the user's environment, so the node started at
# login mines on that many cores too. A re-run or an update keeps the number
# unless GHOST_MINE_THREADS is set again. ghost-setup's closing lines say how
# many cores the node mines on.
#
# The whole script is one script block that runs at its last line, so a
# download cut short runs nothing.

& {
	$ErrorActionPreference = 'Stop'

	# The SHA-256 of the release's ghost-setup-windows-<arch>.exe. The release
	# fills them in; until then they are all zeros, the placeholder, and this
	# script refuses to install rather than run an unchecked program.
	$SetupHashes = @{
		amd64 = '0000000000000000000000000000000000000000000000000000000000000000'
		arm64 = '0000000000000000000000000000000000000000000000000000000000000000'
	}
	$Placeholder = '0000000000000000000000000000000000000000000000000000000000000000'
	$Refusal = 'refusing to install. Nothing was installed.'

	$ReleaseUrl = 'https://github.com/ghostcoin-core/ghost-node/releases/latest/download'
	if ($env:GHOST_RELEASE_URL) { $ReleaseUrl = $env:GHOST_RELEASE_URL }
	$ReleaseUrl = $ReleaseUrl.TrimEnd('/')
	if (-not $ReleaseUrl.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) {
		throw "ghost-node: GHOST_RELEASE_URL must be an https URL, not $ReleaseUrl"
	}

	# GHOST_MINE_TO, when set, is the wallet address to mine to.
	$MineTo = $env:GHOST_MINE_TO
	$HttpPort = 8545
	if ($MineTo) {
		if ($MineTo -cnotmatch '^0x[0-9a-fA-F]{40}\z') {
			throw "ghost-node: GHOST_MINE_TO must be a wallet address, 0x followed by exactly 40 hex characters, not '$MineTo'; $Refusal"
		}
		if (-not $env:USERPROFILE) {
			throw "ghost-node: USERPROFILE is not set to a directory; $Refusal"
		}
		if ($env:GHOST_HTTP_PORT) {
			if ($env:GHOST_HTTP_PORT -cnotmatch '^[1-9][0-9]{0,4}\z' -or [int]$env:GHOST_HTTP_PORT -gt 65535) {
				throw "ghost-node: GHOST_HTTP_PORT is not a port number: $env:GHOST_HTTP_PORT; $Refusal"
			}
			$HttpPort = [int]$env:GHOST_HTTP_PORT
		}
	}
	# GHOST_MINE_THREADS, when set, is the number of CPU cores to mine on;
	# ghost-setup reads it too.
	$MineThreads = $env:GHOST_MINE_THREADS
	if ($MineThreads -and $MineThreads -cnotmatch '^[1-9][0-9]{0,3}\z') {
		throw "ghost-node: GHOST_MINE_THREADS must be the number of CPU cores to mine on, a whole number from 1 to 9999, not '$MineThreads'; $Refusal"
	}
	$NodeHome = $null
	$Config = $null
	if ($env:USERPROFILE) {
		$NodeHome = Join-Path $env:USERPROFILE '.ghost-node'
		$Config = Join-Path $NodeHome 'config.toml'
	}

	$Machine = $env:PROCESSOR_ARCHITECTURE
	if ($env:PROCESSOR_ARCHITEW6432) { $Machine = $env:PROCESSOR_ARCHITEW6432 }
	if ($Machine -eq 'AMD64') {
		$Arch = 'amd64'
	} elseif ($Machine -eq 'ARM64') {
		$Arch = 'arm64'
	} else {
		throw "ghost-node: there is no Ghost node release for $Machine processors; releases are for amd64 and arm64"
	}

	$Name = "ghost-setup-windows-$Arch.exe"
	$Pinned = $SetupHashes[$Arch]
	if ($Pinned -eq $Placeholder) {
		throw "ghost-node: this installer has no hash of $Name pinned yet, only the placeholder, so it cannot check a release; $Refusal"
	}

	$Work = Join-Path ([IO.Path]::GetTempPath()) ('ghost-setup-' + [Guid]::NewGuid().ToString('N'))
	New-Item -ItemType Directory -Path $Work | Out-Null
	try {
		$Setup = Join-Path $Work $Name
		$CurlArgs = @('-fsSL', '--proto', '=https', '--proto-redir', '=https', '--tlsv1.2', '--max-redirs', '8',
			'--connect-timeout', '30', '--retry', '3', '--user-agent', 'ghost-node-installer', '--output', $Setup)
		if ($env:GHOST_INSTALL_CA_FILE) { $CurlArgs += @('--cacert', $env:GHOST_INSTALL_CA_FILE) }
		Write-Host "ghost-node: downloading $Name"
		& curl.exe @CurlArgs "$ReleaseUrl/$Name"
		if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $Setup -PathType Leaf)) {
			throw "ghost-node: could not download $ReleaseUrl/$Name; $Refusal"
		}

		$Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Setup).Hash.ToLowerInvariant()
		if ($Hash -ne $Pinned) {
			throw "ghost-node: the downloaded $Name has the SHA-256 $Hash, not the $Pinned pinned in this installer; $Refusal"
		}

		# With GHOST_MINE_TO, the config mines to its address before ghost-setup
		# runs: ghost-setup keeps an existing config, and so makes no mining key.
		if ($MineTo) {
			$Etherbase = "Etherbase = `"$MineTo`""
			if (Test-Path -LiteralPath $Config -PathType Leaf) {
				$Text = [IO.File]::ReadAllText($Config)
				if ($Text -cmatch '(?m)^Etherbase = ') {
					$Text = [regex]::Replace($Text, '(?m)^Etherbase = [^\r\n]*', $Etherbase)
				} else {
					$Text = $Text.TrimEnd() + "`n`n[Eth.Miner]`n$Etherbase`n"
				}
			} else {
				$DataDir = (Join-Path $NodeHome 'data').Replace('\', '\\').Replace('"', '\"')
				$Text = @'
# The Ghost node's config, written by install.ps1. The node mines to Etherbase,
# the wallet address GHOST_MINE_TO named, whose key is not on this computer.
# Its HTTP RPC listens on this computer only, for the Ghost web apps.

[Eth.Miner]
Etherbase = "{0}"

[Node]
DataDir = "{1}"
HTTPHost = "127.0.0.1"
HTTPPort = {2}
HTTPModules = ["eth", "net", "web3"]
HTTPCors = ["https://ghost-webapp-alpha.vercel.app", "https://ghost-wallet-nine.vercel.app"]
'@ -f $MineTo, $DataDir, $HttpPort
				$Text = $Text.Replace("`r`n", "`n") + "`n"
			}
			New-Item -ItemType Directory -Force -Path $NodeHome | Out-Null
			[IO.File]::WriteAllText($Config, $Text)
			Write-Host "ghost-node: the config $Config mines to $MineTo"
		}

		& $Setup
		if ($LASTEXITCODE -ne 0) {
			throw "ghost-node: the setup stopped with exit code $LASTEXITCODE; see why above."
		}

		if ($Config -and (Test-Path -LiteralPath $Config -PathType Leaf)) {
			$Mined = [regex]::Match([IO.File]::ReadAllText($Config), '(?m)^Etherbase = "(0x[0-9a-fA-F]{40})"\r?$')
			if ($Mined.Success) {
				Write-Host "ghost-node: mining to: $($Mined.Groups[1].Value)"
			}
		}
	} finally {
		Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue
	}
}
