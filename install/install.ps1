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

		& $Setup
		if ($LASTEXITCODE -ne 0) {
			throw "ghost-node: the setup stopped with exit code $LASTEXITCODE; see why above."
		}
	} finally {
		Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue
	}
}
