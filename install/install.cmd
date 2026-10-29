@echo off
rem Installs a Ghost node on Windows for the current user and starts it
rem mining, with no administrator rights. It asks nothing: paste the one line
rem from the README into CMD,
rem
rem   curl -fsSL https://get.ghostcoin.com/win.cmd -o "%TEMP%\ghost-install.cmd" && "%TEMP%\ghost-install.cmd" && del "%TEMP%\ghost-install.cmd"
rem
rem and when it finishes the node is installed, on the network, syncing and
rem mining, and it prints the mining address and how to check on the node.
rem
rem It does exactly what install.ps1 does for PowerShell: it fetches
rem ghost-setup-windows-ARCH.exe from the release with curl.exe, over https
rem only, checks with certutil that its SHA-256 is the one pinned below for
rem this computer, and runs it. On any other hash it stops and runs nothing.
rem ghost-setup (install/winsetup) does the rest: it checks the release's
rem ed25519 signature before unpacking anything, installs the node in
rem %USERPROFILE%\.ghost-node as the per-user service, writes its config with a
rem new mining address, starts it, and runs a signed update at most once a day
rem at login.
rem
rem GHOST_RELEASE_URL sets where the release is downloaded from, over https
rem only, and GHOST_INSTALL_CA_FILE names a certificate file to trust for that
rem server; ghost-setup reads both too.
rem
rem GHOST_MINE_TO mines straight to a wallet address of your own, such as the
rem Ghost pop-up wallet's, instead of a newly generated mining key. In CMD,
rem run  set "GHOST_MINE_TO=0x..."  before the line above. The same in
rem PowerShell and on a Mac or Linux:
rem
rem   $env:GHOST_MINE_TO='0x...'; irm https://get.ghostcoin.com/win | iex
rem   curl -fsSL https://get.ghostcoin.com | GHOST_MINE_TO=0x... sh
rem
rem It must be 0x followed by exactly 40 hex characters; anything else is
rem refused with nothing installed. This script then writes the config with
rem that address as Etherbase before ghost-setup runs, so ghost-setup keeps it
rem and makes no mining key or password file; on a re-run it rewrites the
rem config's Etherbase to the address, and ghost-setup restarts the node.
rem Unset, the config is left to ghost-setup as before. Either way the script
rem ends by printing the address the node mines to.
rem
rem The node mines on half this computer's logical cores, rounded down and at
rem least 1. GHOST_MINE_THREADS chooses the number of cores instead. In CMD,
rem run  set "GHOST_MINE_THREADS=2"  before the line above. The same in
rem PowerShell and on a Mac or Linux:
rem
rem   $env:GHOST_MINE_THREADS='2'; irm https://get.ghostcoin.com/win | iex
rem   curl -fsSL https://get.ghostcoin.com | GHOST_MINE_THREADS=2 sh
rem
rem It must be a whole number from 1 to 9999; anything else is refused with
rem nothing installed. ghost-setup keeps it as GETH_MINER_THREADS, which geth
rem reads as --miner.threads, in the user's environment, so the node started
rem at login mines on that many cores too. A re-run or an update keeps the
rem number unless GHOST_MINE_THREADS is set again. ghost-setup's closing lines
rem say how many cores the node mines on.
rem
rem A release with the node dashboard, ghost-dash.exe, gets it installed beside
rem the node with its own key, dashboard-key, and run as the scheduled task
rem "Ghost Dashboard" at every login, on 127.0.0.1 port 8580. A first install
rem opens it in the browser; re-runs and updates print its link.
rem GHOST_DASH_PORT moves it to another port, a number from 1 to 65535;
rem anything else is refused with nothing installed, and so is a port another
rem program holds. GHOST_NO_DASHBOARD=1 leaves it out. In CMD, run
rem set "GHOST_NO_DASHBOARD=1"  before the line above. The same in PowerShell:
rem
rem   $env:GHOST_NO_DASHBOARD='1'; irm https://get.ghostcoin.com/win | iex
rem
rem It uses no labels, so it runs the same whatever its line endings.

setlocal EnableExtensions DisableDelayedExpansion

rem The SHA-256 of the release's ghost-setup-windows-ARCH.exe. The release
rem fills them in; until then they are all zeros, the placeholder, and this
rem script refuses to install rather than run an unchecked program.
set "SETUP_SHA256_amd64=0000000000000000000000000000000000000000000000000000000000000000"
set "SETUP_SHA256_arm64=0000000000000000000000000000000000000000000000000000000000000000"
set "PLACEHOLDER=0000000000000000000000000000000000000000000000000000000000000000"
set "REFUSAL=refusing to install. Nothing was installed."

set "RELEASE_URL=https://github.com/ghostcoin-core/ghost-node/releases/latest/download"
if defined GHOST_RELEASE_URL set "RELEASE_URL=%GHOST_RELEASE_URL%"
if "%RELEASE_URL:~-1%"=="/" set "RELEASE_URL=%RELEASE_URL:~0,-1%"
if /i not "%RELEASE_URL:~0,8%"=="https://" (
	echo ghost-node: GHOST_RELEASE_URL must be an https URL, not "%RELEASE_URL%" 1>&2
	exit /b 1
)

rem GHOST_MINE_TO, when set, is the wallet address to mine to: 0x and 40 hex
rem characters. It is read with delayed expansion only, so no character in it
rem can run as a command, and used with %% only once it is known to be hex.
rem MINE_TO_OK is 1 when it is unset or such an address. GHOST_HTTP_PORT is
rem checked the same way, as the config written for it holds the port.
set "MINE_TO_OK=1"
set "HTTP_PORT=8545"
if defined GHOST_MINE_TO (
	setlocal EnableDelayedExpansion
	set "MINE_TO_OK="
	set "REST=!GHOST_MINE_TO:~2!"
	for %%C in (0 1 2 3 4 5 6 7 8 9 a b c d e f) do if defined REST set "REST=!REST:%%C=!"
	if "!GHOST_MINE_TO:~0,2!"=="0x" if not "!GHOST_MINE_TO:~41,1!"=="" if "!GHOST_MINE_TO:~42!"=="" if not defined REST set "MINE_TO_OK=1"
	if defined GHOST_HTTP_PORT (
		set "REST=!GHOST_HTTP_PORT!"
		for %%C in (0 1 2 3 4 5 6 7 8 9) do if defined REST set "REST=!REST:%%C=!"
		if defined REST set "MINE_TO_OK="
		if "!GHOST_HTTP_PORT:~0,1!"=="0" set "MINE_TO_OK="
		if not "!GHOST_HTTP_PORT:~5!"=="" set "MINE_TO_OK="
		if not defined REST if !GHOST_HTTP_PORT! gtr 65535 set "MINE_TO_OK="
	)
	for %%R in ("!MINE_TO_OK!") do endlocal & set "MINE_TO_OK=%%~R"
)
if not defined MINE_TO_OK (
	echo ghost-node: GHOST_MINE_TO must be a wallet address, 0x followed by exactly 40 hex characters, and GHOST_HTTP_PORT a port number; %REFUSAL% 1>&2
	exit /b 1
)
rem GHOST_MINE_THREADS, when set, is the number of CPU cores to mine on: a
rem whole number from 1 to 9999, which ghost-setup reads too. It is checked
rem with delayed expansion only, as GHOST_MINE_TO is. THREADS_OK is 1 when it
rem is unset or such a number.
set "THREADS_OK=1"
if defined GHOST_MINE_THREADS (
	setlocal EnableDelayedExpansion
	set "THREADS_OK="
	set "REST=!GHOST_MINE_THREADS!"
	for %%C in (0 1 2 3 4 5 6 7 8 9) do if defined REST set "REST=!REST:%%C=!"
	if not defined REST if not "!GHOST_MINE_THREADS:~0,1!"=="0" if "!GHOST_MINE_THREADS:~4!"=="" set "THREADS_OK=1"
	for %%R in ("!THREADS_OK!") do endlocal & set "THREADS_OK=%%~R"
)
if not defined THREADS_OK (
	echo ghost-node: GHOST_MINE_THREADS must be the number of CPU cores to mine on, a whole number from 1 to 9999; %REFUSAL% 1>&2
	exit /b 1
)
rem GHOST_DASH_PORT, when set, is the node dashboard's port: a number from 1
rem to 65535, which ghost-setup reads too. It is checked with delayed
rem expansion only, as GHOST_MINE_TO is. DASH_PORT_OK is 1 when it is unset or
rem such a number.
set "DASH_PORT_OK=1"
if defined GHOST_DASH_PORT (
	setlocal EnableDelayedExpansion
	set "DASH_PORT_OK="
	set "REST=!GHOST_DASH_PORT!"
	for %%C in (0 1 2 3 4 5 6 7 8 9) do if defined REST set "REST=!REST:%%C=!"
	if not defined REST if not "!GHOST_DASH_PORT:~0,1!"=="0" if "!GHOST_DASH_PORT:~5!"=="" if !GHOST_DASH_PORT! leq 65535 set "DASH_PORT_OK=1"
	for %%R in ("!DASH_PORT_OK!") do endlocal & set "DASH_PORT_OK=%%~R"
)
if not defined DASH_PORT_OK (
	echo ghost-node: GHOST_DASH_PORT must be a port number for the node dashboard, from 1 to 65535; %REFUSAL% 1>&2
	exit /b 1
)
if defined GHOST_MINE_TO if defined GHOST_HTTP_PORT set "HTTP_PORT=%GHOST_HTTP_PORT%"
set "NODE_HOME=%USERPROFILE%\.ghost-node"
set "CONFIG=%NODE_HOME%\config.toml"
if defined GHOST_MINE_TO if not defined USERPROFILE (
	echo ghost-node: USERPROFILE is not set to a directory; %REFUSAL% 1>&2
	exit /b 1
)

set "MACHINE=%PROCESSOR_ARCHITECTURE%"
if defined PROCESSOR_ARCHITEW6432 set "MACHINE=%PROCESSOR_ARCHITEW6432%"
set "ARCH="
if /i "%MACHINE%"=="AMD64" set "ARCH=amd64"
if /i "%MACHINE%"=="ARM64" set "ARCH=arm64"
if not defined ARCH (
	echo ghost-node: there is no Ghost node release for "%MACHINE%" processors; releases are for amd64 and arm64 1>&2
	exit /b 1
)

set "NAME=ghost-setup-windows-%ARCH%.exe"
set "PINNED="
if "%ARCH%"=="amd64" set "PINNED=%SETUP_SHA256_amd64%"
if "%ARCH%"=="arm64" set "PINNED=%SETUP_SHA256_arm64%"
if "%PINNED%"=="%PLACEHOLDER%" (
	echo ghost-node: this installer has no hash of %NAME% pinned yet, only the placeholder, so it cannot check a release; %REFUSAL% 1>&2
	exit /b 1
)

set "WORK=%TEMP%\ghost-setup-%RANDOM%%RANDOM%%RANDOM%"
mkdir "%WORK%" 2>nul
if errorlevel 1 (
	echo ghost-node: could not make a temporary directory; %REFUSAL% 1>&2
	exit /b 1
)
set "SETUP=%WORK%\%NAME%"
set CA_ARGS=
if defined GHOST_INSTALL_CA_FILE set CA_ARGS=--cacert "%GHOST_INSTALL_CA_FILE%"

echo ghost-node: downloading %NAME%
curl.exe -fsSL --proto =https --proto-redir =https --tlsv1.2 --max-redirs 8 --connect-timeout 30 --retry 3 --user-agent ghost-node-installer %CA_ARGS% --output "%SETUP%" "%RELEASE_URL%/%NAME%"
if errorlevel 1 (
	rmdir /s /q "%WORK%"
	echo ghost-node: could not download "%RELEASE_URL%/%NAME%"; %REFUSAL% 1>&2
	exit /b 1
)
if not exist "%SETUP%" (
	rmdir /s /q "%WORK%"
	echo ghost-node: could not download "%RELEASE_URL%/%NAME%"; %REFUSAL% 1>&2
	exit /b 1
)

set "HASH="
for /f "skip=1 delims=" %%H in ('certutil -hashfile "%SETUP%" SHA256') do if not defined HASH set "HASH=%%H"
if defined HASH set "HASH=%HASH: =%"
if /i not "%HASH%"=="%PINNED%" (
	rmdir /s /q "%WORK%"
	echo ghost-node: the downloaded %NAME% has the SHA-256 "%HASH%", not the %PINNED% pinned in this installer; %REFUSAL% 1>&2
	exit /b 1
)

rem With GHOST_MINE_TO, the config mines to its address before ghost-setup
rem runs: ghost-setup keeps an existing config, and so makes no mining key. A
rem new config is written whole; an existing one gets its Etherbase line
rem replaced, every other line kept.
set "FRESH="
set "REWRITE="
if defined GHOST_MINE_TO if not exist "%CONFIG%" set "FRESH=1"
if defined GHOST_MINE_TO if exist "%CONFIG%" set "REWRITE=1"
set "DATA_TOML=%NODE_HOME:\=\\%\\data"
if defined FRESH mkdir "%NODE_HOME%" 2>nul
if defined FRESH >"%CONFIG%.new" echo # The Ghost node's config, written by install.cmd. The node mines to Etherbase,
if defined FRESH >>"%CONFIG%.new" echo # the wallet address GHOST_MINE_TO named, whose key is not on this computer.
if defined FRESH >>"%CONFIG%.new" echo # Its HTTP RPC listens on this computer only, for the Ghost web apps.
if defined FRESH >>"%CONFIG%.new" echo(
if defined FRESH >>"%CONFIG%.new" echo [Eth.Miner]
if defined FRESH >>"%CONFIG%.new" echo Etherbase = "%GHOST_MINE_TO%"
if defined FRESH >>"%CONFIG%.new" echo(
if defined FRESH >>"%CONFIG%.new" echo [Node]
if defined FRESH >>"%CONFIG%.new" echo DataDir = "%DATA_TOML%"
if defined FRESH >>"%CONFIG%.new" echo HTTPHost = "127.0.0.1"
if defined FRESH >>"%CONFIG%.new" echo HTTPPort = %HTTP_PORT%
if defined FRESH >>"%CONFIG%.new" echo HTTPModules = ["eth", "net", "web3"]
if defined FRESH >>"%CONFIG%.new" echo HTTPCors = ["https://ghost-webapp-alpha.vercel.app", "https://ghost-wallet-nine.vercel.app"]
if defined REWRITE type nul >"%CONFIG%.new"
if defined REWRITE for /f "delims=" %%L in ('findstr /n "^" "%CONFIG%"') do (
	set "LINE=%%L"
	setlocal EnableDelayedExpansion
	set "LINE=!LINE:*:=!"
	if "!LINE:~0,10!"=="Etherbase " (
		>>"%CONFIG%.new" echo Etherbase = "%GHOST_MINE_TO%"
	) else (
		>>"%CONFIG%.new" echo(!LINE!
	)
	endlocal
)
set "HAS_ETHERBASE="
if defined REWRITE findstr /b /l /c:"Etherbase " "%CONFIG%" >nul 2>nul && set "HAS_ETHERBASE=1"
if defined REWRITE if not defined HAS_ETHERBASE >>"%CONFIG%.new" echo(
if defined REWRITE if not defined HAS_ETHERBASE >>"%CONFIG%.new" echo [Eth.Miner]
if defined REWRITE if not defined HAS_ETHERBASE >>"%CONFIG%.new" echo Etherbase = "%GHOST_MINE_TO%"
if defined GHOST_MINE_TO move /y "%CONFIG%.new" "%CONFIG%" >nul
if defined GHOST_MINE_TO echo ghost-node: the config "%CONFIG%" mines to %GHOST_MINE_TO%

"%SETUP%"
set "STATUS=%ERRORLEVEL%"
rmdir /s /q "%WORK%"
rem Either way, say the address the node mines to.
if "%STATUS%"=="0" if exist "%CONFIG%" for /f "tokens=2 delims==" %%A in ('findstr /b /l /c:"Etherbase " "%CONFIG%"') do for %%B in (%%A) do echo ghost-node: mining to: %%~B
exit /b %STATUS%
