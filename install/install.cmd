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

"%SETUP%"
set "STATUS=%ERRORLEVEL%"
rmdir /s /q "%WORK%"
exit /b %STATUS%
