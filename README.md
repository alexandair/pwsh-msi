# Unofficial PowerShell 7 MSI

This project builds an **unsigned, unofficial** x64 MSI for PowerShell 7.7.0.
It packages Microsoft's release ZIP using the MSI authoring from PowerShell
7.6.10, adapted for this build. It is not a Microsoft-produced installer.

The MSI uses the original x64 stable `UpgradeCode` and installation directory.
**Installing it is intended to replace an older official PowerShell 7 MSI**, not
to install alongside it. Build the MSI without changing the installed version;
test installation, upgrades, repairs, and uninstall in a disposable Windows VM
before deployment.

## Build

On Windows with PowerShell 7.2 or newer:

```powershell
pwsh -NoProfile -File .\build.ps1
```

The script downloads the official PowerShell ZIP and the portable WiX 3.14.1
tools into `cache`, verifies their pinned SHA-256 hashes, and builds
`out\PowerShell-7.7.0-win-x64-unofficial.msi`. Use `-Force` to replace an
existing output. The ZIP hash comes from the
[PowerShell 7.7.0 release](https://github.com/PowerShell/PowerShell/releases/tag/v7.7.0);
the WiX hash is also recorded in
[Microsoft PowerToys' WiX setup](https://github.com/microsoft/PowerToys/blob/204427d127cb098fa1624f170ed6cee13a0633cc/.pipelines/installWiX.ps1).
The script also checks the signature and version of the extracted `pwsh.exe`.
WiX installer consistency checks run with the upstream ICE40, ICE57, and
ICE61 suppressions. No .NET SDK or system-wide WiX installation is required.

The MSI itself is unsigned. Some files in the official ZIP are Microsoft-signed;
repackaging does not change those files' signatures. Sign the MSI with your own
trusted code-signing certificate before deploying it where policy requires one.

To verify the MSI's identity, upgrade rule, and payload without installing it:

```powershell
pwsh -NoProfile -File .\verify.ps1
```

Verification creates and removes an administrative image; it does not exercise
an actual install, upgrade, repair, uninstall, or remoting configuration.

## Installation and servicing

Installing requires administrator privileges. For example, in a test VM:

```powershell
msiexec.exe /i .\out\PowerShell-7.7.0-win-x64-unofficial.msi /l*v .\powershell-msi.log
```

The legacy installer options for PATH, the event manifest, remoting, telemetry,
and Explorer context menus are retained. The manifest and remoting custom
actions now fail the installation if their processes fail, rather than ignoring
those failures.

**Microsoft Update does not service this unofficial MSI.** Rebuild and deploy
new packages yourself. For new installations, the obsolete `USE_MU=1` and
`ENABLE_MU=1` properties are rejected rather than silently suggesting updates.
Review the supported OS versions and test any required installer options before
deployment.

## Source and license

The authoring and artwork in `assets` come from
[PowerShell v7.6.10](https://github.com/PowerShell/PowerShell/tree/16ac95d24d87c61a5d8300dae2d0619db06c555c/assets/wix)
and are covered by `LICENSE-PowerShell.txt`. The authoring is modified to label
the package as unofficial, require Windows 10 version 1607/Server 2016 or later,
remove Microsoft Update integration, report custom-action failures, and shorten
an overlong tooltip.
