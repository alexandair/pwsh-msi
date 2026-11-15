#Requires -Version 7.2

<#
.SYNOPSIS
Verifies the unofficial MSI's identity and payload, optionally its signature.

.DESCRIPTION
Checks installer identity, x64 architecture, the legacy upgrade rule, update
restrictions, and payload against the hash-verified PowerShell ZIP in cache.
Creates and removes a temporary administrative image without installing the
product. Requires the cached ZIP and matching dependencies.json from the build.

Payload-only verification accepts unsigned MSIs. Supplying ExpectedSignerSubject
also requires a valid Windows signature, the exact subject, Code Signing EKU,
and a timestamp. ExpectedProfileEku adds a durable profile identity check.

.PARAMETER MsiPath
MSI to verify. Defaults to out\PowerShell-<version>-win-x64-unofficial.msi
relative to this repository, using the version in dependencies.json.

.PARAMETER ExpectedSignerSubject
Complete, exact Windows certificate subject. Selects signed verification;
the signer chain must be trusted by the verification machine.

.PARAMETER ExpectedProfileEku
Optional durable Artifact Signing profile identity OID beginning with
1.3.6.1.4.1.311.97. Requires ExpectedSignerSubject.

.EXAMPLE
pwsh -NoProfile -File .\verify.ps1

Checks the default output's identity and full payload. Does not require signing.

.EXAMPLE
.\verify.ps1 -MsiPath 'C:\Packages\organization-powershell.msi'

Checks a package at another location against this build's cached payload.

.EXAMPLE
.\verify.ps1 -ExpectedSignerSubject 'CN=Example Organization, O=Example Organization, C=US'

Checks the default output's signature, signer, timestamp, identity, and payload.

.EXAMPLE
$verification = @{
    MsiPath = 'C:\Packages\organization-powershell.msi'
    ExpectedSignerSubject = 'CN=Example Organization, O=Example Organization, C=US'
    ExpectedProfileEku = '1.3.6.1.4.1.311.97.123.456'
}
.\verify.ps1 @verification

Also checks a durable profile EKU. Replace the subject and example OID with
the actual values for your organization's profile.

.NOTES
Requires Windows and the build's cached PowerShell ZIP.
This does not test installation, upgrades, repairs, uninstall, or remoting.
Use a separate pwsh process when the caller needs to move the MSI immediately
after verification; Windows Installer COM objects can retain file handles.

.LINK
.\README.md

.LINK
.\build.ps1
#>

[CmdletBinding(DefaultParameterSetName = 'Payload')]
param(
    [string] $MsiPath,

    [Parameter(Mandatory, ParameterSetName = 'Signed')]
    [ValidateNotNullOrEmpty()]
    [string] $ExpectedSignerSubject,

    [Parameter(ParameterSetName = 'Signed')]
    [ValidatePattern('^1\.3\.6\.1\.4\.1\.311\.97\.\d+(\.\d+)*$')]
    [string] $ExpectedProfileEku
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $IsWindows) {
    throw 'Verifying this MSI requires Windows.'
}

$dependencies = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'dependencies.json') -Raw | ConvertFrom-Json
$version = [string] $dependencies.powerShell.version
if (-not $MsiPath) {
    $MsiPath = Join-Path $PSScriptRoot "out\PowerShell-$version-win-x64-unofficial.msi"
}
$msi = (Resolve-Path -LiteralPath $MsiPath).ProviderPath
if ($PSCmdlet.ParameterSetName -eq 'Signed') {
    . (Join-Path $PSScriptRoot 'signing.ps1')
    Assert-MsiSignature -Path $msi -ExpectedSignerSubject $ExpectedSignerSubject `
        -ExpectedProfileEku $ExpectedProfileEku -RequireTimestamp
    Write-Host 'MSI signature, expected signer, and timestamp verified.'
}
$zip = Join-Path $PSScriptRoot "cache\PowerShell-$version-win-x64.zip"
if ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash -ne $dependencies.powerShell.sha256) {
    throw "The cached PowerShell ZIP does not match the pinned SHA-256: $zip"
}

$installer = New-Object -ComObject WindowsInstaller.Installer
$database = $installer.OpenDatabase($msi, 0)

function Get-MsiProperty {
    param([Parameter(Mandatory)] [string] $Name)

    $view = $database.OpenView("SELECT ``Value`` FROM ``Property`` WHERE ``Property`` = '$Name'")
    try {
        $null = $view.Execute()
        $record = $view.Fetch()
        if (-not $record) {
            throw "MSI property is missing: $Name"
        }
        return $record.StringData(1)
    }
    finally {
        $null = $view.Close()
    }
}

$actualVersion = Get-MsiProperty 'ProductVersion'
$manufacturer = Get-MsiProperty 'Manufacturer'
$productName = Get-MsiProperty 'ProductName'
if ($actualVersion -ne "$version.0" -or
    $manufacturer -ne 'Unofficial PowerShell MSI' -or
    $productName -notmatch 'Unofficial MSI') {
    throw "Unexpected MSI identity: $productName, $manufacturer, $actualVersion."
}
$secureProperties = (Get-MsiProperty 'SecureCustomProperties') -split ';'
foreach ($property in 'PS_OS_BUILD', 'USE_MU', 'ENABLE_MU') {
    if ($property -notin $secureProperties) {
        throw "The MSI does not preserve $property across elevation."
    }
}
$summary = $installer.SummaryInformation($msi, 0)
if ($summary.Property(7) -ne 'x64;1033') {
    throw "Unexpected MSI architecture: $($summary.Property(7))."
}

$view = $database.OpenView('SELECT `UpgradeCode`,`VersionMax`,`Attributes`,`ActionProperty` FROM `Upgrade`')
try {
    $view.Execute()
    $matchesUpgrade = $false
    while ($record = $view.Fetch()) {
        if ($record.StringData(1) -eq '{31AB5147-9A97-4452-8443-D9709F0516E1}' -and
            $record.StringData(2) -eq "$version.0" -and
            ($record.IntegerData(3) -band 512) -ne 0 -and
            $record.StringData(4) -eq 'WIX_UPGRADE_DETECTED') {
            $matchesUpgrade = $true
        }
    }
    if (-not $matchesUpgrade) {
        throw 'The MSI does not contain the expected legacy x64 upgrade rule.'
    }
}
finally {
    $view.Close()
}

$updateCondition = 'Installed OR ((NOT USE_MU OR USE_MU = "0") AND (NOT ENABLE_MU OR ENABLE_MU = "0"))'
$view = $database.OpenView('SELECT `Condition` FROM `LaunchCondition`')
try {
    $view.Execute()
    $conditions = while ($record = $view.Fetch()) { $record.StringData(1) }
    if ($updateCondition -notin $conditions) {
        throw 'The MSI does not contain the expected Microsoft Update restriction.'
    }
    if ('Installed OR PS_OS_BUILD >= 14393' -notin $conditions) {
        throw 'The MSI does not contain the expected Windows version restriction.'
    }
}
finally {
    $view.Close()
}

$view = $database.OpenView('SELECT `Action`,`Type` FROM `CustomAction`')
try {
    $view.Execute()
    $actions = @{}
    while ($record = $view.Fetch()) {
        $actions[$record.StringData(1)] = $record.IntegerData(2)
    }
    foreach ($action in 'RegisterManifest', 'EnablePSRemoting') {
        if (-not $actions.ContainsKey($action) -or ($actions[$action] -band 64) -ne 0) {
            throw "The $action custom action is missing or ignores failures."
        }
    }
    if ($actions.ContainsKey('EnableMU')) {
        throw 'The MSI unexpectedly contains the Microsoft Update custom action.'
    }
}
finally {
    $view.Close()
}

$session = $installer.OpenPackage($msi, 1)
$null = $session.DoAction('AppSearch')
$actualBuild = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'CurrentBuildNumber'
if ($session.Property('PS_OS_BUILD') -ne $actualBuild) {
    throw 'The MSI did not read the Windows build number from the registry.'
}
foreach ($test in @(
    @{ Build = ''; Expected = 0 }
    @{ Build = '9600'; Expected = 0 }
    @{ Build = '14392'; Expected = 0 }
    @{ Build = '14393'; Expected = 1 }
    @{ Build = '22631'; Expected = 1 }
)) {
    $session.GetType().InvokeMember('Property', [Reflection.BindingFlags]::SetProperty, $null, $session, @('PS_OS_BUILD', $test.Build)) | Out-Null
    if ($session.EvaluateCondition('PS_OS_BUILD >= 14393') -ne $test.Expected) {
        throw "Unexpected Windows version condition result for build $($test.Build)."
    }
}
$expression = '(NOT USE_MU OR USE_MU = "0") AND (NOT ENABLE_MU OR ENABLE_MU = "0")'
$cases = @(
    @{ Use = ''; Enable = ''; Expected = 1 }
    @{ Use = '0'; Enable = '0'; Expected = 1 }
    @{ Use = '1'; Enable = '0'; Expected = 0 }
    @{ Use = '0'; Enable = '1'; Expected = 0 }
)
foreach ($case in $cases) {
    $session.GetType().InvokeMember('Property', [Reflection.BindingFlags]::SetProperty, $null, $session, @('USE_MU', $case.Use)) | Out-Null
    $session.GetType().InvokeMember('Property', [Reflection.BindingFlags]::SetProperty, $null, $session, @('ENABLE_MU', $case.Enable)) | Out-Null
    if ($session.EvaluateCondition($expression) -ne $case.Expected) {
        throw "Unexpected Microsoft Update condition result for USE_MU=$($case.Use), ENABLE_MU=$($case.Enable)."
    }
}
$session = $null
$database = $null

$localWorkRoot = Join-Path $PSScriptRoot '.work'
$tempWorkRoot = [IO.Path]::GetTempPath()
$workRoot = if ($localWorkRoot.Length -lt $tempWorkRoot.Length) { $localWorkRoot } else { $tempWorkRoot }
New-Item -ItemType Directory -Path $workRoot -Force | Out-Null
$workDir = Join-Path $workRoot "psmsi-verify-$([guid]::NewGuid().ToString('N'))"
$imageDir = Join-Path $workDir 'image'
$log = Join-Path $workDir 'msiexec.log'
New-Item -ItemType Directory -Path $imageDir -Force | Out-Null
$completed = $false
try {
    Write-Host 'Extracting an administrative image without installing the product'
    $arguments = @('/a', "`"$msi`"", '/qn', "TARGETDIR=`"$imageDir`"", '/l*v', "`"$log`"")
    $process = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList $arguments -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "Administrative extraction failed with exit code $($process.ExitCode). See $log."
    }

    $executables = @(Get-ChildItem -LiteralPath $imageDir -Filter 'pwsh.exe' -File -Recurse)
    if ($executables.Count -ne 1) {
        throw "Expected one extracted pwsh.exe, found $($executables.Count)."
    }
    $payloadDir = $executables[0].DirectoryName
    $signature = Get-AuthenticodeSignature -LiteralPath $executables[0].FullName
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '(^|,\s*)CN=Microsoft Corporation(,|$)') {
        throw "The extracted pwsh.exe does not have a valid Microsoft signature: $($signature.Status)."
    }

    $archive = [IO.Compression.ZipFile]::OpenRead($zip)
    try {
        $entries = @($archive.Entries | Where-Object { -not $_.FullName.EndsWith('/') })
        foreach ($entry in $entries) {
            $relativePath = $entry.FullName.Replace('/', [IO.Path]::DirectorySeparatorChar)
            $extracted = Join-Path $payloadDir $relativePath
            if (-not (Test-Path -LiteralPath $extracted -PathType Leaf)) {
                throw "MSI payload is missing $relativePath."
            }
            $stream = $entry.Open()
            try {
                $expected = (Get-FileHash -InputStream $stream -Algorithm SHA256).Hash
            }
            finally {
                $stream.Dispose()
            }
            if ((Get-FileHash -LiteralPath $extracted -Algorithm SHA256).Hash -ne $expected) {
                throw "MSI payload differs from the official ZIP: $relativePath."
            }
        }
        $actualCount = @(Get-ChildItem -LiteralPath $payloadDir -File -Recurse -Force).Count
        if ($actualCount -ne ($entries.Count + 4)) {
            throw "Unexpected payload file count: $actualCount."
        }
        foreach ($icon in 'Powershell_av_colors.ico', 'Powershell_avatar.ico', 'Powershell_black.ico', 'ps_black_32x32.ico') {
            $source = Join-Path $PSScriptRoot "assets\$icon"
            $extracted = Join-Path $payloadDir "assets\$icon"
            if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne
                (Get-FileHash -LiteralPath $extracted -Algorithm SHA256).Hash) {
                throw "MSI artwork differs from the legacy source: $icon."
            }
        }
        Write-Host "Verified $($entries.Count) files against the official ZIP and four installer icons."
    }
    finally {
        $archive.Dispose()
    }

    $completed = $true
    Write-Host "MSI identity, upgrade rule, update restrictions, and payload verified: $msi"
}
finally {
    if ($completed) {
        Remove-Item -LiteralPath $workDir -Recurse -Force
    }
    else {
        Write-Warning "Verification files were retained for diagnosis: $workDir"
    }
}
