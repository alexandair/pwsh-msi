#Requires -Version 7.2

[CmdletBinding()]
param(
    [switch] $Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if (-not $IsWindows) {
    throw 'Building this MSI requires Windows.'
}

$dependencies = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'dependencies.json') -Raw | ConvertFrom-Json
$versionText = [string] $dependencies.powerShell.version
if ($versionText -notmatch '^7\.\d+\.\d+$') {
    throw 'The PowerShell version must be a stable 7.x.y release.'
}
$version = [version] $versionText
if ($version.Minor -gt 255 -or $version.Build -gt 65535) {
    throw "The version $versionText cannot be represented as an MSI product version."
}
if ($dependencies.powerShell.architecture -ne 'x64' -or $dependencies.wix.version -ne '3.14.1') {
    throw 'This build is designed for x64 and WiX 3.14.1.'
}

$cacheDir = Join-Path $PSScriptRoot 'cache'
$workRoot = Join-Path $PSScriptRoot '.work'
$outputDir = Join-Path $PSScriptRoot 'out'
$output = Join-Path $outputDir "PowerShell-$versionText-win-x64-unofficial.msi"

if ((Test-Path -LiteralPath $output) -and -not $Force) {
    throw "Output already exists: $output. Use -Force to replace it."
}

function Get-VerifiedArchive {
    param(
        [Parameter(Mandatory)] [string] $Uri,
        [Parameter(Mandatory)] [string] $Sha256,
        [Parameter(Mandatory)] [string] $Path
    )

    if ($Sha256 -notmatch '^[a-fA-F0-9]{64}$') {
        throw "Invalid SHA-256 for $Uri."
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        $partial = "$Path.$([guid]::NewGuid().ToString('N')).partial"
        try {
            Write-Host "Downloading $Uri"
            Invoke-WebRequest -Uri $Uri -OutFile $partial
            $actual = (Get-FileHash -LiteralPath $partial -Algorithm SHA256).Hash
            if ($actual -ne $Sha256) {
                throw "SHA-256 mismatch for $Uri. Expected $Sha256, got $actual."
            }
            Move-Item -LiteralPath $partial -Destination $Path
        }
        finally {
            if (Test-Path -LiteralPath $partial) {
                Remove-Item -LiteralPath $partial -Force
            }
        }
    }

    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($actual -ne $Sha256) {
        throw "SHA-256 mismatch for cached file $Path. Expected $Sha256, got $actual."
    }
}

function Invoke-WixTool {
    param(
        [Parameter(Mandatory)] [string] $Tool,
        [Parameter(Mandatory)] [string[]] $ToolArguments
    )

    & $Tool @ToolArguments
    if ($LASTEXITCODE -ne 0) {
        throw "$([IO.Path]::GetFileName($Tool)) failed with exit code $LASTEXITCODE."
    }
}

New-Item -ItemType Directory -Path $cacheDir, $workRoot, $outputDir -Force | Out-Null
$powerShellZip = Join-Path $cacheDir "PowerShell-$versionText-win-x64.zip"
$wixZip = Join-Path $cacheDir 'wix314-binaries.zip'
Get-VerifiedArchive -Uri $dependencies.powerShell.url -Sha256 $dependencies.powerShell.sha256 -Path $powerShellZip
Get-VerifiedArchive -Uri $dependencies.wix.url -Sha256 $dependencies.wix.sha256 -Path $wixZip

$workDir = Join-Path $workRoot ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $workDir | Out-Null
try {
    $payloadDir = Join-Path $workDir 'payload'
    $wixDir = Join-Path $workDir 'wix'
    [IO.Compression.ZipFile]::ExtractToDirectory($powerShellZip, $payloadDir)
    [IO.Compression.ZipFile]::ExtractToDirectory($wixZip, $wixDir)

    $pwsh = Join-Path $payloadDir 'pwsh.exe'
    $signature = Get-AuthenticodeSignature -LiteralPath $pwsh
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '(^|,\s*)CN=Microsoft Corporation(,|$)') {
        throw "The extracted pwsh.exe does not have a valid Microsoft signature: $($signature.Status)."
    }
    $actualVersion = & $pwsh -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'
    if ($LASTEXITCODE -ne 0 -or $actualVersion -ne $versionText) {
        throw "The extracted pwsh.exe did not report version $versionText."
    }
    if (-not (Test-Path -LiteralPath (Join-Path $payloadDir 'RegisterManifest.ps1') -PathType Leaf)) {
        throw 'The PowerShell ZIP does not contain RegisterManifest.ps1.'
    }

    $payloadAssets = Join-Path $payloadDir 'assets'
    New-Item -ItemType Directory -Path $payloadAssets -Force | Out-Null
    foreach ($icon in 'Powershell_av_colors.ico', 'Powershell_avatar.ico', 'Powershell_black.ico', 'ps_black_32x32.ico') {
        $target = Join-Path $payloadAssets $icon
        if (Test-Path -LiteralPath $target) {
            throw "Refusing to overwrite an existing payload file: $target"
        }
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot "assets\$icon") -Destination $target
    }

    $fragment = Join-Path $workDir 'Fragment.wxs'
    $productObject = Join-Path $workDir 'Product.wixobj'
    $fragmentObject = Join-Path $workDir 'Fragment.wixobj'
    $temporaryMsi = Join-Path $workDir 'PowerShell.msi'
    $temporaryPdb = Join-Path $workDir 'PowerShell.wixpdb'
    $definitions = @(
        '-dIsPreview=False'
        "-dProductSourcePath=$payloadDir"
        '-dProductName=PowerShell'
        "-dProductVersion=$versionText.0"
        '-dSimpleProductVersion=7'
        "-dProductSemanticVersion=$versionText"
        '-dProductProgFilesDir=ProgramFiles64Folder'
        '-dFileArchitecture=amd64'
    )
    $extensions = @(
        '-ext', (Join-Path $wixDir 'WixUIExtension.dll')
        '-ext', (Join-Path $wixDir 'WixUtilExtension.dll')
        '-ext', (Join-Path $wixDir 'WixBalExtension.dll')
    )

    Push-Location $PSScriptRoot
    try {
        Write-Host 'Harvesting the verified PowerShell payload'
        Invoke-WixTool -Tool (Join-Path $wixDir 'heat.exe') -ToolArguments @(
            'dir', $payloadDir, '-nologo', '-dr', 'VersionFolder', '-cg', 'ApplicationFiles',
            '-ag', '-sfrag', '-srd', '-scom', '-sreg', '-out', $fragment,
            '-var', 'var.ProductSourcePath'
        )

        Write-Host 'Compiling the legacy PowerShell installer authoring'
        # WixShellExec expands its target at runtime; CNDL1077 is not applicable.
        Invoke-WixTool -Tool (Join-Path $wixDir 'candle.exe') -ToolArguments (
            @('-nologo', '-sw1077', '-arch', 'x64', '-out', $productObject) + $extensions + $definitions +
            @((Join-Path $PSScriptRoot 'assets\wix\Product.wxs'))
        )
        Invoke-WixTool -Tool (Join-Path $wixDir 'candle.exe') -ToolArguments (
            @('-nologo', '-arch', 'x64', '-out', $fragmentObject) + $extensions + $definitions + @($fragment)
        )

        Write-Host 'Linking the unsigned MSI'
        Invoke-WixTool -Tool (Join-Path $wixDir 'light.exe') -ToolArguments (
            @('-nologo', '-sice:ICE61', '-sice:ICE40', '-sice:ICE57',
              '-out', $temporaryMsi, '-pdbout', $temporaryPdb, $productObject, $fragmentObject) + $extensions
        )
    }
    finally {
        Pop-Location
    }

    Move-Item -LiteralPath $temporaryMsi -Destination $output -Force:$Force
    $hash = (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash
    Write-Host "Created $output"
    Write-Host "SHA-256: $hash"
}
finally {
    if (Test-Path -LiteralPath $workDir) {
        Remove-Item -LiteralPath $workDir -Recurse -Force
    }
}
