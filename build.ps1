#Requires -Version 7.2

<#
.SYNOPSIS
Builds an unofficial x64 PowerShell MSI, optionally signed by your organization.

.DESCRIPTION
Downloads the PowerShell payload and portable WiX tools pinned in
dependencies.json, checks their SHA-256 hashes, and builds the MSI in out.
The version and output filename come from dependencies.json.

Unsigned builds are the default. Choose one signing backend: a local
certificate, a versioned Azure Key Vault certificate, or an Artifact Signing
profile. Signing and signature checks run before publishing the MSI. Failures
do not publish an unsigned fallback or replace existing output.

.PARAMETER Force
Replaces an existing output MSI only after the build and any signing succeed.

.PARAMETER SigningCertificate
Local X509Certificate2 with an accessible private key, Code Signing EKU,
current validity, and a chain trusted by the build machine. Load a PFX with
Get-PfxCertificate or select a certificate from the Windows certificate store.

.PARAMETER KeyVaultCertificateId
Versioned HTTPS certificate URI, such as
https://YOUR_VAULT.vault.azure.net/certificates/YOUR_CERTIFICATE/YOUR_VERSION.
Uses the existing Azure CLI login to read the public certificate and sign with
its key remotely. Requires certificates/get and keys/sign permissions.
The private key is not downloaded.

.PARAMETER ArtifactSigningEndpoint
Regional HTTPS endpoint for the signing account, such as
https://neu.codesigning.azure.net/. Uses the existing Azure CLI login.

.PARAMETER ArtifactSigningAccountName
Artifact Signing account containing the selected certificate profile.

.PARAMETER ArtifactSigningCertificateProfileName
Certificate profile authorized for the Azure CLI identity. Requires the
Artifact Signing Certificate Profile Signer role at the intended profile.

.PARAMETER ExpectedSignerSubject
Complete, exact Windows SignerCertificate.Subject for the Artifact Signing
profile. Friendly publisher names alone are not sufficient.

.PARAMETER ExpectedProfileEku
Optional durable Artifact Signing profile identity OID beginning with
1.3.6.1.4.1.311.97. Do not use a rotating leaf certificate thumbprint.

.PARAMETER SignToolPath
Optional approved x64 signtool.exe. Bypasses the pinned SDK tool download.
If omitted, the tool is resolved from a hash-verified archive in cache.

.PARAMETER ArtifactSigningDlibPath
Optional approved x64 Azure.CodeSigning.Dlib.dll. Bypasses the pinned client
download. Keep its adjacent dependencies. If omitted, the client is resolved
from a hash-verified archive in cache.

.PARAMETER TimestampServer
Local signing: optional HTTP legacy Authenticode timestamp service.
Key Vault: optional HTTP or HTTPS RFC 3161 service.
Artifact Signing: required RFC 3161 timestamp, defaulting to
http://timestamp.acs.microsoft.com when this parameter is omitted.
Local and Key Vault signing do not request a timestamp by default.

.EXAMPLE
pwsh -NoProfile -File .\build.ps1

Builds an unsigned MSI without installing PowerShell or system-wide WiX.

.EXAMPLE
$certificate = Get-PfxCertificate -FilePath 'C:\Signing\codesigning.pfx'
.\build.ps1 -SigningCertificate $certificate -TimestampServer 'http://timestamp.digicert.com' -Force

Prompts for the PFX password, signs and timestamps the MSI, and replaces the
previous output only on success. Keep PFX files outside this repository.

.EXAMPLE
$certificate = Get-Item -LiteralPath 'Cert:\CurrentUser\My\0123456789ABCDEF0123456789ABCDEF01234567'
.\build.ps1 -SigningCertificate $certificate

Signs using a certificate already in the Windows certificate store.
Replace the example thumbprint with your actual certificate thumbprint.

.EXAMPLE
$certificateId = az keyvault certificate show --vault-name 'YOUR_VAULT' --name 'YOUR_CERTIFICATE' --query id --output tsv
if ($LASTEXITCODE -ne 0) { throw 'Could not resolve the Key Vault certificate.' }
.\build.ps1 -KeyVaultCertificateId $certificateId -TimestampServer 'http://timestamp.digicert.com' -Force

Resolves an exact certificate version and signs through Key Vault using your
existing Azure CLI session.

.EXAMPLE
$signing = @{
    ArtifactSigningEndpoint = 'https://neu.codesigning.azure.net/'
    ArtifactSigningAccountName = 'YOUR_ACCOUNT'
    ArtifactSigningCertificateProfileName = 'YOUR_PROFILE'
    ExpectedSignerSubject = 'CN=Example Organization, O=Example Organization, C=US'
}
.\build.ps1 @signing

Signs through Artifact Signing using automatically cached SignTool and dlib.
Replace the endpoint, account, profile, and subject with your organization's
values. This backend always requires a timestamp.

.NOTES
Requires Windows. Use a Microsoft-supported PowerShell release; the #Requires
version is only a technical compatibility floor.
Artifact Signing also requires Azure CLI, x64 .NET runtime 8.0 or newer, and the
x64 Visual C++ v14 Redistributable. The script does not log in, create signing
resources, or install system-wide runtimes. Artifact Signing needs live
acceptance testing with an eligible organization's account.
This MSI is not Microsoft-produced and does not receive Microsoft Update
servicing. Test installation and upgrades in a disposable Windows VM.

.LINK
.\README.md

.LINK
.\verify.ps1
#>

[CmdletBinding(DefaultParameterSetName = 'Unsigned')]
param(
    [switch] $Force,

    [Parameter(Mandatory, ParameterSetName = 'Signed')]
    [ValidateNotNull()]
    [System.Security.Cryptography.X509Certificates.X509Certificate2] $SigningCertificate,

    [Parameter(Mandatory, ParameterSetName = 'KeyVault')]
    [ValidateScript({
        $uri = [uri] $_
        if (-not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https' -or -not $uri.Host -or
            $uri.UserInfo -or $uri.Query -or $uri.Fragment -or
            $uri.AbsolutePath -notmatch '^/certificates/[a-zA-Z0-9-]{1,127}/[a-fA-F0-9]{32}$') {
            throw 'KeyVaultCertificateId must be a versioned HTTPS certificate URI: https://<vault>/certificates/<name>/<version>.'
        }
        $true
    })]
    [string] $KeyVaultCertificateId,

    [Parameter(Mandatory, ParameterSetName = 'ArtifactSigning')]
    [ValidateScript({
        $uri = [uri] $_
        if (-not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https' -or
            $uri.Host -notmatch '^[a-z0-9-]+\.codesigning\.azure\.net$' -or
            -not $uri.IsDefaultPort -or $uri.UserInfo -or $uri.Query -or
            $uri.Fragment -or $uri.AbsolutePath -ne '/') {
            throw 'ArtifactSigningEndpoint must be a regional HTTPS endpoint such as https://neu.codesigning.azure.net/.'
        }
        $true
    })]
    [string] $ArtifactSigningEndpoint,

    [Parameter(Mandatory, ParameterSetName = 'ArtifactSigning')]
    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9-]*$')]
    [string] $ArtifactSigningAccountName,

    [Parameter(Mandatory, ParameterSetName = 'ArtifactSigning')]
    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9-]*$')]
    [string] $ArtifactSigningCertificateProfileName,

    [Parameter(Mandatory, ParameterSetName = 'ArtifactSigning')]
    [ValidateNotNullOrEmpty()]
    [string] $ExpectedSignerSubject,

    [Parameter(ParameterSetName = 'ArtifactSigning')]
    [ValidatePattern('^1\.3\.6\.1\.4\.1\.311\.97\.\d+(\.\d+)*$')]
    [string] $ExpectedProfileEku,

    [Parameter(ParameterSetName = 'ArtifactSigning')]
    [ValidateNotNullOrEmpty()]
    [string] $SignToolPath,

    [Parameter(ParameterSetName = 'ArtifactSigning')]
    [ValidateNotNullOrEmpty()]
    [string] $ArtifactSigningDlibPath,

    [Parameter(ParameterSetName = 'Signed')]
    [Parameter(ParameterSetName = 'KeyVault')]
    [Parameter(ParameterSetName = 'ArtifactSigning')]
    [ValidateScript({
        $uri = [uri] $_
        if (-not $uri.IsAbsoluteUri -or $uri.Scheme -notin 'http', 'https' -or -not $uri.Host) {
            throw 'TimestampServer must be an absolute http:// URL for local signing, or an http:// or https:// URL for cloud signing.'
        }
        $true
    })]
    [string] $TimestampServer
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

. (Join-Path $PSScriptRoot 'signing.ps1')

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

function Assert-CodeSigningCertificate {
    param(
        [Parameter(Mandatory)] [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate
    )

    $now = Get-Date
    if ($now -lt $Certificate.NotBefore -or $now -gt $Certificate.NotAfter) {
        throw 'The signing certificate is not currently valid.'
    }
    $eku = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' }
    if (-not $eku -or '1.3.6.1.5.5.7.3.3' -notin $eku.EnhancedKeyUsages.Value) {
        throw 'The signing certificate must have the Code Signing enhanced key usage.'
    }
}

function Invoke-MsiSigning {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
        [string] $TimestampServer
    )

    $signingParameters = @{
        LiteralPath = $Path
        Certificate = $Certificate
        HashAlgorithm = 'SHA256'
        IncludeChain = 'NotRoot'
        ErrorAction = 'Stop'
    }
    if ($TimestampServer) {
        $signingParameters.TimestampServer = $TimestampServer
    }

    $signature = Set-AuthenticodeSignature @signingParameters
    if ($signature.Status -ne 'Valid') {
        throw "MSI signing failed: $($signature.Status). $($signature.StatusMessage)"
    }

    Assert-MsiSignature -Path $Path -Certificate $Certificate -RequireTimestamp:([bool] $TimestampServer)
}

function Get-VerifiedFile {
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

function Get-KeyVaultSigningCertificate {
    param(
        [Parameter(Mandatory)] [string] $CertificateId
    )

    $json = Invoke-NativeTool -Tool 'az' -ToolArguments @(
        'keyvault', 'certificate', 'show', '--id', $CertificateId,
        '--query', '{id:id,cer:cer}', '--output', 'json', '--only-show-errors'
    )
    $metadata = ($json -join [Environment]::NewLine) | ConvertFrom-Json
    if ($metadata.id -ne $CertificateId) {
        throw "Key Vault returned a different certificate version: $($metadata.id). Expected $CertificateId."
    }
    return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        [Convert]::FromBase64String($metadata.cer)
    )
}

function Get-ArtifactSigningTool {
    param(
        [Parameter(Mandatory)] [pscustomobject] $Dependency,
        [Parameter(Mandatory)] [string] $CacheDirectory,
        [Parameter(Mandatory)] [string] $WorkDirectory
    )

    $fileName = [IO.Path]::GetFileName(([uri] $Dependency.url).AbsolutePath)
    $archive = Join-Path $CacheDirectory $fileName
    Get-VerifiedFile -Uri $Dependency.url -Sha256 $Dependency.sha256 -Path $archive

    # Re-extract verified archives into this build's private workspace, never reuse loose cached binaries.
    $directory = Join-Path $WorkDirectory ([IO.Path]::GetFileNameWithoutExtension($fileName))
    [IO.Compression.ZipFile]::ExtractToDirectory($archive, $directory)
    $tool = Join-Path $directory $Dependency.toolPath
    if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) {
        throw "The signing tools package does not contain the expected x64 tool: $($Dependency.toolPath)."
    }
    return $tool
}

function Get-ArtifactSigningRuntimeStatus {
    $dotNetVersions = @()
    # .NET records all architectures in the 32-bit registry view.
    $registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry32
    )
    try {
        $key = $registry.OpenSubKey('SOFTWARE\dotnet\Setup\InstalledVersions\x64\sharedfx\Microsoft.NETCore.App')
        if ($key) {
            try { $dotNetVersions = @($key.GetValueNames()) }
            finally { $key.Dispose() }
        }
    }
    finally { $registry.Dispose() }

    $visualCppInstalled = $false
    $registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64
    )
    try {
        $key = $registry.OpenSubKey('SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64')
        if ($key) {
            try { $visualCppInstalled = $key.GetValue('Installed') -eq 1 }
            finally { $key.Dispose() }
        }
    }
    finally { $registry.Dispose() }

    return [pscustomobject] @{
        DotNetVersions = $dotNetVersions
        VisualCppInstalled = $visualCppInstalled
    }
}

function Assert-ArtifactSigningPrerequisites {
    $runtime = Get-ArtifactSigningRuntimeStatus
    if (-not ($runtime.DotNetVersions | Where-Object {
        $_ -match '^\d+\.\d+\.\d+$' -and [version] $_ -ge [version] '8.0.0'
    })) {
        throw 'Artifact Signing requires an installed x64 .NET runtime 8.0 or newer. Install it from https://dotnet.microsoft.com/download/dotnet/8.0 and retry; no runtime is installed automatically.'
    }
    if (-not $runtime.VisualCppInstalled) {
        throw 'Artifact Signing requires the x64 Visual C++ v14 Redistributable. Install the latest supported version from https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist and retry; no runtime is installed automatically.'
    }
}

function Invoke-KeyVaultMsiSigning {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $CertificateId,
        [Parameter(Mandatory)] [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
        [Parameter(Mandatory)] [string] $Tool,
        [string] $TimestampServer
    )

    $uri = [uri] $CertificateId
    $arguments = @(
        'sign', '-kvu', $uri.GetLeftPart([UriPartial]::Authority),
        '-kvc', $uri.Segments[2].TrimEnd('/'), '-kvcv', $uri.Segments[3],
        '-kvm', '-fd', 'sha256'
    )
    if ($TimestampServer) {
        $arguments += @('-tr', $TimestampServer, '-td', 'sha256')
    }
    $arguments += $Path

    $previousCredential = [Environment]::GetEnvironmentVariable('AZURE_TOKEN_CREDENTIALS', 'Process')
    try {
        # Restrict DefaultAzureCredential to the caller's existing Azure CLI login.
        [Environment]::SetEnvironmentVariable('AZURE_TOKEN_CREDENTIALS', 'AzureCliCredential', 'Process')
        Invoke-NativeTool -Tool $Tool -ToolArguments $arguments
    }
    finally {
        [Environment]::SetEnvironmentVariable('AZURE_TOKEN_CREDENTIALS', $previousCredential, 'Process')
    }
    Assert-MsiSignature -Path $Path -Certificate $Certificate -RequireTimestamp:([bool] $TimestampServer)
}

if ($PSCmdlet.ParameterSetName -eq 'Signed') {
    if ($TimestampServer -and ([uri] $TimestampServer).Scheme -ne 'http') {
        throw 'TimestampServer must be an absolute http:// URL for an Authenticode timestamp service.'
    }
    if (-not $SigningCertificate.HasPrivateKey) {
        throw 'The signing certificate must have an accessible private key.'
    }
    Assert-CodeSigningCertificate -Certificate $SigningCertificate
}
elseif ($PSCmdlet.ParameterSetName -eq 'ArtifactSigning') {
    Get-Command az -ErrorAction Stop | Out-Null
    Assert-ArtifactSigningPrerequisites
    if ($SignToolPath) {
        $SignToolPath = (Resolve-Path -LiteralPath $SignToolPath -ErrorAction Stop).ProviderPath
        if (-not (Test-Path -LiteralPath $SignToolPath -PathType Leaf) -or
            [IO.Path]::GetExtension($SignToolPath) -ne '.exe') {
            throw 'SignToolPath must point to an x64 signtool.exe file.'
        }
    }
    if ($ArtifactSigningDlibPath) {
        $ArtifactSigningDlibPath = (Resolve-Path -LiteralPath $ArtifactSigningDlibPath -ErrorAction Stop).ProviderPath
        if (-not (Test-Path -LiteralPath $ArtifactSigningDlibPath -PathType Leaf) -or
            [IO.Path]::GetExtension($ArtifactSigningDlibPath) -ne '.dll') {
            throw 'ArtifactSigningDlibPath must point to an x64 Azure.CodeSigning.Dlib.dll file.'
        }
    }
    if (-not $TimestampServer) {
        $TimestampServer = 'http://timestamp.acs.microsoft.com'
    }
}

$workDir = $null
$keyVaultCertificate = $null
try {
    if ($PSCmdlet.ParameterSetName -eq 'KeyVault') {
        Get-Command az -ErrorAction Stop | Out-Null
        $keyVaultCertificate = Get-KeyVaultSigningCertificate -CertificateId $KeyVaultCertificateId
        Assert-CodeSigningCertificate -Certificate $keyVaultCertificate
    }

    New-Item -ItemType Directory -Path $cacheDir, $workRoot, $outputDir -Force | Out-Null
    if ($PSCmdlet.ParameterSetName -eq 'KeyVault') {
        $signingTool = Join-Path $cacheDir "AzureSignTool-$($dependencies.azureSignTool.version)-x64.exe"
        Get-VerifiedFile -Uri $dependencies.azureSignTool.url -Sha256 $dependencies.azureSignTool.sha256 -Path $signingTool
    }
    $powerShellZip = Join-Path $cacheDir "PowerShell-$versionText-win-x64.zip"
    $wixZip = Join-Path $cacheDir 'wix314-binaries.zip'
    Get-VerifiedFile -Uri $dependencies.powerShell.url -Sha256 $dependencies.powerShell.sha256 -Path $powerShellZip
    Get-VerifiedFile -Uri $dependencies.wix.url -Sha256 $dependencies.wix.sha256 -Path $wixZip

    $workDir = Join-Path $workRoot ([guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $workDir | Out-Null
    if ($PSCmdlet.ParameterSetName -eq 'ArtifactSigning') {
        if (-not $SignToolPath) {
            $SignToolPath = Get-ArtifactSigningTool -Dependency $dependencies.windowsSdkBuildTools `
                -CacheDirectory $cacheDir -WorkDirectory $workDir
        }
        if (-not $ArtifactSigningDlibPath) {
            $ArtifactSigningDlibPath = Get-ArtifactSigningTool -Dependency $dependencies.artifactSigningClient `
                -CacheDirectory $cacheDir -WorkDirectory $workDir
        }
    }
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
        Invoke-NativeTool -Tool (Join-Path $wixDir 'heat.exe') -ToolArguments @(
            'dir', $payloadDir, '-nologo', '-dr', 'VersionFolder', '-cg', 'ApplicationFiles',
            '-ag', '-sfrag', '-srd', '-scom', '-sreg', '-out', $fragment,
            '-var', 'var.ProductSourcePath'
        )

        Write-Host 'Compiling the legacy PowerShell installer authoring'
        # WixShellExec expands its target at runtime; CNDL1077 is not applicable.
        Invoke-NativeTool -Tool (Join-Path $wixDir 'candle.exe') -ToolArguments (
            @('-nologo', '-sw1077', '-arch', 'x64', '-out', $productObject) + $extensions + $definitions +
            @((Join-Path $PSScriptRoot 'assets\wix\Product.wxs'))
        )
        Invoke-NativeTool -Tool (Join-Path $wixDir 'candle.exe') -ToolArguments (
            @('-nologo', '-arch', 'x64', '-out', $fragmentObject) + $extensions + $definitions + @($fragment)
        )

        Write-Host 'Linking the unsigned MSI'
        Invoke-NativeTool -Tool (Join-Path $wixDir 'light.exe') -ToolArguments (
            @('-nologo', '-sice:ICE61', '-sice:ICE40', '-sice:ICE57',
              '-out', $temporaryMsi, '-pdbout', $temporaryPdb, $productObject, $fragmentObject) + $extensions
        )
    }
    finally {
        Pop-Location
    }

    if ($PSCmdlet.ParameterSetName -eq 'Signed') {
        Write-Host "Signing the MSI with $($SigningCertificate.Subject)"
        Invoke-MsiSigning -Path $temporaryMsi -Certificate $SigningCertificate -TimestampServer $TimestampServer
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'KeyVault') {
        Write-Host "Signing the MSI with Key Vault certificate $KeyVaultCertificateId"
        Invoke-KeyVaultMsiSigning -Path $temporaryMsi -CertificateId $KeyVaultCertificateId `
            -Certificate $keyVaultCertificate -Tool $signingTool -TimestampServer $TimestampServer
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'ArtifactSigning') {
        Write-Host "Signing the MSI with Artifact Signing profile $ArtifactSigningAccountName/$ArtifactSigningCertificateProfileName"
        Invoke-ArtifactMsiSigning -Path $temporaryMsi -Endpoint $ArtifactSigningEndpoint `
            -AccountName $ArtifactSigningAccountName -CertificateProfileName $ArtifactSigningCertificateProfileName `
            -ExpectedSignerSubject $ExpectedSignerSubject -ExpectedProfileEku $ExpectedProfileEku `
            -SignToolPath $SignToolPath -DlibPath $ArtifactSigningDlibPath -TimestampServer $TimestampServer
    }

    Move-Item -LiteralPath $temporaryMsi -Destination $output -Force:$Force
    $hash = (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash
    Write-Host "Created $output"
    Write-Host "SHA-256: $hash"
}
finally {
    if ($keyVaultCertificate) {
        $keyVaultCertificate.Dispose()
    }
    if ($workDir -and (Test-Path -LiteralPath $workDir)) {
        Remove-Item -LiteralPath $workDir -Recurse -Force
    }
}
