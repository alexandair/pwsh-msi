#Requires -Version 7.2

<#
.SYNOPSIS
Loads shared native-tool, MSI signature, and Artifact Signing helpers.

.DESCRIPTION
Dot-source this file to define signing, verification, and CA certificate helpers.
Loading it does not sign files, download tools, install certificates, or
authenticate to Azure.

Assert-MsiSignature checks Windows trust and either a certificate thumbprint
or an exact signer subject, with optional profile EKU and timestamp checks.
Invoke-ArtifactMsiSigning signs in place with supplied SignTool and dlib paths,
uses the existing Azure CLI login, removes temporary metadata, and verifies
the signer and mandatory RFC 3161 timestamp.

Use build.ps1 for normal builds and automatic tool acquisition, or verify.ps1
for full installer and payload verification.

.EXAMPLE
. .\signing.ps1
Get-Command Assert-MsiSignature, Invoke-ArtifactMsiSigning, Invoke-NativeTool

Loads the helpers without invoking any signing or cloud operations.

.EXAMPLE
. .\signing.ps1
Assert-MsiSignature -Path 'C:\Packages\organization-powershell.msi' -ExpectedSignerSubject 'CN=Example Organization, O=Example Organization, C=US' -RequireTimestamp

Checks a trusted Windows signature, exact signer subject, Code Signing EKU,
and timestamp. Does not check installer identity or payload.

.EXAMPLE
. .\signing.ps1
$certificate = Get-Item -LiteralPath 'Cert:\CurrentUser\My\0123456789ABCDEF0123456789ABCDEF01234567'
Assert-MsiSignature -Path 'C:\Packages\organization-powershell.msi' -Certificate $certificate

Checks that a trusted signature matches the selected certificate's thumbprint.
Replace the example thumbprint with your actual certificate thumbprint.

.EXAMPLE
. .\signing.ps1
$root = Get-ArtifactSigningCaCertificate -Path 'C:\Signing\profile-root.cer' -Root
$root.Dispose()

Checks that a supplied public certificate is a root CA without installing it.

.NOTES
Signing and Authenticode verification require Windows. Direct Artifact Signing
requires matching x64 tools with their adjacent dependencies, supported .NET
and Visual C++ runtimes, an authenticated Azure CLI session, and profile
signing permission. A failed direct signing call can leave its input modified;
build.ps1 protects published output by signing a temporary MSI instead.
Only Import-ArtifactSigningTrust installs explicitly supplied CA certificates,
into the current user's stores. No helper logs in.

.LINK
.\README.md

.LINK
.\build.ps1

.LINK
.\verify.ps1
#>



function Invoke-NativeTool {
    param(
        [Parameter(Mandatory)] [string] $Tool,
        [Parameter(Mandatory)] [string[]] $ToolArguments
    )

    & $Tool @ToolArguments
    if ($LASTEXITCODE -ne 0) {
        throw "$([IO.Path]::GetFileName($Tool)) failed with exit code $LASTEXITCODE."
    }
}

function Get-ArtifactSigningCaCertificate {
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Path')] [string] $Path,
        [Parameter(Mandatory, ParameterSetName = 'Base64')] [string] $Base64Certificate,
        [switch] $Root
    )

    [byte[]] $bytes = if ($PSCmdlet.ParameterSetName -eq 'Path') {
        [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath)
    }
    else {
        [Convert]::FromBase64String($Base64Certificate)
    }
    if ([Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType($bytes) -ne
        [Security.Cryptography.X509Certificates.X509ContentType]::Cert) {
        throw 'Supply one public CA certificate (.cer), not a PFX or certificate bundle.'
    }
    $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes)
    $valid = $false
    try {
        $constraints = $certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' }
        if (-not $constraints -or -not $constraints.CertificateAuthority) {
            throw 'The supplied certificate is not a CA certificate. Do not trust a signing leaf as a root.'
        }
        $selfIssued = [Convert]::ToBase64String($certificate.SubjectName.RawData) -ceq
            [Convert]::ToBase64String($certificate.IssuerName.RawData)
        if ($Root -and -not $selfIssued) {
            throw 'The supplied root CA must be self-issued. Supply intermediate CAs separately.'
        }
        if (-not $Root -and $selfIssued) {
            throw 'The supplied intermediate CA is a root. Supply it as the root CA instead.'
        }
        $valid = $true
        return $certificate
    }
    finally {
        if (-not $valid) { $certificate.Dispose() }
    }
}

function Import-ArtifactSigningTrust {
    param(
        [string] $RootCertificateBase64,
        [string] $IntermediateCertificatesBase64
    )

    $imports = @()
    try {
        if ($RootCertificateBase64) {
            $imports += @{
                Certificate = Get-ArtifactSigningCaCertificate -Base64Certificate $RootCertificateBase64 -Root
                Store = 'Cert:\CurrentUser\Root'
            }
        }
        foreach ($encoded in ($IntermediateCertificatesBase64 -split '\s+' | Where-Object { $_ })) {
            $imports += @{
                Certificate = Get-ArtifactSigningCaCertificate -Base64Certificate $encoded
                Store = 'Cert:\CurrentUser\CA'
            }
        }
        foreach ($item in $imports) {
            $path = Join-Path ([IO.Path]::GetTempPath()) "artifact-signing-ca-$([guid]::NewGuid().ToString('N')).cer"
            try {
                [IO.File]::WriteAllBytes($path, $item.Certificate.RawData)
                $null = Import-Certificate -FilePath $path -CertStoreLocation $item.Store -ErrorAction Stop
                Write-Host "Imported approved CA $($item.Certificate.Thumbprint) into $($item.Store)."
            }
            finally {
                if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force -ErrorAction Stop }
            }
        }
    }
    finally {
        foreach ($item in $imports) { $item.Certificate.Dispose() }
    }
}

function Assert-MsiSignature {
    [CmdletBinding(DefaultParameterSetName = 'Certificate')]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory, ParameterSetName = 'Certificate')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
        [Parameter(Mandatory, ParameterSetName = 'Subject')]
        [ValidateNotNullOrEmpty()] [string] $ExpectedSignerSubject,
        [Parameter(ParameterSetName = 'Subject')]
        [string] $ExpectedProfileEku,
        [switch] $RequireTimestamp
    )

    $expectedSigner = if ($PSCmdlet.ParameterSetName -eq 'Certificate') {
        $Certificate.Thumbprint
    }
    else {
        $ExpectedSignerSubject
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate) {
        throw "MSI signature verification failed for expected signer ${expectedSigner}: $($signature.Status). $($signature.StatusMessage)"
    }
    if ($PSCmdlet.ParameterSetName -eq 'Certificate') {
        if ($signature.SignerCertificate.Thumbprint -ne $Certificate.Thumbprint) {
            throw "MSI signature verification failed for expected signer ${expectedSigner}: signer thumbprint does not match."
        }
    }
    else {
        if ($signature.SignerCertificate.Subject -cne $ExpectedSignerSubject) {
            throw "MSI signature verification failed: expected subject '$ExpectedSignerSubject', got '$($signature.SignerCertificate.Subject)'."
        }
        $eku = $signature.SignerCertificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' }
        if (-not $eku -or '1.3.6.1.5.5.7.3.3' -notin $eku.EnhancedKeyUsages.Value) {
            throw 'The MSI signer does not have the Code Signing enhanced key usage.'
        }
        if ($ExpectedProfileEku -and $ExpectedProfileEku -notin $eku.EnhancedKeyUsages.Value) {
            throw "The MSI signer does not have the expected Artifact Signing profile EKU: $ExpectedProfileEku."
        }
    }
    if ($RequireTimestamp -and -not $signature.TimeStamperCertificate) {
        throw 'The MSI signature does not contain the requested timestamp.'
    }
}

function Invoke-ArtifactMsiSigning {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [uri] $Endpoint,
        [Parameter(Mandatory)] [string] $AccountName,
        [Parameter(Mandatory)] [string] $CertificateProfileName,
        [Parameter(Mandatory)] [string] $ExpectedSignerSubject,
        [string] $ExpectedProfileEku,
        [Parameter(Mandatory)] [string] $SignToolPath,
        [Parameter(Mandatory)] [string] $DlibPath,
        [string] $TimestampServer = 'http://timestamp.acs.microsoft.com'
    )

    $metadataPath = Join-Path (Split-Path -Parent $Path) "artifact-signing-$([guid]::NewGuid().ToString('N')).json"
    try {
        @{
            Endpoint = $Endpoint.AbsoluteUri
            CodeSigningAccountName = $AccountName
            CertificateProfileName = $CertificateProfileName
            ExcludeCredentials = @(
                'EnvironmentCredential', 'WorkloadIdentityCredential', 'ManagedIdentityCredential',
                'SharedTokenCacheCredential', 'VisualStudioCredential', 'VisualStudioCodeCredential',
                'AzurePowerShellCredential', 'AzureDeveloperCliCredential', 'InteractiveBrowserCredential'
            )
        } | ConvertTo-Json | Set-Content -LiteralPath $metadataPath -Encoding utf8

        Invoke-NativeTool -Tool $SignToolPath -ToolArguments @(
            'sign', '/fd', 'SHA256', '/tr', $TimestampServer, '/td', 'SHA256',
            '/dlib', $DlibPath, '/dmdf', $metadataPath, $Path
        )
    }
    finally {
        if (Test-Path -LiteralPath $metadataPath) {
            Remove-Item -LiteralPath $metadataPath -Force
        }
    }
    Assert-MsiSignature -Path $Path -ExpectedSignerSubject $ExpectedSignerSubject `
        -ExpectedProfileEku $ExpectedProfileEku -RequireTimestamp
}
