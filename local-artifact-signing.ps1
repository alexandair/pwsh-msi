#Requires -Version 7.2

<#
.SYNOPSIS
Builds and verifies an MSI signed with your Microsoft Artifact Signing profile.

.DESCRIPTION
Uses caller-supplied subscription, regional endpoint, account, and profile
settings. Requires an existing Azure CLI login and selects the given subscription.
Does not log in, create Azure resources, or install the MSI.

DownloadCertificates uses the existing Azure PowerShell login to download public
root and chain certificates, export intermediate CAs, and report fingerprints
and the exact signer subject. It does not install certificates.

Signing is the default mode and requires ExpectedSignerSubject. Only explicitly
supplied CA files are imported into the current user's stores. Existing CA trust
can be reused on subsequent runs. The script builds and timestamps the MSI, then
verifies its signature, signer, timestamp, installer properties, and full payload.

.PARAMETER SubscriptionId
Subscription containing the Artifact Signing account.

.PARAMETER Endpoint
Account's regional HTTPS endpoint. For example, https://neu.codesigning.azure.net/
is for North Europe; use the endpoint for your account's region.

.PARAMETER AccountName
Artifact Signing account name.

.PARAMETER CertificateProfileName
Public Trust or Private Trust code-signing certificate profile name.

.PARAMETER ExpectedSignerSubject
Exact Windows certificate subject, required for signing. The download result
includes SignerSubject. If supplied when downloading, it must match that subject.

.PARAMETER DownloadCertificates
Downloads public certificates only. Requires Az.ArtifactSigning; install it with
Install-Module Az.ArtifactSigning -Scope CurrentUser if needed.

.PARAMETER CertificateDirectory
Download directory. Defaults to cache\artifact-signing\<subscription>\<account>\
<profile> under this repository, keeping different profiles' files separate.

.PARAMETER TrustedRootCertificatePath
Approved public root CA .cer file to trust for the current Windows user.
Omit CA paths when Windows already trusts the chain.

.PARAMETER IntermediateCertificatePath
Approved intermediate CA .cer files to import into the current user's CA store.

.PARAMETER Force
Allows replacement of downloaded certificate files in download mode, or the MSI
after a successful signed build in signing mode. Does not bypass verification.

.EXAMPLE
$signing = @{
    SubscriptionId = '<SUBSCRIPTION_ID>'
    Endpoint = '<YOUR_REGIONAL_CODESIGNING_ENDPOINT>'
    AccountName = '<YOUR_ACCOUNT>'
    CertificateProfileName = '<YOUR_PROFILE>'
}
$certificates = .\local-artifact-signing.ps1 @signing -DownloadCertificates

Downloads certificates without trusting them. Verify the displayed CA
fingerprints with the profile owner before using the next example.

.EXAMPLE
$signing.ExpectedSignerSubject = $certificates.SignerSubject
.\local-artifact-signing.ps1 @signing -TrustedRootCertificatePath $certificates.RootCertificatePath -IntermediateCertificatePath $certificates.IntermediateCertificatePath -Force

Imports only the approved CAs, builds and signs the MSI, and verifies the result.
Public Trust normally needs no CA import; omit the two CA path parameters then.

.EXAMPLE
.\local-artifact-signing.ps1 @signing -Force

Reuses the same settings and installed CAs to rebuild, sign, and verify. Force
allows replacement of the existing MSI. No certificate download is needed.

.NOTES
Run in PowerShell 7 on Windows. Authenticate Azure CLI before signing, and
Connect-AzAccount before downloading certificates. The identity needs Artifact
Signing Certificate Profile Signer access. build.ps1 checks runtime prerequisites
and downloads the signing tools. The signed MSI is written to out.
CA trust persists for the current Windows user. Routine signing-certificate
rotation does not require reinstalling CAs; changes to the CA chain may.

.LINK
.\README.md
#>

[CmdletBinding(DefaultParameterSetName = 'Sign')]
param(
    [Parameter(Mandatory)]
    [guid] $SubscriptionId,

    [Parameter(Mandatory)]
    [ValidateScript({
        $uri = [uri] $_
        if (-not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https' -or
            $uri.Host -notmatch '^[a-z0-9-]+\.codesigning\.azure\.net$' -or
            -not $uri.IsDefaultPort -or $uri.UserInfo -or $uri.Query -or
            $uri.Fragment -or $uri.AbsolutePath -ne '/') {
            throw 'Endpoint must be a regional HTTPS endpoint such as https://neu.codesigning.azure.net/.'
        }
        $true
    })]
    [string] $Endpoint,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9-]*$')]
    [string] $AccountName,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9-]*$')]
    [string] $CertificateProfileName,

    [Parameter(Mandatory, ParameterSetName = 'Sign')]
    [Parameter(ParameterSetName = 'Download')]
    [ValidateNotNullOrEmpty()]
    [string] $ExpectedSignerSubject,

    [Parameter(Mandatory, ParameterSetName = 'Download')]
    [switch] $DownloadCertificates,

    [Parameter(ParameterSetName = 'Download')]
    [ValidateNotNullOrEmpty()]
    [string] $CertificateDirectory,

    [Parameter(ParameterSetName = 'Sign')]
    [ValidateNotNullOrEmpty()]
    [string] $TrustedRootCertificatePath,

    [Parameter(ParameterSetName = 'Sign')]
    [string[]] $IntermediateCertificatePath,

    [switch] $Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'signing.ps1')

function Invoke-LocalArtifactSigning {
    [CmdletBinding()]
    param(
        [string] $ProjectRoot,
        [string] $SubscriptionId,
        [string] $Endpoint,
        [string] $AccountName,
        [string] $CertificateProfileName,
        [string] $ExpectedSignerSubject,
        [switch] $DownloadCertificates,
        [string] $CertificateDirectory,
        [string] $TrustedRootCertificatePath,
        [string[]] $IntermediateCertificatePath,
        [switch] $Force
    )

    if (-not $IsWindows) { throw 'Local Artifact Signing requires Windows.' }
    $profileParameters = @{
        AccountName = $AccountName
        ProfileName = $CertificateProfileName
        EndpointUrl = $Endpoint
    }
    Invoke-NativeTool -Tool az -ToolArguments @('account', 'set', '--subscription', $SubscriptionId)

    if ($DownloadCertificates) {
        Import-Module -Name Az.ArtifactSigning -ErrorAction Stop
        $accountJson = Invoke-NativeTool -Tool az -ToolArguments @('account', 'show', '--output', 'json')
        $account = ($accountJson -join [Environment]::NewLine) | ConvertFrom-Json
        $null = Set-AzContext -Subscription $SubscriptionId -Tenant $account.tenantId -Scope Process -ErrorAction Stop
        if (-not $CertificateDirectory) {
            $CertificateDirectory = Join-Path $ProjectRoot "cache\artifact-signing\$SubscriptionId\$AccountName\$CertificateProfileName"
        }
        $null = New-Item -ItemType Directory -Path $CertificateDirectory -Force
        $directory = (Resolve-Path -LiteralPath $CertificateDirectory).ProviderPath
        $rootPath = Join-Path $directory 'profile-root.cer'
        $chainPath = Join-Path $directory 'profile-chain.der'
        foreach ($path in @($rootPath, $chainPath)) {
            if ((Test-Path -LiteralPath $path) -and -not $Force) {
                throw "Certificate file already exists: $path. Use -DownloadCertificates -Force to replace it."
            }
        }
        $null = Get-AzArtifactSigningCertificateRoot @profileParameters -Destination $rootPath
        $null = Get-AzArtifactSigningCertificateChain @profileParameters -Destination $chainPath
        $rootCertificate = Get-ArtifactSigningCaCertificate -Path $rootPath -Root
        $rootCertificate.Dispose()
        $chain = [Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        try {
            $chain.Import($chainPath)
            $signers = @($chain | Where-Object {
                $constraints = $_.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' }
                $eku = $_.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' }
                -not ($constraints -and $constraints.CertificateAuthority) -and
                    $eku -and '1.3.6.1.5.5.7.3.3' -in $eku.EnhancedKeyUsages.Value
            })
            if ($signers.Count -ne 1) { throw 'Expected one code-signing leaf certificate in the profile chain.' }
            if ($ExpectedSignerSubject -and $signers[0].Subject -cne $ExpectedSignerSubject) {
                throw "Expected subject '$ExpectedSignerSubject', got '$($signers[0].Subject)'."
            }
            $intermediatePaths = @(
                foreach ($certificate in $chain) {
                    $constraints = $certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' }
                    if ($constraints -and $constraints.CertificateAuthority -and
                        $certificate.Subject -ne $certificate.Issuer) {
                        $path = Join-Path $directory "intermediate-$($certificate.Thumbprint).cer"
                        if ((Test-Path -LiteralPath $path) -and -not $Force) {
                            throw "Certificate file already exists: $path. Use -DownloadCertificates -Force to replace it."
                        }
                        [IO.File]::WriteAllBytes($path, $certificate.RawData)
                        $path
                    }
                }
            )
            foreach ($path in @($rootPath) + $intermediatePaths) {
                Write-Host "$path`nSHA-256: $((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash)"
            }
            Write-Host "Signer subject: $($signers[0].Subject)"
            Write-Host 'Have the profile owner verify the CA fingerprints before trusting these files.'
            return [pscustomobject] @{
                RootCertificatePath = $rootPath
                IntermediateCertificatePath = $intermediatePaths
                SignerSubject = $signers[0].Subject
            }
        }
        finally {
            foreach ($certificate in $chain) { $certificate.Dispose() }
        }
    }

    $rootBase64 = ''
    if ($TrustedRootCertificatePath) {
        $rootCertificate = Get-ArtifactSigningCaCertificate -Path $TrustedRootCertificatePath -Root
        try { $rootBase64 = [Convert]::ToBase64String($rootCertificate.RawData) }
        finally { $rootCertificate.Dispose() }
    }
    $intermediateBase64 = @(
        foreach ($path in $IntermediateCertificatePath) {
            $certificate = Get-ArtifactSigningCaCertificate -Path $path
            try { [Convert]::ToBase64String($certificate.RawData) }
            finally { $certificate.Dispose() }
        }
    ) -join "`n"
    if ($rootBase64 -or $intermediateBase64) {
        Import-ArtifactSigningTrust -RootCertificateBase64 $rootBase64 -IntermediateCertificatesBase64 $intermediateBase64
    }
    $pwsh = (Get-Command pwsh -ErrorAction Stop).Source
    $arguments = @(
        '-NoProfile', '-File', (Join-Path $ProjectRoot 'build.ps1'),
        '-ArtifactSigningEndpoint', $Endpoint,
        '-ArtifactSigningAccountName', $AccountName,
        '-ArtifactSigningCertificateProfileName', $CertificateProfileName,
        '-ExpectedSignerSubject', $ExpectedSignerSubject
    )
    if ($Force) { $arguments += '-Force' }
    Invoke-NativeTool -Tool $pwsh -ToolArguments $arguments
    $dependencies = Get-Content -LiteralPath (Join-Path $ProjectRoot 'dependencies.json') -Raw | ConvertFrom-Json
    $msi = Join-Path $ProjectRoot "out\PowerShell-$($dependencies.powerShell.version)-win-x64-unofficial.msi"
    Invoke-NativeTool -Tool $pwsh -ToolArguments @(
        '-NoProfile', '-File', (Join-Path $ProjectRoot 'verify.ps1'),
        '-MsiPath', $msi, '-ExpectedSignerSubject', $ExpectedSignerSubject
    )
    Write-Host 'Signed MSI passed signature, timestamp, installer, and payload verification.'
    [pscustomobject] @{
        MsiPath = $msi
        SHA256 = (Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash
    }
}

$signingParameters = @{} + $PSBoundParameters
$signingParameters.ProjectRoot = $PSScriptRoot
Invoke-LocalArtifactSigning @signingParameters
