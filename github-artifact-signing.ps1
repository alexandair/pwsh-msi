#Requires -Version 7.2

<#
.SYNOPSIS
Sets up and tests the GitHub Actions Artifact Signing workflow.

.DESCRIPTION
Uses setup-artifact-signing.ps1 to configure OIDC, the protected GitHub
environment, and profile-scoped signing permissions. Run setup with WhatIf first.
The signing account and certificate profile must already exist.

Run dispatches artifact-signing.yml on the remote default branch and returns
the exact run ID. No reviewer is required by default. If reviewers are configured,
another designated reviewer must approve the environment in GitHub.
This script never approves jobs or pushes files.

RunId downloads a completed run's signed artifact into temporary staging,
verifies its signature and full payload, compares its SHA-256 with the run log,
and publishes it under out\github. It does not replace the locally built MSI.
The current checkout's build and verification files must match the remote
revision. Cloud calls require existing gh and, for setup, az authentication.

.PARAMETER Repository
GitHub.com repository in OWNER/REPOSITORY form.

.PARAMETER Setup
Calls setup-artifact-signing.ps1. Requires its Azure and GitHub administrator
permissions, a certificate profile ARM ID, and approved Private Trust
CA files. Does not dispatch a run. WhatIf performs read-only prerequisite checks.

.PARAMETER Run
Starts a new signing run after setup. This is the default mode.
Returns RunId and RunUrl without waiting for reviewer approval or completion.

.PARAMETER RunId
Exact completed run to download and verify. Never selects the latest run.
Failed, incomplete, wrong-workflow, and skipped signing jobs are rejected.

.PARAMETER CertificateProfileId
Full ARM ID of the existing signing certificate profile. Used during setup.
Setup derives the tenant, subscription, and regional endpoint from this resource.

.PARAMETER ExpectedSignerSubject
Exact Windows signer subject. Required for setup and download verification.
When supplied during dispatch, must match the protected environment's value.

.PARAMETER Reviewer
Optional GitHub users or ORG/TEAM-SLUG values (up to six). Used during setup.
Omit for solo use with no reviewer approval. Omitting also removes any previously
configured required reviewers. If supplied, another reviewer must approve runs.

.PARAMETER ExpectedProfileEku
Optional durable profile identity OID. Forwarded to setup or local verification.
When supplied during dispatch, must match the protected environment's value.

.PARAMETER ApplicationClientId
Optional existing Entra application client ID. Used during setup.
Without it, setup creates or reuses the repository's dedicated application.

.PARAMETER TrustedRootCertificatePath
Approved public root CA .cer file for the hosted runner. Required during setup
for Private Trust. Does not configure trust on this verification machine.

.PARAMETER IntermediateCertificatePath
Approved intermediate CA .cer files for the hosted runner. Used during setup.

.PARAMETER Force
Allows replacing this run attempt's previously downloaded MSI, but only after
the new download passes every check. Does not rerun or approve a workflow.

.EXAMPLE
$github = @{
    Repository = 'YOUR_ORG/YOUR_REPOSITORY'
    ExpectedSignerSubject = 'CN=Example Organization, O=Example Organization, C=US'
}
$setup = @{
    CertificateProfileId = '/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RESOURCE_GROUP>/providers/Microsoft.CodeSigning/codeSigningAccounts/<ACCOUNT>/certificateProfiles/<PROFILE>'
    TrustedRootCertificatePath = 'C:\Signing\profile-root.cer'
}
.\github-artifact-signing.ps1 @github -Setup @setup -WhatIf
.\github-artifact-signing.ps1 @github -Setup @setup

Previews and then configures a Private Trust workflow. Omit the CA parameter
for Public Trust when no additional CA installation is needed.

.EXAMPLE
$run = .\github-artifact-signing.ps1 @github -Run
$run

Starts a run and returns its ID and URL. Follow RunUrl and wait for completion.
Reviewer approval is needed only if configured.

.EXAMPLE
.\github-artifact-signing.ps1 @github -RunId $run.RunId

Downloads and verifies that exact successful run. Requires Windows, locally
trusted signing CAs, and the matching cached PowerShell ZIP from a local build.

.EXAMPLE
.\github-artifact-signing.ps1 @github -RunId 123456789 -Force

Replaces a previously downloaded result after verification. Use your actual
run ID. To create a new MSI instead, use Run; setup is not needed again.

.NOTES
Publish the current workflow and build/verification files to the repository's
default branch before setup. Source comparisons ignore Windows line endings.
Setup requires the permissions and GitHub plan documented in README.md.
No client secret, signing account, or certificate profile is created.
Downloaded packages are not installed. No trust store is modified locally.
Local full-payload verification uses the hash-pinned ZIP in cache.

.LINK
.\README.md

.LINK
.\setup-artifact-signing.ps1
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Run')]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')]
    [string] $Repository,

    [Parameter(Mandatory, ParameterSetName = 'Setup')]
    [switch] $Setup,

    [Parameter(ParameterSetName = 'Run')]
    [switch] $Run,

    [Parameter(Mandatory, ParameterSetName = 'Download')]
    [ValidateRange(1, [long]::MaxValue)]
    [long] $RunId,

    [Parameter(Mandatory, ParameterSetName = 'Setup')]
    [ValidateNotNullOrEmpty()]
    [string] $CertificateProfileId,

    [Parameter(Mandatory, ParameterSetName = 'Setup')]
    [Parameter(Mandatory, ParameterSetName = 'Download')]
    [Parameter(ParameterSetName = 'Run')]
    [ValidateNotNullOrEmpty()]
    [string] $ExpectedSignerSubject,

    [Parameter(ParameterSetName = 'Setup')]
    [ValidateCount(0, 6)]
    [string[]] $Reviewer,

    [ValidatePattern('^1\.3\.6\.1\.4\.1\.311\.97\.\d+(\.\d+)*$')]
    [string] $ExpectedProfileEku,

    [Parameter(ParameterSetName = 'Setup')]
    [string] $ApplicationClientId,

    [Parameter(ParameterSetName = 'Setup')]
    [ValidateNotNullOrEmpty()]
    [string] $TrustedRootCertificatePath,

    [Parameter(ParameterSetName = 'Setup')]
    [ValidateNotNullOrEmpty()]
    [string[]] $IntermediateCertificatePath,

    [Parameter(ParameterSetName = 'Download')]
    [switch] $Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'signing.ps1')

function Invoke-GitHubSigningApi {
    param(
        [string] $Endpoint,
        [string] $Method = 'GET',
        [string[]] $Field
    )

    $arguments = @(
        'api', $Endpoint, '--hostname', 'github.com', '--method', $Method,
        '-H', 'Accept: application/vnd.github+json', '-H', 'X-GitHub-Api-Version: 2026-03-10'
    )
    foreach ($value in $Field) { $arguments += @('--raw-field', $value) }
    $json = Invoke-NativeTool -Tool gh -ToolArguments $arguments
    if ($json) { ($json -join [Environment]::NewLine) | ConvertFrom-Json }
}

function Assert-GitHubSigningSource {
    param(
        [string] $ProjectRoot,
        [string] $Repository,
        [string] $Ref
    )

    foreach ($relative in @(
        '.github\workflows\artifact-signing.yml', 'build.ps1', 'verify.ps1',
        'signing.ps1', 'dependencies.json'
    )) {
        $path = $relative.Replace('\', '/')
        $file = Invoke-GitHubSigningApi -Endpoint "repos/$Repository/contents/$path`?ref=$([uri]::EscapeDataString($Ref))"
        if ($file.encoding -ne 'base64') { throw "GitHub did not return base64 content for $path." }
        $remote = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($file.content))
        $local = Get-Content -LiteralPath (Join-Path $ProjectRoot $relative) -Raw
        if ($local.Replace("`r`n", "`n") -cne $remote.Replace("`r`n", "`n")) {
            throw "$path differs from $Repository at $Ref. Publish the intended files to the default branch, or check out the run's revision before verifying."
        }
    }
}

function Invoke-GitHubArtifactSigning {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [string] $ProjectRoot,
        [string] $Repository,
        [switch] $Setup,
        [switch] $Run,
        [long] $RunId,
        [string] $CertificateProfileId,
        [string] $ExpectedSignerSubject,
        [string[]] $Reviewer,
        [string] $ExpectedProfileEku,
        [string] $ApplicationClientId,
        [string] $TrustedRootCertificatePath,
        [string[]] $IntermediateCertificatePath,
        [switch] $Force
    )

    $repo = Invoke-GitHubSigningApi -Endpoint "repos/$Repository"
    $Repository = $repo.full_name
    $defaultBranch = $repo.default_branch
    if (-not $defaultBranch) { throw 'The repository must have a default branch.' }
    $endpoint = "repos/$Repository"

    if ($Setup) {
        Assert-GitHubSigningSource -ProjectRoot $ProjectRoot -Repository $Repository -Ref $defaultBranch
        $parameters = @{
            Repository = $Repository
            CertificateProfileId = $CertificateProfileId
            ExpectedSignerSubject = $ExpectedSignerSubject
            WhatIf = [bool] $WhatIfPreference
        }
        foreach ($name in @(
            'ExpectedProfileEku', 'ApplicationClientId', 'TrustedRootCertificatePath',
            'IntermediateCertificatePath', 'Reviewer', 'Confirm'
        )) {
            if ($PSBoundParameters.ContainsKey($name)) { $parameters[$name] = $PSBoundParameters[$name] }
        }
        & (Join-Path $ProjectRoot 'setup-artifact-signing.ps1') @parameters
        return
    }

    if (-not $RunId) {
        Assert-GitHubSigningSource -ProjectRoot $ProjectRoot -Repository $Repository -Ref $defaultBranch
        $workflow = Invoke-GitHubSigningApi -Endpoint "$endpoint/actions/workflows/artifact-signing.yml"
        if ($workflow.state -ne 'active') { throw 'Enable artifact-signing.yml in the repository Actions settings before dispatching.' }
        $enabled = Invoke-GitHubSigningApi -Endpoint "$endpoint/actions/variables/ENABLE_ARTIFACT_SIGNING"
        if ($enabled.value -cne 'true') { throw 'Signing is not enabled. Run this helper with -Setup first.' }
        foreach ($setting in @(
            @{ Name = 'EXPECTED_SIGNER_SUBJECT'; Value = $ExpectedSignerSubject },
            @{ Name = 'EXPECTED_PROFILE_EKU'; Value = $ExpectedProfileEku }
        )) {
            if ($setting.Value) {
                $configured = Invoke-GitHubSigningApi -Endpoint "$endpoint/environments/artifact-signing/variables/$($setting.Name)"
                if ($configured.value -cne $setting.Value) { throw "$($setting.Name) does not match your settings. Review and rerun setup." }
            }
        }
        if (-not $PSCmdlet.ShouldProcess("$Repository at $defaultBranch", 'Dispatch the protected Artifact Signing workflow')) { return }
        # This API version returns the dispatched run ID, avoiding races with other runs.
        $dispatch = Invoke-GitHubSigningApi -Endpoint "$endpoint/actions/workflows/artifact-signing.yml/dispatches" `
            -Method POST -Field @("ref=refs/heads/$defaultBranch")
        if (-not $dispatch -or -not $dispatch.PSObject.Properties['workflow_run_id'] -or $dispatch.workflow_run_id -le 0) {
            throw "Dispatch returned no run ID. Check https://github.com/$Repository/actions before starting another run."
        }
        $url = "https://github.com/$Repository/actions/runs/$($dispatch.workflow_run_id)"
        Write-Host "Workflow dispatched: $url"
        Write-Host 'Wait for completion. Reviewer approval is needed only if configured on the environment.'
        return [pscustomobject] @{
            Repository = $Repository
            RunId = [long] $dispatch.workflow_run_id
            RunUrl = $url
        }
    }

    if (-not $IsWindows) { throw 'Local MSI verification requires Windows.' }
    $runInfo = Invoke-GitHubSigningApi -Endpoint "$endpoint/actions/runs/$RunId"
    $url = "https://github.com/$Repository/actions/runs/$RunId"
    if ($runInfo.path -cne '.github/workflows/artifact-signing.yml' -or
        $runInfo.event -ne 'workflow_dispatch' -or $runInfo.head_branch -cne $defaultBranch -or
        $runInfo.head_repository.full_name -ine $Repository) {
        throw "Run $RunId is not this repository's default-branch Artifact Signing dispatch."
    }
    if ($runInfo.status -ne 'completed' -or $runInfo.conclusion -ne 'success') {
        throw "Run $RunId has status '$($runInfo.status)' and conclusion '$($runInfo.conclusion)'. Wait for a successful completed run: $url"
    }
    $attempt = $runInfo.run_attempt
    $jobs = Invoke-GitHubSigningApi -Endpoint "$endpoint/actions/runs/$RunId/attempts/$attempt/jobs?per_page=100"
    $signJobs = @($jobs.jobs | Where-Object name -EQ 'sign')
    if ($signJobs.Count -ne 1 -or $signJobs[0].conclusion -ne 'success') {
        throw "The signing job did not succeed in run $RunId attempt $attempt. Skipped jobs do not prove signing works."
    }
    Assert-GitHubSigningSource -ProjectRoot $ProjectRoot -Repository $Repository -Ref $runInfo.head_sha
    $dependencies = Get-Content -LiteralPath (Join-Path $ProjectRoot 'dependencies.json') -Raw | ConvertFrom-Json
    $version = $dependencies.powerShell.version
    $zip = Join-Path $ProjectRoot "cache\PowerShell-$version-win-x64.zip"
    if (-not (Test-Path -LiteralPath $zip) -or
        (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash -ne $dependencies.powerShell.sha256) {
        throw "Full payload verification requires the matching hash-verified ZIP from a local build: $zip"
    }
    $name = "PowerShell-$version-win-x64-unofficial.msi"
    $repositoryDirectory = $Repository.Replace('/', '\')
    $directory = Join-Path $ProjectRoot "out\github\$repositoryDirectory\$RunId\attempt-$attempt"
    $destination = Join-Path $directory $name
    if ((Test-Path -LiteralPath $destination) -and -not $Force) {
        throw "Downloaded MSI already exists: $destination. Use -Force to replace it after verification."
    }
    if (-not $PSCmdlet.ShouldProcess($url, "Download, verify, and publish the signed MSI to $destination")) { return }
    $staging = Join-Path $ProjectRoot ".work\github-artifact-signing\$([guid]::NewGuid().ToString('N'))"
    $null = New-Item -ItemType Directory -Path $staging
    try {
        $null = Invoke-NativeTool -Tool gh -ToolArguments @(
            'run', 'download', "$RunId", '--repo', "github.com/$Repository",
            '--name', 'powershell-msi-signed', '--dir', $staging
        )
        $msis = @(Get-ChildItem -LiteralPath $staging -Filter '*.msi' -File -Recurse)
        if ($msis.Count -ne 1 -or $msis[0].Name -cne $name -or $msis[0].DirectoryName -ne $staging) {
            throw "Expected exactly one top-level signed MSI named $name in powershell-msi-signed."
        }
        $msi = $msis[0].FullName
        $arguments = @(
            '-NoProfile', '-File', (Join-Path $ProjectRoot 'verify.ps1'),
            '-MsiPath', $msi, '-ExpectedSignerSubject', $ExpectedSignerSubject
        )
        if ($ExpectedProfileEku) { $arguments += @('-ExpectedProfileEku', $ExpectedProfileEku) }
        $null = Invoke-NativeTool -Tool (Get-Command pwsh -ErrorAction Stop).Source -ToolArguments $arguments
        $hash = (Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash
        $log = Invoke-NativeTool -Tool gh -ToolArguments @(
            'run', 'view', "$RunId", '--repo', "github.com/$Repository", '--attempt', "$attempt", '--log'
        )
        $hashes = [regex]::Matches(($log -join "`n"), 'Signed MSI SHA-256: ([A-Fa-f0-9]{64})')
        if ($hashes.Count -ne 1 -or $hashes[0].Groups[1].Value -ine $hash) {
            throw 'The downloaded MSI SHA-256 does not match exactly one signed-MSI hash in this run attempt log.'
        }
        $null = New-Item -ItemType Directory -Path $directory -Force
        [IO.File]::Move($msi, $destination, [bool] $Force)
        Write-Host "Signed MSI passed signature, timestamp, payload, and run-log hash checks: $destination"
        [pscustomobject] @{
            Repository = $Repository
            RunId = $RunId
            RunAttempt = $attempt
            Commit = $runInfo.head_sha
            RunUrl = $url
            MsiPath = $destination
            SHA256 = $hash
        }
    }
    finally {
        Remove-Item -LiteralPath $staging -Recurse -Force
    }
}

$parameters = @{} + $PSBoundParameters
$parameters.ProjectRoot = $PSScriptRoot
Invoke-GitHubArtifactSigning @parameters
