#Requires -Version 7.2

<#
.SYNOPSIS
Sets up and starts the GitHub Actions Artifact Signing workflow.

.DESCRIPTION
Uses setup-artifact-signing.ps1 for one-time Azure OIDC, GitHub environment, and
profile-scoped permission setup. The signing account and profile must exist.
Run setup with WhatIf first. No local certificates, MSI tools, or payload cache
are needed. Setup does not install certificates on this machine.

Run dispatches artifact-signing.yml on the remote default branch and returns
the exact run ID and URL. The Windows runner retrieves any Private Trust CA
certificates, builds, signs, timestamps, verifies, and uploads the MSI.
This script does not perform those operations locally or push files.
Reviewer approval is optional and disabled by default.

.PARAMETER Repository
GitHub.com repository in OWNER/REPOSITORY form.

.PARAMETER Setup
Configures Azure and GitHub resources using setup-artifact-signing.ps1.
Requires that script's administrator permissions. Does not dispatch a run.

.PARAMETER Run
Starts a new signing run after setup. This is the default mode.
Returns RunId and RunUrl without waiting for completion.

.PARAMETER CertificateProfileId
Full ARM ID of the existing signing certificate profile. Required for setup.
Setup derives the tenant, subscription, and regional endpoint from this resource.

.PARAMETER ExpectedSignerSubject
Exact Windows signer subject. Required for setup.
When supplied during dispatch, must match the protected environment's value.

.PARAMETER Reviewer
Optional GitHub users or ORG/TEAM-SLUG values (up to six). Used during setup.
Omit for solo use with no reviewer approval. Omitting also removes any previously
configured required reviewers. If supplied, another reviewer must approve runs.

.PARAMETER ExpectedProfileEku
Optional durable profile identity OID. Forwarded to setup for runner verification.
When supplied during dispatch, must match the protected environment's value.

.PARAMETER ApplicationClientId
Optional existing Entra application client ID. Used during setup.
Without it, setup creates or reuses the repository's dedicated application.

.EXAMPLE
$setup = @{
    Repository = 'YOUR_ORG/YOUR_REPOSITORY'
    CertificateProfileId = '/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RESOURCE_GROUP>/providers/Microsoft.CodeSigning/codeSigningAccounts/<ACCOUNT>/certificateProfiles/<PROFILE>'
    ExpectedSignerSubject = 'CN=Example Organization, O=Example Organization, C=US'
}
.\github-artifact-signing.ps1 -Setup @setup -WhatIf
.\github-artifact-signing.ps1 -Setup @setup

Previews and configures the Azure and GitHub resources once. Works with
Public Trust or Private Trust without local CA files or another reviewer.

.EXAMPLE
$run = .\github-artifact-signing.ps1 -Repository 'YOUR_ORG/YOUR_REPOSITORY' -Run
$run

Starts a run using the saved GitHub environment settings. Follow RunUrl to see
progress and download the finished MSI from the run's Artifacts section.

.NOTES
Authenticate gh and, for setup, az before running. The workflow and supporting
scripts must already be on the remote default branch. Setup requires the
permissions and GitHub plan documented in README.md.
No client secret, signing account, or certificate profile is created.
Subsequent runs need only GitHub authentication, not a local Azure session.

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

    [Parameter(Mandatory, ParameterSetName = 'Setup')]
    [ValidateNotNullOrEmpty()]
    [string] $CertificateProfileId,

    [Parameter(Mandatory, ParameterSetName = 'Setup')]
    [Parameter(ParameterSetName = 'Run')]
    [ValidateNotNullOrEmpty()]
    [string] $ExpectedSignerSubject,

    [Parameter(ParameterSetName = 'Setup')]
    [ValidateCount(0, 6)]
    [string[]] $Reviewer,

    [ValidatePattern('^1\.3\.6\.1\.4\.1\.311\.97\.\d+(\.\d+)*$')]
    [string] $ExpectedProfileEku,

    [Parameter(ParameterSetName = 'Setup')]
    [string] $ApplicationClientId
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

function Invoke-GitHubArtifactSigning {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [string] $ProjectRoot,
        [string] $Repository,
        [switch] $Setup,
        [switch] $Run,
        [string] $CertificateProfileId,
        [string] $ExpectedSignerSubject,
        [string[]] $Reviewer,
        [string] $ExpectedProfileEku,
        [string] $ApplicationClientId
    )

    if ($Setup) {
        $parameters = @{
            Repository = $Repository
            CertificateProfileId = $CertificateProfileId
            ExpectedSignerSubject = $ExpectedSignerSubject
            WhatIf = [bool] $WhatIfPreference
        }
        foreach ($name in @('ExpectedProfileEku', 'ApplicationClientId', 'Reviewer', 'Confirm')) {
            if ($PSBoundParameters.ContainsKey($name)) { $parameters[$name] = $PSBoundParameters[$name] }
        }
        & (Join-Path $ProjectRoot 'setup-artifact-signing.ps1') @parameters
        return
    }

    $repo = Invoke-GitHubSigningApi -Endpoint "repos/$Repository"
    $Repository = $repo.full_name
    $defaultBranch = $repo.default_branch
    if (-not $defaultBranch) { throw 'The repository must have a default branch.' }
    $endpoint = "repos/$Repository"
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
    if (-not $PSCmdlet.ShouldProcess("$Repository at $defaultBranch", 'Dispatch the Artifact Signing workflow')) { return }
    # This API version returns the dispatched run ID, avoiding races with other runs.
    $dispatch = Invoke-GitHubSigningApi -Endpoint "$endpoint/actions/workflows/artifact-signing.yml/dispatches" `
        -Method POST -Field @("ref=refs/heads/$defaultBranch")
    if (-not $dispatch -or -not $dispatch.PSObject.Properties['workflow_run_id'] -or $dispatch.workflow_run_id -le 0) {
        throw "Dispatch returned no run ID. Check https://github.com/$Repository/actions before starting another run."
    }
    $url = "https://github.com/$Repository/actions/runs/$($dispatch.workflow_run_id)"
    Write-Host "Workflow dispatched: $url"
    Write-Host 'The Windows runner handles certificate trust, building, signing, verification, and artifact upload.'
    [pscustomobject] @{
        Repository = $Repository
        RunId = [long] $dispatch.workflow_run_id
        RunUrl = $url
    }
}

$parameters = @{} + $PSBoundParameters
$parameters.ProjectRoot = $PSScriptRoot
Invoke-GitHubArtifactSigning @parameters
