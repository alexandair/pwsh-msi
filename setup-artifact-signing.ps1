#Requires -Version 7.2

<#
.SYNOPSIS
Configures the protected GitHub Actions Artifact Signing workflow using OIDC.

.DESCRIPTION
Uses Azure CLI, GitHub CLI, and Microsoft Graph to configure an existing
repository and Artifact Signing certificate profile. Disables signing, sets
default-branch-only deployment policies, and preserves an existing environment
wait timer. Reviewer approval is optional; when configured, self-approval is
prevented.

Creates or reuses an Entra application and service principal, configures the
repository's environment-scoped federated credential, assigns the signer role
at the exact certificate profile, and writes workflow variables. Enables
signing only after reading back and verifying the configuration.

On configuration failure, attempts to disable signing and reports any failure
to do so. Created identities and permissions remain available for a rerun.
Does not log in, create a signing account/profile, enroll an organization,
complete identity validation, create client secrets, or approve workflow jobs.

.PARAMETER Repository
GitHub.com repository or fork in OWNER/REPOSITORY form. Requires administrator
access and artifact-signing.yml already on the repository's default branch.

.PARAMETER CertificateProfileId
Full ARM resource ID of an existing PublicTrust or PrivateTrust certificate
profile. Determines the subscription, tenant, account, and regional endpoint.

.PARAMETER ExpectedSignerSubject
Complete, exact Windows SignerCertificate.Subject for the selected profile.

.PARAMETER Reviewer
Optional GitHub usernames or ORG/TEAM-SLUG values with repository read access
(up to six). Teams must belong to the repository's organization. Replaces the
dedicated artifact-signing environment's reviewer list. Omit to require no
reviewer approval, including when reconfiguring an existing environment.

.PARAMETER ExpectedProfileEku
Optional durable Artifact Signing profile identity OID beginning with
1.3.6.1.4.1.311.97. Omitting it clears the optional workflow variable.

.PARAMETER ApplicationClientId
Existing Entra application's client ID in the profile's subscription tenant.
Otherwise creates or reuses an application named from the GitHub repository ID.
Unrelated credentials and existing permissions are not removed.

.PARAMETER Dispatch
Starts artifact-signing.yml on the default branch after verified setup.
A designated reviewer must approve it only when Reviewer is supplied.
A dispatch failure does not undo the successfully verified configuration.

.EXAMPLE
$setup = @{
    Repository = 'YOUR_ORG/YOUR_REPOSITORY'
    CertificateProfileId = '/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RESOURCE_GROUP>/providers/Microsoft.CodeSigning/codeSigningAccounts/<ACCOUNT>/certificateProfiles/<PROFILE>'
    ExpectedSignerSubject = 'CN=Example Organization, O=Example Organization, C=US'
}
.\setup-artifact-signing.ps1 @setup -WhatIf

Replace the placeholders with your organization's values. Performs read-only
prerequisite checks and previews the operation without changing cloud settings.

.EXAMPLE
.\setup-artifact-signing.ps1 @setup

Uses the setup hashtable from the previous example and asks for confirmation
before configuring the signing environment, identity, permissions, and variables.
No reviewer approval is required. Add -Reviewer when an approval gate is wanted.

.EXAMPLE
.\setup-artifact-signing.ps1 @setup -ApplicationClientId '11111111-1111-1111-1111-111111111111' -ExpectedProfileEku '1.3.6.1.4.1.311.97.123.456' -Dispatch

Uses an existing application and a known profile EKU, then starts the workflow.
Replace the client ID and example OID with your actual values.

.NOTES
No local CA files, certificate trust, signing tools, or payload cache are needed.
The Windows runner retrieves Private Trust CA certificates from the selected
profile after OIDC login and performs all building, signing, and verification.
Authenticate az and gh before running. Requires permission to manage repository
environments, variables, OIDC settings, and reviewer metadata; read Azure
signing resources; manage Entra applications, service principals, and federated
credentials; and assign the profile signer role.
Supports GitHub.com, Azure public cloud, and default GitHub OIDC subjects only.
Unsupported environment protections cause failure, not weakened protection.
If reviewers are configured, private repositories generally require GitHub
Enterprise for required-reviewer protection.
Use -Confirm:$false only after reviewing the configuration. Do not run setup
concurrently or while signing jobs are running. Azure permission propagation
may require waiting before a rerun. Live setup and signing still need acceptance
testing with an eligible organization's account.

.LINK
.\README.md
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')]
    [string] $Repository,

    [Parameter(Mandatory)]
    [ValidatePattern('(?i)^/subscriptions/[a-f0-9-]{36}/resourceGroups/[^/]+/providers/Microsoft\.CodeSigning/codeSigningAccounts/[a-z0-9-]+/certificateProfiles/[a-z0-9-]+$')]
    [string] $CertificateProfileId,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $ExpectedSignerSubject,

    [ValidateCount(0, 6)]
    [ValidatePattern('^(?:[A-Za-z0-9-]+/)?[A-Za-z0-9-]+$')]
    [string[]] $Reviewer = @(),

    [ValidatePattern('^1\.3\.6\.1\.4\.1\.311\.97\.\d+(\.\d+)*$')]
    [string] $ExpectedProfileEku,

    [ValidatePattern('^[a-fA-F0-9-]{36}$')]
    [string] $ApplicationClientId,

    [switch] $Dispatch
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'signing.ps1')

function Invoke-SetupGitHub {
    param(
        [Parameter(Mandatory)] [string] $Endpoint,
        [string] $Method = 'GET',
        [hashtable] $Body,
        [switch] $Paginate
    )

    $arguments = @('api', $Endpoint, '--hostname', 'github.com', '--method', $Method,
        '-H', 'Accept: application/vnd.github+json', '-H', 'X-GitHub-Api-Version: 2022-11-28')
    $file = $null
    try {
        if ($null -ne $Body) {
            $file = [IO.Path]::GetTempFileName()
            $Body | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $file -Encoding utf8
            $arguments += @('--input', $file)
        }
        if ($Paginate) { $arguments += @('--paginate', '--slurp') }
        $json = Invoke-NativeTool -Tool gh -ToolArguments $arguments
        if ($json) { ($json -join [Environment]::NewLine) | ConvertFrom-Json }
    }
    finally {
        if ($file) { Remove-Item -LiteralPath $file -Force }
    }
}

function Invoke-SetupAzure {
    param(
        [Parameter(Mandatory)] [string[]] $Arguments,
        [Parameter(Mandatory)] [string] $SubscriptionId
    )

    $json = Invoke-NativeTool -Tool az -ToolArguments (
        $Arguments + @('--subscription', $SubscriptionId, '--output', 'json', '--only-show-errors')
    )
    if ($json) { ($json -join [Environment]::NewLine) | ConvertFrom-Json }
}

function Invoke-SetupGraph {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $AccessToken,
        [string] $Method = 'GET',
        [hashtable] $Body
    )

    $url = "https://graph.microsoft.com/v1.0/$Path"
    do {
        if (([uri] $url).Host -ne 'graph.microsoft.com' -or ([uri] $url).Scheme -ne 'https') {
            throw 'Microsoft Graph returned an unsupported continuation URL.'
        }
        $request = @{
            Uri = $url
            Method = $Method
            Headers = @{ Authorization = "Bearer $AccessToken" }
            ContentType = 'application/json'
        }
        if ($null -ne $Body) { $request.Body = $Body | ConvertTo-Json -Depth 10 }
        $result = Invoke-RestMethod @request
        $url = $null
        if ($null -ne $result) {
            if ($result.PSObject.Properties['value']) {
                $result.value
                if ($result.PSObject.Properties['@odata.nextLink']) { $url = $result.'@odata.nextLink' }
            }
            else { $result }
        }
    }
    while ($url)
}

function Set-SetupVariable {
    param(
        [Parameter(Mandatory)] [string] $Endpoint,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Value
    )

    $variables = @(Invoke-SetupGitHub -Endpoint "$Endpoint`?per_page=30" -Paginate |
        ForEach-Object { $_.variables })
    if ($variables | Where-Object name -EQ $Name) {
        $null = Invoke-SetupGitHub -Endpoint "$Endpoint/$Name" -Method PATCH -Body @{ name = $Name; value = $Value }
    }
    else {
        $null = Invoke-SetupGitHub -Endpoint $Endpoint -Method POST -Body @{ name = $Name; value = $Value }
    }
}

function Assert-SetupEnvironment {
    param(
        [Parameter(Mandatory)] [string] $Endpoint,
        [Parameter(Mandatory)] [string] $DefaultBranch,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Reviewers,
        [int] $WaitTimer = 0
    )

    $environment = Invoke-SetupGitHub -Endpoint $Endpoint
    $rules = @($environment.protection_rules | Where-Object type -EQ 'required_reviewers')
    if ($Reviewers.Count -eq 0) {
        if ($rules.Count -ne 0) {
            throw 'GitHub did not remove required-reviewer approval as requested; signing must remain disabled.'
        }
    }
    else {
        if ($rules.Count -ne 1 -or -not $rules[0].prevent_self_review) {
            throw 'GitHub did not enforce required reviewers and prevention of self-approval. Check your GitHub plan; signing must remain disabled.'
        }
        $expected = @($Reviewers | ForEach-Object { "$($_.type):$($_.id)" } | Sort-Object -Unique)
        $actual = @($rules[0].reviewers | ForEach-Object { "$($_.type):$($_.reviewer.id)" } | Sort-Object -Unique)
        if ($expected.Count -ne $actual.Count -or (Compare-Object $expected $actual)) {
            throw "GitHub environment reviewers do not match the requested reviewers. Expected: $($expected -join ', '); actual: $($actual -join ', ')."
        }
    }
    if ($WaitTimer -gt 0) {
        $timers = @($environment.protection_rules | Where-Object type -EQ 'wait_timer')
        if ($timers.Count -ne 1 -or $timers[0].wait_timer -ne $WaitTimer) {
            throw 'GitHub did not preserve the existing environment wait timer.'
        }
    }
    if (-not $environment.deployment_branch_policy -or -not $environment.deployment_branch_policy.custom_branch_policies -or
        $environment.deployment_branch_policy.protected_branches) {
        throw 'GitHub did not enforce selected deployment branches.'
    }
    $policies = @(Invoke-SetupGitHub -Endpoint "$Endpoint/deployment-branch-policies?per_page=100" -Paginate |
        ForEach-Object { $_.branch_policies })
    if ($policies.Count -ne 1 -or $policies[0].name -cne $DefaultBranch -or $policies[0].type -ne 'branch') {
        throw 'The signing environment must allow only the default branch, with no tag policies.'
    }
}

function Invoke-ArtifactSigningSetup {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [string] $Repository,
        [string] $CertificateProfileId,
        [string] $ExpectedSignerSubject,
        [string[]] $Reviewer = @(),
        [string] $ExpectedProfileEku,
        [string] $ApplicationClientId,
        [switch] $Dispatch
    )

    Get-Command az, gh -ErrorAction Stop | Out-Null
    if ([string]::IsNullOrWhiteSpace($ExpectedSignerSubject)) {
        throw 'ExpectedSignerSubject must be the complete certificate subject.'
    }
    $subscriptionId = ([guid]::Parse($CertificateProfileId.Split('/')[2])).ToString()
    $subscription = Invoke-SetupAzure -SubscriptionId $subscriptionId -Arguments @('account', 'show')
    if ($subscription.environmentName -ne 'AzureCloud') { throw 'This setup supports Azure public cloud only.' }
    $repo = Invoke-SetupGitHub -Endpoint "repos/$Repository"
    if (-not $repo.permissions.admin) { throw 'GitHub repository administrator access is required.' }
    $Repository = $repo.full_name
    $repoEndpoint = "repos/$Repository"
    $environmentEndpoint = "$repoEndpoint/environments/artifact-signing"
    $flagEndpoint = "$repoEndpoint/actions/variables"
    $defaultBranch = $repo.default_branch
    if ([string]::IsNullOrWhiteSpace($defaultBranch)) { throw 'The repository must have a default branch.' }
    $null = Invoke-SetupGitHub -Endpoint "$repoEndpoint/contents/.github/workflows/artifact-signing.yml?ref=$([uri]::EscapeDataString($defaultBranch))"
    $oidc = Invoke-SetupGitHub -Endpoint "$repoEndpoint/actions/oidc/customization/sub"
    if (-not $oidc.use_default) { throw 'Custom GitHub OIDC subject templates are not supported by this setup script.' }

    $certificateProfile = Invoke-SetupAzure -SubscriptionId $subscriptionId -Arguments @(
        'resource', 'show', '--ids', $CertificateProfileId, '--api-version', '2025-10-13'
    )
    if ($certificateProfile.id -ne $CertificateProfileId -or $certificateProfile.properties.profileType -notin 'PublicTrust', 'PrivateTrust') {
        throw 'Select an existing PublicTrust or PrivateTrust code-signing certificate profile.'
    }
    $accountId = $CertificateProfileId.Substring(0, $CertificateProfileId.LastIndexOf('/certificateProfiles/', [StringComparison]::OrdinalIgnoreCase))
    $account = Invoke-SetupAzure -SubscriptionId $subscriptionId -Arguments @(
        'resource', 'show', '--ids', $accountId, '--api-version', '2025-10-13'
    )
    $endpoint = [uri] $account.properties.accountUri
    if ($endpoint.Scheme -ne 'https' -or $endpoint.Host -notmatch '^[a-z0-9-]+\.codesigning\.azure\.net$' -or
        $endpoint.AbsolutePath -ne '/' -or $endpoint.UserInfo -or $endpoint.Query -or $endpoint.Fragment -or -not $endpoint.IsDefaultPort) {
        throw 'The signing account did not return a supported regional HTTPS endpoint.'
    }

    $reviewers = @(
        foreach ($name in $Reviewer | Select-Object -Unique) {
            if ($name.Contains('/')) {
                $organization, $slug = $name.Split('/')
                if ($organization -ne $Repository.Split('/')[0]) { throw "Reviewer team $name must belong to the repository's organization." }
                $team = Invoke-SetupGitHub -Endpoint "orgs/$organization/teams/$slug"
                $null = Invoke-SetupGitHub -Endpoint "orgs/$organization/teams/$slug/repos/$Repository"
                @{ type = 'Team'; id = $team.id }
            }
            else {
                $user = Invoke-SetupGitHub -Endpoint "users/$name"
                $access = Invoke-SetupGitHub -Endpoint "$repoEndpoint/collaborators/$name/permission"
                if ($access.permission -notin 'read', 'pull', 'triage', 'write', 'push', 'maintain', 'admin') {
                    throw "Reviewer $name must have at least read access to the repository."
                }
                @{ type = 'User'; id = $user.id }
            }
        }
    )
    $reviewers = @($reviewers | Sort-Object -Property type, id -Unique)
    $approval = if ($reviewers.Count) { 'require reviewer approval' } else { 'remove reviewer approval' }
    if (-not $PSCmdlet.ShouldProcess(
        "$Repository and certificate profile $CertificateProfileId",
        "Disable signing, $approval, replace branch policies, configure Entra federation and profile RBAC, verify configuration, then enable signing"
    )) { return }

    try {
        Set-SetupVariable -Endpoint $flagEndpoint -Name ENABLE_ARTIFACT_SIGNING -Value false
        if ((Invoke-SetupGitHub -Endpoint "$flagEndpoint/ENABLE_ARTIFACT_SIGNING").value -cne 'false') {
            throw 'Could not confirm that signing is disabled.'
        }
        $environmentBody = @{
            prevent_self_review = ($reviewers.Count -gt 0)
            reviewers = $reviewers
            deployment_branch_policy = @{ protected_branches = $false; custom_branch_policies = $true }
        }
        $existing = @(Invoke-SetupGitHub -Endpoint "$repoEndpoint/environments?per_page=100" -Paginate |
            ForEach-Object { $_.environments } | Where-Object name -EQ 'artifact-signing')
        if ($existing.Count -gt 1) { throw 'Multiple signing environments matched the requested name.' }
        $waitTimer = 0
        if ($existing.Count -eq 1) {
            $timers = @($existing[0].protection_rules | Where-Object type -EQ 'wait_timer')
            if ($timers.Count -gt 1) { throw 'Multiple signing environment wait timers were returned.' }
            if ($timers.Count -eq 1) {
                $waitTimer = $timers[0].wait_timer
                $environmentBody.wait_timer = $waitTimer
            }
        }
        $null = Invoke-SetupGitHub -Endpoint $environmentEndpoint -Method PUT -Body $environmentBody
        $policies = @(Invoke-SetupGitHub -Endpoint "$environmentEndpoint/deployment-branch-policies?per_page=100" -Paginate |
            ForEach-Object { $_.branch_policies })
        foreach ($policy in $policies) {
            if ($policy.name -cne $defaultBranch -or $policy.type -ne 'branch') {
                $null = Invoke-SetupGitHub -Endpoint "$environmentEndpoint/deployment-branch-policies/$($policy.id)" -Method DELETE
            }
        }
        if (-not ($policies | Where-Object { $_.name -ceq $defaultBranch -and $_.type -eq 'branch' })) {
            $null = Invoke-SetupGitHub -Endpoint "$environmentEndpoint/deployment-branch-policies" -Method POST -Body @{
                name = $defaultBranch; type = 'branch'
            }
        }
        Assert-SetupEnvironment -Endpoint $environmentEndpoint -DefaultBranch $defaultBranch -Reviewers $reviewers -WaitTimer $waitTimer

        $tokenJson = Invoke-NativeTool -Tool az -ToolArguments @(
            'account', 'get-access-token', '--subscription', $subscriptionId, '--resource-type', 'ms-graph',
            '--output', 'json', '--only-show-errors'
        )
        $graphToken = (($tokenJson -join [Environment]::NewLine) | ConvertFrom-Json).accessToken
        if ($ApplicationClientId) {
            $clientId = ([guid]::Parse($ApplicationClientId)).ToString()
            $apps = @(Invoke-SetupGraph -Path "applications?`$filter=$([uri]::EscapeDataString("appId eq '$clientId'"))" -AccessToken $graphToken)
            if ($apps.Count -ne 1) { throw 'The requested application was not uniquely found in the signing subscription tenant.' }
            $app = $apps[0]
        }
        else {
            $appName = "pwsh-msi-artifact-signing-$($repo.id)"
            $apps = @(Invoke-SetupGraph -Path "applications?`$filter=$([uri]::EscapeDataString("displayName eq '$appName'"))" -AccessToken $graphToken)
            if ($apps.Count -gt 1) { throw 'Multiple matching Entra applications exist. Specify -ApplicationClientId explicitly.' }
            if ($apps.Count -eq 1) { $app = $apps[0] }
            else {
                $app = Invoke-SetupGraph -Path applications -Method POST -AccessToken $graphToken -Body @{
                    displayName = $appName; signInAudience = 'AzureADMyOrg'
                }
                Write-Host "Created Entra application $($app.appId); retained if later setup fails."
            }
        }
        $principals = @(Invoke-SetupGraph -Path "servicePrincipals?`$filter=$([uri]::EscapeDataString("appId eq '$($app.appId)'"))" -AccessToken $graphToken)
        if ($principals.Count -gt 1) { throw 'Multiple service principals matched the application.' }
        if ($principals.Count -eq 1) { $principal = $principals[0] }
        else { $principal = Invoke-SetupGraph -Path servicePrincipals -Method POST -AccessToken $graphToken -Body @{ appId = $app.appId } }

        $credentialName = "github-artifact-signing-$($repo.id)"
        $federation = @{
            name = $credentialName
            issuer = 'https://token.actions.githubusercontent.com'
            subject = "repo:${Repository}:environment:artifact-signing"
            audiences = @('api://AzureADTokenExchange')
        }
        $credentialPath = "applications/$($app.id)/federatedIdentityCredentials"
        $credentials = @(Invoke-SetupGraph -Path $credentialPath -AccessToken $graphToken)
        $credential = @($credentials | Where-Object name -EQ $credentialName)
        if ($credential.Count -gt 1) { throw 'Multiple matching federated credentials exist.' }
        if ($credential.Count -eq 0) {
            $null = Invoke-SetupGraph -Path $credentialPath -Method POST -AccessToken $graphToken -Body $federation
        }
        elseif ($credential[0].issuer -cne $federation.issuer -or $credential[0].subject -cne $federation.subject -or
            @($credential[0].audiences).Count -ne 1 -or $credential[0].audiences[0] -cne $federation.audiences[0]) {
            $update = $federation.Clone()
            $update.Remove('name')
            $null = Invoke-SetupGraph -Path "$credentialPath/$($credential[0].id)" -Method PATCH -AccessToken $graphToken -Body $update
        }
        $credential = @(Invoke-SetupGraph -Path $credentialPath -AccessToken $graphToken |
            Where-Object name -EQ $credentialName)
        if ($credential.Count -ne 1 -or $credential[0].issuer -cne $federation.issuer -or
            $credential[0].subject -cne $federation.subject -or @($credential[0].audiences).Count -ne 1 -or
            $credential[0].audiences[0] -cne $federation.audiences[0]) {
            throw 'Entra federated credential verification failed.'
        }

        $roles = @(Invoke-SetupAzure -SubscriptionId $subscriptionId -Arguments @(
            'role', 'definition', 'list', '--name', 'Artifact Signing Certificate Profile Signer', '--scope', $CertificateProfileId
        ) | Where-Object { $_.roleType -eq 'BuiltInRole' -and $_.roleName -eq 'Artifact Signing Certificate Profile Signer' })
        if ($roles.Count -ne 1) { throw 'Could not resolve the built-in Artifact Signing Certificate Profile Signer role.' }
        $roleId = $roles[0].id
        $assignments = @(Invoke-SetupAzure -SubscriptionId $subscriptionId -Arguments @('role', 'assignment', 'list', '--scope', $CertificateProfileId))
        $matching = @($assignments | Where-Object {
            $_.principalId -eq $principal.id -and $_.scope -eq $CertificateProfileId -and $_.roleDefinitionId -eq $roleId
        })
        if ($matching.Count -eq 0) {
            $null = Invoke-SetupAzure -SubscriptionId $subscriptionId -Arguments @(
                'role', 'assignment', 'create', '--assignee-object-id', $principal.id,
                '--assignee-principal-type', 'ServicePrincipal', '--role', $roleId, '--scope', $CertificateProfileId
            )
        }
        $assignments = @(Invoke-SetupAzure -SubscriptionId $subscriptionId -Arguments @('role', 'assignment', 'list', '--scope', $CertificateProfileId))
        if (-not ($assignments | Where-Object {
            $_.principalId -eq $principal.id -and $_.scope -eq $CertificateProfileId -and $_.roleDefinitionId -eq $roleId
        })) { throw 'Profile-scoped role assignment verification failed. Allow Azure propagation and rerun setup.' }

        $variables = @{
            AZURE_CLIENT_ID = [string] $app.appId
            AZURE_TENANT_ID = [string] $subscription.tenantId
            AZURE_SUBSCRIPTION_ID = $subscriptionId
            ARTIFACT_SIGNING_ENDPOINT = $endpoint.AbsoluteUri
            ARTIFACT_SIGNING_ACCOUNT_NAME = $accountId.Split('/')[-1]
            ARTIFACT_SIGNING_CERTIFICATE_PROFILE_NAME = $CertificateProfileId.Split('/')[-1]
            ARTIFACT_SIGNING_PROFILE_TYPE = [string] $certificateProfile.properties.profileType
            EXPECTED_SIGNER_SUBJECT = $ExpectedSignerSubject
            EXPECTED_PROFILE_EKU = $ExpectedProfileEku
        }
        foreach ($name in $variables.Keys) {
            Set-SetupVariable -Endpoint "$environmentEndpoint/variables" -Name $name -Value $variables[$name]
        }
        $actual = @(Invoke-SetupGitHub -Endpoint "$environmentEndpoint/variables?per_page=30" -Paginate | ForEach-Object { $_.variables })
        foreach ($name in $variables.Keys) {
            $value = @($actual | Where-Object name -EQ $name)
            if ($value.Count -ne 1 -or $value[0].value -cne $variables[$name]) { throw "GitHub variable verification failed: $name." }
        }
        Assert-SetupEnvironment -Endpoint $environmentEndpoint -DefaultBranch $defaultBranch -Reviewers $reviewers -WaitTimer $waitTimer
        Set-SetupVariable -Endpoint $flagEndpoint -Name ENABLE_ARTIFACT_SIGNING -Value true
        if ((Invoke-SetupGitHub -Endpoint "$flagEndpoint/ENABLE_ARTIFACT_SIGNING").value -cne 'true') {
            throw 'Could not verify the final signing enable flag.'
        }
    }
    catch {
        $failure = $_.Exception
        try {
            Set-SetupVariable -Endpoint $flagEndpoint -Name ENABLE_ARTIFACT_SIGNING -Value false
            if ((Invoke-SetupGitHub -Endpoint "$flagEndpoint/ENABLE_ARTIFACT_SIGNING").value -cne 'false') {
                throw 'The signing enable flag could not be verified as false.'
            }
        }
        catch {
            throw [InvalidOperationException]::new(
                "Setup failed: $($failure.Message) Disabling signing also failed: $($_.Exception.Message) Manually set ENABLE_ARTIFACT_SIGNING=false immediately.", $failure
            )
        }
        throw [InvalidOperationException]::new(
            "Setup failed; signing is disabled. Created identities and permissions were retained so setup can be rerun. $($failure.Message)", $failure
        )
    }

    Write-Host "Configured $Repository for Artifact Signing using application $($app.appId)."
    if ($Dispatch) {
        Invoke-NativeTool -Tool gh -ToolArguments @('workflow', 'run', 'artifact-signing.yml', '--repo', "github.com/$Repository", '--ref', $defaultBranch)
    }
    Write-Host "Run the signing workflow at https://github.com/$Repository/actions/workflows/artifact-signing.yml"
    if ($reviewers.Count) { Write-Host 'A designated reviewer other than the initiator must approve the signing environment.' }
    Write-Host 'Live signing acceptance is still required; setup does not prove that signing succeeds.'
}

Invoke-ArtifactSigningSetup @PSBoundParameters
