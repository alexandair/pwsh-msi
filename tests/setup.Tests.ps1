#Requires -Version 7.2
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
.SYNOPSIS
Runs mocked Artifact Signing setup and GitHub workflow tests through Pester.

.DESCRIPTION
Loads setup functions without executing the setup script. Tests environment
protections, identity and federation reuse, profile-scoped RBAC, workflow
variables, WhatIf, dispatch, failure handling, and API request safety. Also tests
the GitHub workflow helper's setup forwarding, dispatch, and runner CA setup.

GitHub, Microsoft Graph, Azure, and native CLI calls are mocked. Does not need
cloud credentials or change repository settings, identities, or Azure resources.

.EXAMPLE
Invoke-Pester -Path .\tests\setup.Tests.ps1

Tests setup automation without running live configuration.

.EXAMPLE
$result = Invoke-Pester -Path .\tests\setup.Tests.ps1 -Output Detailed -PassThru
if ($result.Result -ne 'Passed') { throw 'Setup tests failed.' }

Shows individual test results and fails the calling script if tests fail.

.NOTES
Requires Pester 5. Mocked tests do not prove that an organization's live
permissions, GitHub plan, or Artifact Signing enrollment are sufficient.

.LINK
..\README.md
#>

BeforeAll {
    . (Join-Path $PSScriptRoot '..\signing.ps1')
    foreach ($scriptName in @('setup-artifact-signing.ps1', 'github-artifact-signing.ps1')) {
        $tokens = $null
        $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $PSScriptRoot "..\$scriptName"), [ref] $tokens, [ref] $errors
        )
        if ($errors.Count) { throw ($errors.Message -join [Environment]::NewLine) }
        foreach ($function in $ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst]
        }, $false)) {
            . ([scriptblock]::Create($function.Extent.Text))
        }
    }

}

Describe 'Artifact Signing setup orchestration' {
    BeforeEach {
        $setup = @{
            Repository = 'exampleorg/msi'
            CertificateProfileId = '/subscriptions/66666666-6666-6666-6666-666666666666/resourceGroups/signing/providers/Microsoft.CodeSigning/codeSigningAccounts/account-name/certificateProfiles/profile-name'
            ExpectedSignerSubject = 'CN=Example Organization, O=Example Organization'
            Reviewer = @('reviewer-a')
            Confirm = $false
        }
        $script:repoVariables = @{}
        $script:environmentVariables = @{}
        $script:policies = @(
            [pscustomobject] @{ id = 99; name = '*'; type = 'branch' }
            [pscustomobject] @{ id = 100; name = 'main'; type = 'tag' }
        )
        $script:reviewers = @()
        $script:apps = @()
        $script:principals = @()
        $script:credentials = @()
        $script:assignments = @()
        $script:roleId = '/subscriptions/66666666-6666-6666-6666-666666666666/providers/Microsoft.Authorization/roleDefinitions/77777777-7777-7777-7777-777777777777'
        $script:protectionsSupported = $true
        $script:roleAssignmentAllowed = $true
        $script:failFinalEnableRead = $false
        $script:customSubject = $false
        $script:subjectPrefix = 'repo:ExampleOrg/msi'
        $script:existingEnvironments = @()
        $script:configuredWaitTimer = 0
        $script:ignoreWaitTimer = $false
        $script:ignoreReviewerChanges = $false
        $script:profileType = 'PublicTrust'
        Mock Get-Command {}
        Mock Invoke-NativeTool {
            if ($Tool -eq 'az' -and $ToolArguments[1] -eq 'get-access-token') {
                return '{"accessToken":"test-only-placeholder"}'
            }
            if ($Tool -eq 'gh' -and $ToolArguments[0] -eq 'workflow') { return }
            throw "Unexpected native CLI call: $Tool"
        }
        Mock Invoke-SetupGitHub {
            $methodValue = if ($Method) { $Method } else { 'GET' }
            if ($Endpoint -ieq 'repos/exampleorg/msi') {
                return [pscustomobject] @{
                    id = 123
                    full_name = 'ExampleOrg/msi'
                    default_branch = 'main'
                    permissions = [pscustomobject] @{ admin = $true }
                }
            }
            if ($Endpoint -like '*contents/.github/workflows/artifact-signing.yml*') { return @{} }
            if ($Endpoint -like '*oidc/customization/sub') {
                return [pscustomobject] @{
                    use_default = -not $script:customSubject
                    sub_claim_prefix = $script:subjectPrefix
                }
            }
            if ($Endpoint -eq 'repos/ExampleOrg/msi/environments?per_page=100') {
                return [pscustomobject] @{ environments = $script:existingEnvironments }
            }
            if ($Endpoint -eq 'users/reviewer-a') { return [pscustomobject] @{ id = 5 } }
            if ($Endpoint -like '*collaborators/reviewer-a/permission') { return [pscustomobject] @{ permission = 'read' } }
            if ($Endpoint -eq 'orgs/ExampleOrg/teams/signers') { return [pscustomobject] @{ id = 15 } }
            if ($Endpoint -eq 'orgs/ExampleOrg/teams/signers/repos/ExampleOrg/msi') { return @{} }
            if ($Endpoint -match '/variables(?:/([^?]+))?(?:\?.*)?$') {
                $name = $Matches[1]
                $variables = if ($Endpoint -like '*actions/variables*') { $script:repoVariables } else { $script:environmentVariables }
                if ($methodValue -in 'POST', 'PATCH') {
                    if ([string]::IsNullOrEmpty($Body.value)) { throw 'Variable value cannot be empty.' }
                    $variables[$Body.name] = $Body.value
                    return
                }
                if ($methodValue -eq 'DELETE') {
                    $variables.Remove($name)
                    return
                }
                if ($name) {
                    if ($script:failFinalEnableRead -and $variables[$name] -eq 'true') { throw 'Enable read-back failed' }
                    return [pscustomobject] @{ name = $name; value = $variables[$name] }
                }
                return [pscustomobject] @{
                    variables = @($variables.GetEnumerator() | ForEach-Object { [pscustomobject] @{ name = $_.Key; value = $_.Value } })
                }
            }
            if ($Endpoint -like '*deployment-branch-policies*') {
                if ($methodValue -eq 'DELETE') {
                    $id = [int] $Endpoint.Split('/')[-1]
                    $script:policies = @($script:policies | Where-Object id -NE $id)
                    return
                }
                if ($methodValue -eq 'POST') {
                    $script:policies += [pscustomobject] @{ id = 101; name = $Body.name; type = $Body.type }
                    return
                }
                return [pscustomobject] @{ branch_policies = $script:policies }
            }
            if ($Endpoint -like '*environments/artifact-signing') {
                if ($methodValue -eq 'PUT') {
                    if (-not $script:ignoreReviewerChanges) { $script:reviewers = $Body.reviewers }
                    if ($Body.ContainsKey('wait_timer') -and -not $script:ignoreWaitTimer) {
                        $script:configuredWaitTimer = $Body.wait_timer
                    }
                    return
                }
                return [pscustomobject] @{
                    protection_rules = @(
                        if ($script:reviewers.Count) {
                            [pscustomobject] @{
                                type = 'required_reviewers'
                                prevent_self_review = $script:protectionsSupported
                                reviewers = @($script:reviewers | ForEach-Object {
                                    [pscustomobject] @{ type = $_.type; reviewer = [pscustomobject] @{ id = $_.id } }
                                })
                            }
                        }
                        if ($script:configuredWaitTimer -gt 0) {
                            [pscustomobject] @{ type = 'wait_timer'; wait_timer = $script:configuredWaitTimer }
                        }
                    )
                    deployment_branch_policy = [pscustomobject] @{ protected_branches = $false; custom_branch_policies = $true }
                }
            }
            throw "Unexpected GitHub API request: $methodValue $Endpoint"
        }
        Mock Invoke-SetupGraph {
            $methodValue = if ($Method) { $Method } else { 'GET' }
            if ($Path.StartsWith('applications?')) { return $script:apps }
            if ($Path -eq 'applications' -and $methodValue -eq 'POST') {
                $script:apps = @([pscustomobject] @{
                    id = '11111111-1111-1111-1111-111111111111'
                    appId = '22222222-2222-2222-2222-222222222222'
                })
                return $script:apps
            }
            if ($Path.StartsWith('servicePrincipals?')) { return $script:principals }
            if ($Path -eq 'servicePrincipals' -and $methodValue -eq 'POST') {
                $script:principals = @([pscustomobject] @{ id = '33333333-3333-3333-3333-333333333333' })
                return $script:principals
            }
            if ($Path -like '*federatedIdentityCredentials*') {
                if ($methodValue -in 'POST', 'PATCH') {
                    $script:credentials = @([pscustomobject] @{
                        id = '44444444-4444-4444-4444-444444444444'
                        name = 'github-artifact-signing-123'
                        issuer = $Body.issuer
                        subject = $Body.subject
                        audiences = $Body.audiences
                    })
                    return $script:credentials
                }
                return $script:credentials
            }
            throw "Unexpected Graph API request: $methodValue $Path"
        }
        Mock Invoke-SetupAzure {
            if ($Arguments[0] -eq 'account') {
                return [pscustomobject] @{ tenantId = '55555555-5555-5555-5555-555555555555'; environmentName = 'AzureCloud' }
            }
            if ($Arguments[0] -eq 'resource') {
                $id = $Arguments[3]
                if ($id -like '*certificateProfiles*') {
                    return [pscustomobject] @{ id = $id; properties = [pscustomobject] @{ profileType = $script:profileType } }
                }
                return [pscustomobject] @{ properties = [pscustomobject] @{ accountUri = 'https://neu.codesigning.azure.net/' } }
            }
            if ($Arguments[1] -eq 'definition') {
                return [pscustomobject] @{
                    id = $script:roleId
                    roleType = 'BuiltInRole'
                    roleName = 'Artifact Signing Certificate Profile Signer'
                }
            }
            if ($Arguments[2] -eq 'create') {
                if (-not $script:roleAssignmentAllowed) { throw 'Role assignment permission denied' }
                $script:assignments = @([pscustomobject] @{
                    principalId = $Arguments[4]
                    scope = $Arguments[10]
                    roleDefinitionId = $Arguments[8]
                })
                return $script:assignments
            }
            return $script:assignments
        }
    }

    It 'configures a protected default-branch-only environment and enables only after verified setup' {
        Invoke-ArtifactSigningSetup @setup

        $script:repoVariables.ENABLE_ARTIFACT_SIGNING | Should -BeExactly 'true'
        $script:policies.Count | Should -Be 1
        $script:policies[0].type | Should -Be 'branch'
        $script:policies[0].name | Should -Be 'main'
        $script:credentials[0].subject | Should -BeExactly 'repo:ExampleOrg/msi:environment:artifact-signing'
        $script:environmentVariables.EXPECTED_SIGNER_SUBJECT | Should -Be $setup.ExpectedSignerSubject
        $script:assignments[0].scope | Should -Be $setup.CertificateProfileId
        Should -Invoke Invoke-SetupAzure -Times 1 -Exactly -ParameterFilter {
            $Arguments[0] -eq 'role' -and $Arguments[2] -eq 'create' -and
            $Arguments[5] -eq '--assignee-principal-type' -and $Arguments[6] -eq 'ServicePrincipal'
        }
        Should -Invoke Invoke-NativeTool -Times 0 -ParameterFilter { $Tool -eq 'gh' }
        Should -Invoke Invoke-NativeTool -Times 1 -Exactly -ParameterFilter {
            $Tool -eq 'az' -and $ToolArguments[2] -eq '--subscription' -and
            $ToolArguments[3] -eq '66666666-6666-6666-6666-666666666666'
        }
    }

    It 'omits an unconfigured profile EKU without writing an empty GitHub variable' {
        Invoke-ArtifactSigningSetup @setup

        $script:repoVariables.ENABLE_ARTIFACT_SIGNING | Should -BeExactly 'true'
        $script:environmentVariables.ContainsKey('EXPECTED_PROFILE_EKU') | Should -BeFalse
        Should -Invoke Invoke-SetupGitHub -Times 0 -ParameterFilter {
            $Endpoint -like '*/variables*' -and $Method -in 'POST', 'PATCH' -and
            [string]::IsNullOrEmpty($Body.value)
        }
    }

    It 'sets a supplied profile EKU and deletes it when omitted on rerun' {
        $setup.ExpectedProfileEku = '1.3.6.1.4.1.311.97.123.456'
        Invoke-ArtifactSigningSetup @setup
        $script:environmentVariables.EXPECTED_PROFILE_EKU | Should -BeExactly $setup.ExpectedProfileEku
        $setup.Remove('ExpectedProfileEku')

        Invoke-ArtifactSigningSetup @setup

        $script:repoVariables.ENABLE_ARTIFACT_SIGNING | Should -BeExactly 'true'
        $script:environmentVariables.ContainsKey('EXPECTED_PROFILE_EKU') | Should -BeFalse
        Should -Invoke Invoke-SetupGitHub -Times 1 -Exactly -ParameterFilter {
            $Method -eq 'DELETE' -and $Endpoint -like '*/variables/EXPECTED_PROFILE_EKU'
        }
    }

    It 'keeps signing disabled if the omitted profile EKU is not deleted' {
        $script:environmentVariables.EXPECTED_PROFILE_EKU = '1.3.6.1.4.1.311.97.123.456'
        Mock Invoke-SetupGitHub {} -ParameterFilter {
            $Method -eq 'DELETE' -and $Endpoint -like '*/variables/EXPECTED_PROFILE_EKU'
        }

        { Invoke-ArtifactSigningSetup @setup } | Should -Throw '*GitHub variable verification failed: EXPECTED_PROFILE_EKU*'

        $script:repoVariables.ENABLE_ARTIFACT_SIGNING | Should -BeExactly 'false'
    }

    It 'supports solo setup without reviewer lookups or a required-reviewer protection feature' {
        $setup.Remove('Reviewer')
        $script:protectionsSupported = $false

        Invoke-ArtifactSigningSetup @setup

        $script:repoVariables.ENABLE_ARTIFACT_SIGNING | Should -BeExactly 'true'
        $script:reviewers.Count | Should -Be 0
        $script:policies.Count | Should -Be 1
        $script:policies[0].name | Should -Be 'main'
        Should -Invoke Invoke-SetupGitHub -Times 0 -ParameterFilter {
            $Endpoint -like 'users/*' -or $Endpoint -like '*/collaborators/*'
        }
        Should -Invoke Invoke-SetupGitHub -Times 1 -Exactly -ParameterFilter {
            $Method -eq 'PUT' -and $Body.reviewers.Count -eq 0 -and -not $Body.prevent_self_review
        }
    }

    It 'removes existing required reviewers when rerun without Reviewer' {
        Invoke-ArtifactSigningSetup @setup
        $setup.Remove('Reviewer')

        Invoke-ArtifactSigningSetup @setup

        $script:repoVariables.ENABLE_ARTIFACT_SIGNING | Should -BeExactly 'true'
        $script:reviewers.Count | Should -Be 0
        Should -Invoke Invoke-SetupGraph -Times 1 -Exactly -ParameterFilter {
            $Path -eq 'applications' -and $Method -eq 'POST'
        }
    }

    It 'keeps signing disabled if GitHub does not remove a previous reviewer gate' {
        Invoke-ArtifactSigningSetup @setup
        $setup.Remove('Reviewer')
        $script:ignoreReviewerChanges = $true

        { Invoke-ArtifactSigningSetup @setup } | Should -Throw '*did not remove required-reviewer approval*'

        $script:repoVariables.ENABLE_ARTIFACT_SIGNING | Should -BeExactly 'false'
    }

    It 'reruns without creating duplicate identities, federation or role assignments' {
        Invoke-ArtifactSigningSetup @setup
        Invoke-ArtifactSigningSetup @setup

        Should -Invoke Invoke-SetupGraph -Times 1 -Exactly -ParameterFilter { $Path -eq 'applications' -and $Method -eq 'POST' }
        Should -Invoke Invoke-SetupGraph -Times 1 -Exactly -ParameterFilter { $Path -like '*federatedIdentityCredentials' -and $Method -eq 'POST' }
        Should -Invoke Invoke-SetupAzure -Times 1 -Exactly -ParameterFilter { $Arguments[0] -eq 'role' -and $Arguments[2] -eq 'create' }
    }

    It 'configures <ProfileType> without local certificate inputs or trust changes' -ForEach @(
        @{ ProfileType = 'PublicTrust' },
        @{ ProfileType = 'PrivateTrust' }
    ) {
        $script:profileType = $ProfileType
        Mock Get-ArtifactSigningCaCertificate { throw 'Setup must not read local CA files.' }
        Mock Import-ArtifactSigningTrust { throw 'Setup must not change local trust.' }

        Invoke-ArtifactSigningSetup @setup

        $script:repoVariables.ENABLE_ARTIFACT_SIGNING | Should -BeExactly 'true'
        $script:environmentVariables.ARTIFACT_SIGNING_PROFILE_TYPE | Should -BeExactly $ProfileType
        $script:environmentVariables.Keys | Should -Not -Contain 'ARTIFACT_SIGNING_ROOT_CERTIFICATE_BASE64'
        Should -Invoke Get-ArtifactSigningCaCertificate -Times 0
        Should -Invoke Import-ArtifactSigningTrust -Times 0
    }

    It 'makes no remote changes with WhatIf' {
        Invoke-ArtifactSigningSetup @setup -WhatIf

        $script:repoVariables.Count | Should -Be 0
        Should -Invoke Invoke-SetupGitHub -Times 0 -ParameterFilter { $Method -in 'PUT', 'POST', 'PATCH', 'DELETE' }
        Should -Invoke Invoke-SetupGraph -Times 0
        Should -Invoke Invoke-NativeTool -Times 0
    }

    It 'preserves an existing environment wait timer while tightening branch policies' {
        $script:existingEnvironments = @([pscustomobject] @{
            name = 'artifact-signing'
            protection_rules = @([pscustomobject] @{ type = 'wait_timer'; wait_timer = 30 })
        })

        Invoke-ArtifactSigningSetup @setup

        $script:configuredWaitTimer | Should -Be 30
        $script:policies.Count | Should -Be 1
    }

    It 'uses an explicitly selected application without creating another application' {
        $script:apps = @([pscustomobject] @{
            id = '11111111-1111-1111-1111-111111111111'
            appId = '22222222-2222-2222-2222-222222222222'
        })
        $setup.ApplicationClientId = $script:apps[0].appId

        Invoke-ArtifactSigningSetup @setup

        $script:environmentVariables.AZURE_CLIENT_ID | Should -Be $setup.ApplicationClientId
        Should -Invoke Invoke-SetupGraph -Times 0 -ParameterFilter { $Path -eq 'applications' -and $Method -eq 'POST' }
    }

    It 'keeps signing disabled when the existing wait timer is not preserved' {
        $script:existingEnvironments = @([pscustomobject] @{
            name = 'artifact-signing'
            protection_rules = @([pscustomobject] @{ type = 'wait_timer'; wait_timer = 30 })
        })
        $script:ignoreWaitTimer = $true

        { Invoke-ArtifactSigningSetup @setup } | Should -Throw '*did not preserve*wait timer*'

        $script:repoVariables.ENABLE_ARTIFACT_SIGNING | Should -BeExactly 'false'
        Should -Invoke Invoke-SetupGraph -Times 0
    }

    It 'repairs this repository federation without changing its immutable name' {
        Invoke-ArtifactSigningSetup @setup
        $script:credentials[0].subject = 'repo:old-owner/msi:environment:artifact-signing'

        Invoke-ArtifactSigningSetup @setup

        $script:credentials[0].subject | Should -BeExactly 'repo:ExampleOrg/msi:environment:artifact-signing'
        Should -Invoke Invoke-SetupGraph -Times 1 -Exactly -ParameterFilter {
            $Path -like '*federatedIdentityCredentials/*' -and $Method -eq 'PATCH' -and -not $Body.ContainsKey('name')
        }
    }

    It 'uses the GitHub-reported immutable subject prefix when creating federation' {
        $script:subjectPrefix = 'repo:ExampleOrg@456/msi@123'

        Invoke-ArtifactSigningSetup @setup

        $script:credentials[0].subject | Should -BeExactly 'repo:ExampleOrg@456/msi@123:environment:artifact-signing'
        $script:repoVariables.ENABLE_ARTIFACT_SIGNING | Should -BeExactly 'true'
    }

    It 'repairs name-only federation when the repository adopts immutable subjects' {
        Invoke-ArtifactSigningSetup @setup
        $script:subjectPrefix = 'repo:ExampleOrg@456/msi@123'

        Invoke-ArtifactSigningSetup @setup

        $script:credentials[0].subject | Should -BeExactly 'repo:ExampleOrg@456/msi@123:environment:artifact-signing'
        Should -Invoke Invoke-SetupGraph -Times 1 -Exactly -ParameterFilter {
            $Path -like '*federatedIdentityCredentials/*' -and $Method -eq 'PATCH'
        }
        Should -Invoke Invoke-SetupGraph -Times 1 -Exactly -ParameterFilter {
            $Path -eq 'applications' -and $Method -eq 'POST'
        }
    }

    It 'rejects a missing OIDC subject prefix before making remote changes' {
        Mock Invoke-SetupGitHub { [pscustomobject] @{ use_default = $true } } -ParameterFilter {
            $Endpoint -like '*oidc/customization/sub'
        }

        { Invoke-ArtifactSigningSetup @setup } | Should -Throw '*GitHub did not return an OIDC subject prefix*'

        Should -Invoke Invoke-SetupGitHub -Times 0 -ParameterFilter { $Method -in 'PUT', 'POST', 'PATCH', 'DELETE' }
        Should -Invoke Invoke-SetupGraph -Times 0
    }

    It 'rejects ambiguous existing applications instead of granting permissions to the first match' {
        $script:apps = @([pscustomobject] @{ id = 'first' }, [pscustomobject] @{ id = 'second' })

        { Invoke-ArtifactSigningSetup @setup } | Should -Throw '*Multiple matching Entra applications*'

        $script:repoVariables.ENABLE_ARTIFACT_SIGNING | Should -BeExactly 'false'
        Should -Invoke Invoke-SetupAzure -Times 0 -ParameterFilter { $Arguments[0] -eq 'role' -and $Arguments[2] -eq 'create' }
    }

    It 'keeps signing disabled and creates no identity when protection enforcement is unavailable' {
        $script:protectionsSupported = $false

        { Invoke-ArtifactSigningSetup @setup } | Should -Throw '*signing is disabled*Check your GitHub plan*'

        $script:repoVariables.ENABLE_ARTIFACT_SIGNING | Should -BeExactly 'false'
        Should -Invoke Invoke-SetupGraph -Times 0
    }

    It 'keeps signing disabled on RBAC failure and retains the identity for rerun' {
        $script:roleAssignmentAllowed = $false

        { Invoke-ArtifactSigningSetup @setup } | Should -Throw '*signing is disabled*Role assignment permission denied*'

        $script:repoVariables.ENABLE_ARTIFACT_SIGNING | Should -BeExactly 'false'
        $script:apps.Count | Should -Be 1
    }

    It 'rolls back the enable flag if final read-back fails' {
        $script:failFinalEnableRead = $true

        { Invoke-ArtifactSigningSetup @setup } | Should -Throw '*signing is disabled*Enable read-back failed*'

        $script:repoVariables.ENABLE_ARTIFACT_SIGNING | Should -BeExactly 'false'
    }

    It 'reports explicitly when signing cannot be disabled rather than claiming safe rollback' {
        Mock Invoke-SetupGitHub { throw 'Variable write denied' } -ParameterFilter {
            $Endpoint -like '*actions/variables*' -and $Method -in 'POST', 'PATCH'
        }

        { Invoke-ArtifactSigningSetup @setup } |
            Should -Throw '*Disabling signing also failed*Manually set ENABLE_ARTIFACT_SIGNING=false immediately*'

        Should -Invoke Invoke-SetupGraph -Times 0
    }

    It 'rejects custom OIDC templates before making any remote changes' {
        $script:customSubject = $true

        { Invoke-ArtifactSigningSetup @setup } | Should -Throw '*Custom GitHub OIDC subject templates*'

        $script:repoVariables.Count | Should -Be 0
        Should -Invoke Invoke-SetupGraph -Times 0
    }

    It 'resolves team reviewers and optionally dispatches the default branch without approving it' {
        $setup.Reviewer = @('ExampleOrg/signers')
        Invoke-ArtifactSigningSetup @setup -Dispatch

        $script:reviewers[0].type | Should -Be 'Team'
        Should -Invoke Invoke-NativeTool -Times 1 -Exactly -ParameterFilter {
            $Tool -eq 'gh' -and $ToolArguments[0] -eq 'workflow' -and $ToolArguments[-1] -eq 'main'
        }
    }
}

Describe 'Setup API request encoding' {
    It 'encodes JSON bodies and removes temporary request files even after a CLI failure' {
        $script:requestPath = $null
        Mock Invoke-NativeTool {
            $script:requestPath = $ToolArguments[([array]::IndexOf($ToolArguments, '--input') + 1)]
            $body = Get-Content -LiteralPath $script:requestPath -Raw | ConvertFrom-Json
            $body.value | Should -Be 'CN="Example, Inc."'
            throw 'GitHub API failure'
        }

        { Invoke-SetupGitHub -Endpoint 'repos/example/msi/actions/variables' -Method POST `
            -Body @{ name = 'EXPECTED_SIGNER_SUBJECT'; value = 'CN="Example, Inc."' } } |
            Should -Throw '*GitHub API failure*'

        $script:requestPath | Should -Not -Exist
    }

    It 'never forwards the Graph bearer token to an unexpected continuation host' {
        Mock Invoke-RestMethod {
            return [pscustomobject] @{
                value = @([pscustomobject] @{ id = 'first' })
                '@odata.nextLink' = 'https://unexpected.example.test/page2'
            }
        }

        { Invoke-SetupGraph -Path applications -AccessToken 'test-only-placeholder' } |
            Should -Throw '*unsupported continuation URL*'

        Should -Invoke Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
            $Uri -eq 'https://graph.microsoft.com/v1.0/applications'
        }
    }
}

Describe 'GitHub Artifact Signing setup and dispatch' {
    BeforeEach {
        $script:project = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $project
        $script:github = @{
            ProjectRoot = $project
            Repository = 'exampleorg/msi'
            ExpectedSignerSubject = 'CN=Example Organization'
            Confirm = $false
        }
        Mock Invoke-GitHubSigningApi {
            if ($Endpoint -eq 'repos/exampleorg/msi') {
                return [pscustomobject] @{ full_name = 'ExampleOrg/msi'; default_branch = 'release/default' }
            }
            if ($Endpoint -eq 'repos/ExampleOrg/msi/actions/workflows/artifact-signing.yml') {
                return [pscustomobject] @{ state = 'active' }
            }
            if ($Endpoint -like '*/actions/variables/ENABLE_ARTIFACT_SIGNING') {
                return [pscustomobject] @{ value = 'true' }
            }
            if ($Endpoint -like '*/variables/EXPECTED_SIGNER_SUBJECT') {
                return [pscustomobject] @{ value = 'CN=Example Organization' }
            }
            if ($Endpoint -like '*/variables/EXPECTED_PROFILE_EKU') {
                return [pscustomobject] @{ value = '1.3.6.1.4.1.311.97.123.456' }
            }
            if ($Endpoint -like '*/dispatches' -and $Method -eq 'POST') {
                return [pscustomobject] @{ workflow_run_id = 456 }
            }
            throw "Unexpected GitHub helper request: $Method $Endpoint"
        }
        Mock Invoke-NativeTool { throw "Local MSI or Azure commands must not run: $Tool $ToolArguments" }
    }

    It 'allows the GitHub helper to set up solo use without supplying Reviewer' {
        @'
[CmdletBinding(SupportsShouldProcess)]
param($Repository, $CertificateProfileId, $ExpectedSignerSubject)
[pscustomobject] $PSBoundParameters
'@ | Set-Content -LiteralPath (Join-Path $project 'setup-artifact-signing.ps1')

        $result = Invoke-GitHubArtifactSigning @github -Setup -CertificateProfileId '/subscriptions/test/profile'

        $result.Repository | Should -BeExactly 'exampleorg/msi'
        $result.ExpectedSignerSubject | Should -Be $github.ExpectedSignerSubject
        $result.PSObject.Properties.Name | Should -Not -Contain 'Reviewer'
    }

    It 'forwards setup settings and WhatIf without dispatching or approving anything' {
        @'
[CmdletBinding(SupportsShouldProcess)]
param($Repository, $CertificateProfileId, $ExpectedSignerSubject, $Reviewer,
      $ExpectedProfileEku, $ApplicationClientId)
[pscustomobject] $PSBoundParameters
'@ | Set-Content -LiteralPath (Join-Path $project 'setup-artifact-signing.ps1')
        $result = Invoke-GitHubArtifactSigning @github -Setup -WhatIf `
            -CertificateProfileId '/subscriptions/test/profile' -Reviewer @('another-reviewer') `
            -ExpectedProfileEku '1.3.6.1.4.1.311.97.123.456'

        $result.Repository | Should -BeExactly 'exampleorg/msi'
        $result.CertificateProfileId | Should -Be '/subscriptions/test/profile'
        $result.Reviewer | Should -Be @('another-reviewer')
        $result.ExpectedProfileEku | Should -Be '1.3.6.1.4.1.311.97.123.456'
        [bool] $result.WhatIf | Should -BeTrue
        [bool] $result.Confirm | Should -BeFalse
        Should -Invoke Invoke-GitHubSigningApi -Times 0 -ParameterFilter { $Method -eq 'POST' }
        Should -Invoke Invoke-NativeTool -Times 0
    }

    It 'returns the dispatched run ID from the API rather than selecting the latest run' {
        $result = Invoke-GitHubArtifactSigning @github -Run

        $result.RunId | Should -Be 456
        $result.RunUrl | Should -Be 'https://github.com/ExampleOrg/msi/actions/runs/456'
        Should -Invoke Invoke-GitHubSigningApi -Times 1 -Exactly -ParameterFilter {
            $Method -eq 'POST' -and $Field.Count -eq 1 -and $Field[0] -eq 'ref=refs/heads/release/default'
        }
        Should -Invoke Invoke-NativeTool -Times 0
    }

    It 'previews a dispatch without creating a run' {
        $result = Invoke-GitHubArtifactSigning @github -Run -WhatIf

        $result | Should -BeNullOrEmpty
        Should -Invoke Invoke-GitHubSigningApi -Times 0 -ParameterFilter { $Method -eq 'POST' }
    }

    It 'triggers using only the repository without Azure commands or local build files' {
        $github.Remove('ExpectedSignerSubject')

        $result = Invoke-GitHubArtifactSigning @github -Run

        $result.RunId | Should -Be 456
        @(Get-ChildItem -LiteralPath $project -Force).Count | Should -Be 0
        Should -Invoke Invoke-NativeTool -Times 0
        Should -Invoke Invoke-GitHubSigningApi -Times 0 -ParameterFilter {
            $Endpoint -like '*/environments/*/variables/*'
        }
    }

    It 'requires setup to be enabled before dispatch' {
        Mock Invoke-GitHubSigningApi { [pscustomobject] @{ value = 'false' } } -ParameterFilter {
            $Endpoint -like '*/actions/variables/ENABLE_ARTIFACT_SIGNING'
        }

        { Invoke-GitHubArtifactSigning @github -Run } | Should -Throw '*Run this helper with -Setup first*'
        Should -Invoke Invoke-GitHubSigningApi -Times 0 -ParameterFilter { $Method -eq 'POST' }
    }

    It 'rejects a configured signer that differs from the requested publisher' {
        $github.ExpectedSignerSubject = 'CN=Different publisher'

        { Invoke-GitHubArtifactSigning @github -Run } | Should -Throw '*EXPECTED_SIGNER_SUBJECT does not match*'
        Should -Invoke Invoke-GitHubSigningApi -Times 0 -ParameterFilter { $Method -eq 'POST' }
    }

    It 'does not guess a run when dispatch returns no run ID' {
        Mock Invoke-GitHubSigningApi {} -ParameterFilter { $Method -eq 'POST' }

        { Invoke-GitHubArtifactSigning @github -Run } | Should -Throw '*Check https://github.com/ExampleOrg/msi/actions*'
        Should -Invoke Invoke-GitHubSigningApi -Times 1 -Exactly -ParameterFilter { $Method -eq 'POST' }
    }

}

Describe 'Private Trust setup on the Windows runner' {
    BeforeAll {
        $workflow = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\.github\workflows\artifact-signing.yml') -Raw
        $match = [regex]::Match($workflow, '(?ms)^      - name: Configure Private Trust CA certificates on the runner\r?\n        if:.*?\r?\n        run: \|\r?\n(?<body>.*?)(?=^      - name:)')
        if (-not $match.Success) { throw 'Private Trust runner step was not found.' }
        $runnerTrust = [scriptblock]::Create(($match.Groups['body'].Value -replace '(?m)^ {10}', ''))
    }

    BeforeEach {
        $runnerRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $runnerRoot
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot '..\dependencies.json') -Destination $runnerRoot
        '# Runner signing helper fixture' | Set-Content -LiteralPath (Join-Path $runnerRoot 'signing.ps1')
        Set-Content -LiteralPath (Join-Path $runnerRoot 'root.cer') -Value 'public root fixture'
        Set-Content -LiteralPath (Join-Path $runnerRoot 'intermediate.cer') -Value 'public intermediate fixture'
        @'
param($SubscriptionId, $Endpoint, $AccountName, $CertificateProfileName,
      $ExpectedSignerSubject, [switch] $DownloadCertificates)
if (-not $DownloadCertificates) { throw 'Building or signing must not run in the CA step.' }
if ($AccountName -ne 'account-name' -or $CertificateProfileName -ne 'profile-name' -or
    $ExpectedSignerSubject -cne 'CN=Expected publisher') { throw 'Wrong profile download settings.' }
[pscustomobject] @{
    RootCertificatePath = Join-Path $PSScriptRoot 'root.cer'
    IntermediateCertificatePath = @(Join-Path $PSScriptRoot 'intermediate.cer')
}
'@ | Set-Content -LiteralPath (Join-Path $runnerRoot 'local-artifact-signing.ps1')
        $environment = @{
            AZURE_SUBSCRIPTION_ID = '66666666-6666-6666-6666-666666666666'
            ARTIFACT_SIGNING_ENDPOINT = 'https://neu.codesigning.azure.net/'
            ARTIFACT_SIGNING_ACCOUNT_NAME = 'account-name'
            ARTIFACT_SIGNING_CERTIFICATE_PROFILE_NAME = 'profile-name'
            EXPECTED_SIGNER_SUBJECT = 'CN=Expected publisher'
        }
        $previousEnvironment = @{}
        foreach ($name in $environment.Keys) {
            $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name)
            [Environment]::SetEnvironmentVariable($name, $environment[$name])
        }
        Mock Get-Module { @() } -ParameterFilter { $Name -contains 'Az.ArtifactSigning' }
        Mock Install-Module {} -ParameterFilter { $Name -contains 'Az.ArtifactSigning' }
        Mock Import-Module {} -ParameterFilter { $Name -contains 'Az.ArtifactSigning' }
        Mock Import-ArtifactSigningTrust {}
    }

    AfterEach {
        foreach ($name in $previousEnvironment.Keys) {
            [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name])
        }
    }

    It 'retrieves the configured profile CAs on the runner and imports them using the pinned module' {
        Push-Location $runnerRoot
        try { & $runnerTrust }
        finally { Pop-Location }

        $version = (Get-Content -LiteralPath (Join-Path $runnerRoot 'dependencies.json') -Raw | ConvertFrom-Json).azArtifactSigning.version
        Should -Invoke Install-Module -Times 1 -Exactly -ParameterFilter {
            $Name -contains 'Az.ArtifactSigning' -and $RequiredVersion -eq $version
        }
        Should -Invoke Import-Module -Times 1 -Exactly -ParameterFilter {
            $Name -contains 'Az.ArtifactSigning' -and $RequiredVersion -eq $version
        }
        $root = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $runnerRoot 'root.cer')))
        $intermediate = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $runnerRoot 'intermediate.cer')))
        Should -Invoke Import-ArtifactSigningTrust -Times 1 -Exactly -ParameterFilter {
            $RootCertificateBase64 -ceq $root -and $IntermediateCertificatesBase64 -ceq $intermediate -and
            $StoreLocation -eq 'LocalMachine'
        }
    }

    It 'stops before importing trust if profile certificate retrieval fails' {
        "throw 'Profile certificate retrieval failed.'" |
            Set-Content -LiteralPath (Join-Path $runnerRoot 'local-artifact-signing.ps1')

        Push-Location $runnerRoot
        try { { & $runnerTrust } | Should -Throw '*Profile certificate retrieval failed*' }
        finally { Pop-Location }

        Should -Invoke Import-ArtifactSigningTrust -Times 0
    }
}

Describe 'GitHub signing dispatch requests' {
    It 'requests a run-ID-returning API version and preserves a slash-containing branch ref' {
        Mock Invoke-NativeTool { '{"workflow_run_id":456}' }

        $result = Invoke-GitHubSigningApi -Endpoint 'repos/example/msi/actions/workflows/artifact-signing.yml/dispatches' `
            -Method POST -Field @('ref=refs/heads/release/default')

        $result.workflow_run_id | Should -Be 456
        Should -Invoke Invoke-NativeTool -Times 1 -Exactly -ParameterFilter {
            $Tool -eq 'gh' -and $ToolArguments -contains 'X-GitHub-Api-Version: 2026-03-10' -and
            $ToolArguments -contains 'POST' -and $ToolArguments -contains 'ref=refs/heads/release/default'
        }
    }
}
