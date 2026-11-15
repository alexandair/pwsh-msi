#Requires -Version 7.2
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
.SYNOPSIS
Runs mocked Artifact Signing setup regression tests through Pester.

.DESCRIPTION
Loads setup functions without executing the setup script. Tests environment
protections, identity and federation reuse, profile-scoped RBAC, workflow
variables, WhatIf, dispatch, failure handling, and API request safety.

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
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $PSScriptRoot '..\setup-artifact-signing.ps1'), [ref] $tokens, [ref] $errors
    )
    if ($errors.Count) { throw ($errors.Message -join [Environment]::NewLine) }
    foreach ($function in $ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst]
    }, $false)) {
        . ([scriptblock]::Create($function.Extent.Text))
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
        $script:existingEnvironments = @()
        $script:configuredWaitTimer = 0
        $script:ignoreWaitTimer = $false
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
                return [pscustomobject] @{ use_default = -not $script:customSubject }
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
                    $variables[$Body.name] = $Body.value
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
                    $script:reviewers = $Body.reviewers
                    if ($Body.ContainsKey('wait_timer') -and -not $script:ignoreWaitTimer) {
                        $script:configuredWaitTimer = $Body.wait_timer
                    }
                    return
                }
                return [pscustomobject] @{
                    protection_rules = @([pscustomobject] @{
                        type = 'required_reviewers'
                        prevent_self_review = $script:protectionsSupported
                        reviewers = @($script:reviewers | ForEach-Object {
                            [pscustomobject] @{ type = $_.type; reviewer = [pscustomobject] @{ id = $_.id } }
                        })
                    }) + @(
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
                    return [pscustomobject] @{ id = $id; properties = [pscustomobject] @{ profileType = 'PublicTrust' } }
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

    It 'reruns without creating duplicate identities, federation or role assignments' {
        Invoke-ArtifactSigningSetup @setup
        Invoke-ArtifactSigningSetup @setup

        Should -Invoke Invoke-SetupGraph -Times 1 -Exactly -ParameterFilter { $Path -eq 'applications' -and $Method -eq 'POST' }
        Should -Invoke Invoke-SetupGraph -Times 1 -Exactly -ParameterFilter { $Path -like '*federatedIdentityCredentials' -and $Method -eq 'POST' }
        Should -Invoke Invoke-SetupAzure -Times 1 -Exactly -ParameterFilter { $Arguments[0] -eq 'role' -and $Arguments[2] -eq 'create' }
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
