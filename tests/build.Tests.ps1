#Requires -Version 7.2
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
.SYNOPSIS
Runs build and signing regression tests through Pester.

.DESCRIPTION
Tests local, Key Vault, and Artifact Signing helpers, cached tool handling,
runtime prerequisites, and failure behavior. Uses mocked cloud calls and
temporary test certificates, not production signing credentials.

Load this file with Invoke-Pester or New-PesterContainer. Supplying an MSI
enables the native signing integration test; otherwise that test is skipped.

.PARAMETER IntegrationMsiPath
Optional existing MSI for native signing verification on Windows. The test
signs a temporary copy with an untrusted test certificate and verifies that
it is rejected. Does not modify the original MSI or certificate stores.

.EXAMPLE
Invoke-Pester -Path .\tests\build.Tests.ps1

Runs the tests without the optional native MSI signing integration test.

.EXAMPLE
$container = New-PesterContainer -Path .\tests\build.Tests.ps1 -Data @{
    IntegrationMsiPath = (Resolve-Path .\out\PowerShell-7.7.0-win-x64-unofficial.msi).Path
}
Invoke-Pester -Container $container

Also exercises native signing against a temporary copy of the existing MSI.
Adjust the path to match the version configured in dependencies.json.

.NOTES
Requires Windows and Pester 5. The tests do not create Azure resources or
replace your built MSI. Live cloud signing and installation acceptance are
separate checks.

.LINK
..\README.md
#>

param(
    [string] $IntegrationMsiPath
)

BeforeAll {
    $buildPath = Join-Path $PSScriptRoot '..\build.ps1'
    $tokens = $null
    $parseErrors = $null
    $build = [System.Management.Automation.Language.Parser]::ParseFile(
        $buildPath, [ref] $tokens, [ref] $parseErrors
    )
    if ($parseErrors.Count) {
        throw ($parseErrors.Message -join [Environment]::NewLine)
    }

    . (Join-Path $PSScriptRoot '..\signing.ps1')

    # Load build-specific signing helpers without downloading the payload.
    foreach ($name in @(
        'Assert-CodeSigningCertificate', 'Invoke-MsiSigning',
        'Get-KeyVaultSigningCertificate', 'Invoke-KeyVaultMsiSigning',
        'Get-VerifiedFile', 'Get-ArtifactSigningTool',
        'Get-ArtifactSigningRuntimeStatus', 'Assert-ArtifactSigningPrerequisites',
        'Publish-Msi'
    )) {
        $function = $build.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $name
        }, $false)
        if (-not $function) { throw "Signing helper not found: $name" }
        . ([scriptblock]::Create($function.Extent.Text))
    }

    $key = [System.Security.Cryptography.RSA]::Create(2048)
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=MSI signing test', $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $usages = [System.Security.Cryptography.OidCollection]::new()
    $null = $usages.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
    $profileEku = '1.3.6.1.4.1.311.97.123.456'
    $null = $usages.Add([System.Security.Cryptography.Oid]::new($profileEku))
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($usages, $true)
    )
    $certificate = $request.CreateSelfSigned(
        [DateTimeOffset]::Now.AddMinutes(-5), [DateTimeOffset]::Now.AddDays(1)
    )
    $expiredCertificate = $request.CreateSelfSigned(
        [DateTimeOffset]::Now.AddDays(-2), [DateTimeOffset]::Now.AddDays(-1)
    )
    $publicCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    )
    $request.CertificateExtensions.Clear()
    $nonSigningCertificate = $request.CreateSelfSigned(
        [DateTimeOffset]::Now.AddMinutes(-5), [DateTimeOffset]::Now.AddDays(1)
    )
}

AfterAll {
    if ($nonSigningCertificate) { $nonSigningCertificate.Dispose() }
    if ($publicCertificate) { $publicCertificate.Dispose() }
    if ($expiredCertificate) { $expiredCertificate.Dispose() }
    if ($certificate) { $certificate.Dispose() }
    if ($key) { $key.Dispose() }
}

Describe 'MSI publication' {
    BeforeEach {
        $directory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $directory
        $staged = Join-Path $directory 'PowerShell.msi'
        $destination = Join-Path $directory 'PowerShell-version-win-x64-unofficial.msi'
        [IO.File]::WriteAllText($staged, 'verified new MSI')
    }

    It 'publishes a new output without Force' {
        Publish-Msi -Path $staged -Destination $destination

        [IO.File]::ReadAllText($destination) | Should -BeExactly 'verified new MSI'
        $staged | Should -Not -Exist
    }

    It 'replaces existing output with Force' {
        [IO.File]::WriteAllText($destination, 'previous MSI')

        Publish-Msi -Path $staged -Destination $destination -Force

        [IO.File]::ReadAllText($destination) | Should -BeExactly 'verified new MSI'
        $staged | Should -Not -Exist
    }

    It 'preserves existing output and staging when Force is absent' {
        [IO.File]::WriteAllText($destination, 'previous MSI')

        { Publish-Msi -Path $staged -Destination $destination } | Should -Throw

        [IO.File]::ReadAllText($destination) | Should -BeExactly 'previous MSI'
        [IO.File]::ReadAllText($staged) | Should -BeExactly 'verified new MSI'
    }

    It 'preserves existing output when forced publication fails' {
        [IO.File]::WriteAllText($destination, 'previous MSI')
        $lock = [IO.File]::Open($destination, 'Open', 'Read', 'None')
        try {
            { Publish-Msi -Path $staged -Destination $destination -Force } | Should -Throw
        }
        finally {
            $lock.Dispose()
        }

        [IO.File]::ReadAllText($destination) | Should -BeExactly 'previous MSI'
        [IO.File]::ReadAllText($staged) | Should -BeExactly 'verified new MSI'
    }
}

Describe 'Explicit Artifact Signing CA trust' -Skip:(-not $IsWindows) {
    BeforeAll {
        $rootRequest = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=Artifact Signing test root', $key, [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $rootRequest.CertificateExtensions.Add(
            [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true)
        )
        $rootRequest.CertificateExtensions.Add(
            [Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
                [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign, $true
            )
        )
        $rootCa = $rootRequest.CreateSelfSigned(
            [DateTimeOffset]::Now.AddMinutes(-5), [DateTimeOffset]::Now.AddDays(1)
        )
        $intermediateRequest = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=Artifact Signing test intermediate', $key, [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $intermediateRequest.CertificateExtensions.Add(
            [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true)
        )
        $intermediateCa = $intermediateRequest.Create(
            $rootCa, [DateTimeOffset]::Now.AddMinutes(-1), [DateTimeOffset]::Now.AddHours(1), [byte[]] @(1, 2, 3)
        )
        $rootBase64 = [Convert]::ToBase64String($rootCa.RawData)
        $intermediateBase64 = [Convert]::ToBase64String($intermediateCa.RawData)
        $leafBase64 = [Convert]::ToBase64String($publicCertificate.RawData)
    }

    AfterAll {
        $intermediateCa.Dispose()
        $rootCa.Dispose()
    }

    BeforeEach {
        $script:importPaths = @()
        $script:importedCertificates = @()
        Mock Import-Certificate {
            $script:importPaths += $FilePath
            $imported = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
                [IO.File]::ReadAllBytes($FilePath)
            )
            try {
                $script:importedCertificates += @{
                    Thumbprint = $imported.Thumbprint
                    Store = $CertStoreLocation
                }
            }
            finally { $imported.Dispose() }
        }
    }

    It 'does not change trust when no additional CA certificates are configured' {
        Import-ArtifactSigningTrust

        Should -Invoke Import-Certificate -Times 0
    }

    It 'imports only the approved root and intermediates into their correct stores and removes temporary files' {
        Import-ArtifactSigningTrust -RootCertificateBase64 $rootBase64 `
            -IntermediateCertificatesBase64 "$intermediateBase64`n$intermediateBase64"

        $script:importedCertificates.Count | Should -Be 3
        $script:importedCertificates[0].Thumbprint | Should -Be $rootCa.Thumbprint
        $script:importedCertificates[0].Store | Should -BeExactly 'Cert:\CurrentUser\Root'
        $script:importedCertificates[1].Thumbprint | Should -Be $intermediateCa.Thumbprint
        $script:importedCertificates[1].Store | Should -BeExactly 'Cert:\CurrentUser\CA'
        $script:importedCertificates[2].Store | Should -BeExactly 'Cert:\CurrentUser\CA'
        foreach ($path in $script:importPaths) { $path | Should -Not -Exist }
    }

    It 'imports validated CAs into machine stores when explicitly requested for an unattended runner' {
        Import-ArtifactSigningTrust -RootCertificateBase64 $rootBase64 `
            -IntermediateCertificatesBase64 $intermediateBase64 -StoreLocation LocalMachine

        $script:importedCertificates.Count | Should -Be 2
        $script:importedCertificates[0].Thumbprint | Should -Be $rootCa.Thumbprint
        $script:importedCertificates[0].Store | Should -BeExactly 'Cert:\LocalMachine\Root'
        $script:importedCertificates[1].Thumbprint | Should -Be $intermediateCa.Thumbprint
        $script:importedCertificates[1].Store | Should -BeExactly 'Cert:\LocalMachine\CA'
        foreach ($path in $script:importPaths) { $path | Should -Not -Exist }
    }

    It 'rejects a signing leaf as a root CA' {
        { Import-ArtifactSigningTrust -RootCertificateBase64 $leafBase64 } | Should -Throw '*not a CA certificate*'

        Should -Invoke Import-Certificate -Times 0
    }

    It 'validates every certificate before making any trust changes' {
        { Import-ArtifactSigningTrust -RootCertificateBase64 $rootBase64 `
            -IntermediateCertificatesBase64 "$intermediateBase64`n$leafBase64" } |
            Should -Throw '*not a CA certificate*'

        Should -Invoke Import-Certificate -Times 0
    }

    It 'rejects a root or intermediate assigned to the wrong store' {
        { Get-ArtifactSigningCaCertificate -Base64Certificate $intermediateBase64 -Root } |
            Should -Throw '*root CA must be self-issued*'
        { Get-ArtifactSigningCaCertificate -Base64Certificate $rootBase64 } |
            Should -Throw '*intermediate CA is a root*'
    }

    It 'rejects malformed or private-key input instead of installing it' {
        { Import-ArtifactSigningTrust -RootCertificateBase64 'not-base64' } | Should -Throw
        $pfx = [Convert]::ToBase64String($rootCa.Export(
            [Security.Cryptography.X509Certificates.X509ContentType]::Pfx
        ))
        { Import-ArtifactSigningTrust -RootCertificateBase64 $pfx } | Should -Throw '*not a PFX*'

        Should -Invoke Import-Certificate -Times 0
    }

    It 'reports import failures and removes temporary certificate files' {
        Mock Import-Certificate {
            $script:importPaths += $FilePath
            throw 'Certificate store write denied'
        }

        { Import-ArtifactSigningTrust -RootCertificateBase64 $rootBase64 } |
            Should -Throw '*Certificate store write denied*'

        $script:importPaths.Count | Should -Be 1
        $script:importPaths[0] | Should -Not -Exist
    }

    It 'runs the README subject-discovery example with <SignerCount> signing leaves' -TestCases @(
        @{ SignerCount = 0 }
        @{ SignerCount = 1 }
        @{ SignerCount = 2 }
    ) {
        param($SignerCount)

        $certificates = [Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $null = $certificates.Add($rootCa)
        $null = $certificates.Add($intermediateCa)
        if ($SignerCount -ge 1) { $null = $certificates.Add($publicCertificate) }
        if ($SignerCount -eq 2) { $null = $certificates.Add($expiredCertificate) }
        $chainPath = Join-Path $TestDrive 'profile-chain.der'
        [IO.File]::WriteAllBytes($chainPath, $certificates.Export(
            [Security.Cryptography.X509Certificates.X509ContentType]::Pkcs7
        ))
        $readme = Get-Content (Join-Path $PSScriptRoot '..\README.md') -Raw
        $example = [regex]::Match($readme, '(?ms)^```powershell\r?\n(\$chain = .*?)^```').Groups[1].Value
        if (-not $example) { throw 'README subject-discovery example not found.' }
        $escapedPath = $chainPath.Replace("'", "''")
        $scriptBlock = [scriptblock]::Create($example.Replace("'C:\Signing\profile-chain.der'", "'$escapedPath'"))

        if ($SignerCount -eq 1) {
            & $scriptBlock | Should -BeExactly $publicCertificate.Subject
        }
        else {
            { & $scriptBlock } | Should -Throw '*Expected one code-signing leaf certificate*'
        }
    }
}

Describe 'Local Artifact Signing workflow' -Skip:(-not $IsWindows) {
    BeforeAll {
        $testScript = Join-Path $PSScriptRoot '..\local-artifact-signing.ps1'
        $tokens = $null
        $parseErrors = $null
        $testAst = [Management.Automation.Language.Parser]::ParseFile($testScript, [ref] $tokens, [ref] $parseErrors)
        if ($parseErrors.Count) { throw ($parseErrors.Message -join [Environment]::NewLine) }
        $function = $testAst.Find({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'Invoke-LocalArtifactSigning'
        }, $false)
        . ([scriptblock]::Create($function.Extent.Text))
        function Get-AzArtifactSigningCertificateRoot {
            [CmdletBinding()]
            param($AccountName, $ProfileName, $EndpointUrl, $Destination)
        }
        function Get-AzArtifactSigningCertificateChain {
            [CmdletBinding()]
            param($AccountName, $ProfileName, $EndpointUrl, $Destination)
        }
        function Set-AzContext {
            [CmdletBinding()]
            param($Subscription, $Tenant, $Scope)
        }
        $caRequest = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=Acceptance script test root', $key, [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $caRequest.CertificateExtensions.Add(
            [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true)
        )
        $acceptanceRoot = $caRequest.CreateSelfSigned(
            [DateTimeOffset]::Now.AddMinutes(-5), [DateTimeOffset]::Now.AddDays(1)
        )
        $intermediateRequest = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=Acceptance script test intermediate', $key, [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $intermediateRequest.CertificateExtensions.Add(
            [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true)
        )
        $acceptanceIntermediate = $intermediateRequest.Create(
            $acceptanceRoot, [DateTimeOffset]::Now.AddMinutes(-1), [DateTimeOffset]::Now.AddHours(1), [byte[]] @(7, 8, 9)
        )
    }

    AfterAll {
        $acceptanceIntermediate.Dispose()
        $acceptanceRoot.Dispose()
    }

    BeforeEach {
        $testParameters = @{
            ProjectRoot = (Split-Path -Parent $PSScriptRoot)
            SubscriptionId = '66666666-6666-6666-6666-666666666666'
            Endpoint = 'https://neu.codesigning.azure.net/'
            AccountName = 'example-account'
            CertificateProfileName = 'example-profile'
            CertificateDirectory = (Join-Path $TestDrive ([guid]::NewGuid().ToString('N')))
            ExpectedSignerSubject = $publicCertificate.Subject
        }
        Mock Invoke-NativeTool {
            if ($Tool -eq 'az') {
                if ($ToolArguments[1] -eq 'set') { return }
                if ($ToolArguments[1] -eq 'show') {
                    return '{"tenantId":"11111111-1111-1111-1111-111111111111"}'
                }
            }
            elseif ($ToolArguments[2] -match '\\(build|verify)\.ps1$') { return }
            throw "Unexpected command: $Tool $ToolArguments"
        }
        Mock Set-AzContext {}
        Mock Import-Module {} -ParameterFilter { $Name -contains 'Az.ArtifactSigning' }
        Mock Get-AzArtifactSigningCertificateRoot {
            [IO.File]::WriteAllBytes($Destination, $acceptanceRoot.RawData)
        }
        Mock Get-AzArtifactSigningCertificateChain {
            $chain = [Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
            $null = $chain.Add($publicCertificate)
            $null = $chain.Add($acceptanceRoot)
            $null = $chain.Add($acceptanceIntermediate)
            [IO.File]::WriteAllBytes($Destination, $chain.Export(
                [Security.Cryptography.X509Certificates.X509ContentType]::Pkcs7
            ))
        }
        Mock Import-ArtifactSigningTrust {}
        Mock Get-FileHash { [pscustomobject] @{ Hash = 'test-msi-hash' } } -ParameterFilter {
            $LiteralPath -like '*.msi'
        }
    }

    It 'downloads CA files and discovers the subject without trusting certificates or building' {
        $download = Invoke-LocalArtifactSigning @testParameters -DownloadCertificates

        $download.SignerSubject | Should -BeExactly $publicCertificate.Subject
        $download.RootCertificatePath | Should -Exist
        @($download.IntermediateCertificatePath).Count | Should -Be 1
        $intermediate = Get-ArtifactSigningCaCertificate -Path $download.IntermediateCertificatePath[0]
        try { $intermediate.Thumbprint | Should -Be $acceptanceIntermediate.Thumbprint }
        finally { $intermediate.Dispose() }
        Should -Invoke Import-ArtifactSigningTrust -Times 0
        Should -Invoke Invoke-NativeTool -Times 0 -ParameterFilter { $Tool -ne 'az' }
        Should -Invoke Set-AzContext -Times 1 -Exactly -ParameterFilter { $Scope -eq 'Process' }
        Should -Invoke Get-AzArtifactSigningCertificateRoot -Times 1 -Exactly -ParameterFilter {
            $AccountName -eq $testParameters.AccountName -and
            $ProfileName -eq $testParameters.CertificateProfileName -and
            $EndpointUrl -eq $testParameters.Endpoint
        }
    }

    It 'explicitly loads the installed download module when command discovery cannot autoload it' {
        Mock Get-Command { @() } -ParameterFilter {
            $Name -contains 'Get-AzArtifactSigningCertificateRoot' -or
                $Name -contains 'Get-AzArtifactSigningCertificateChain'
        }

        $download = Invoke-LocalArtifactSigning @testParameters -DownloadCertificates

        $download.RootCertificatePath | Should -Exist
        Should -Invoke Import-Module -Times 1 -Exactly -ParameterFilter { $Name -contains 'Az.ArtifactSigning' }
    }

    It 'reports the real module import failure instead of asking to reinstall an installed module' {
        Mock Import-Module { throw 'Required assembly could not be loaded' } -ParameterFilter {
            $Name -contains 'Az.ArtifactSigning'
        }

        { Invoke-LocalArtifactSigning @testParameters -DownloadCertificates } |
            Should -Throw '*Required assembly could not be loaded*'

        Should -Invoke Set-AzContext -Times 0
        Should -Invoke Get-AzArtifactSigningCertificateRoot -Times 0
    }

    It 'does not overwrite downloaded certificates without Force' {
        $null = Invoke-LocalArtifactSigning @testParameters -DownloadCertificates
        $rootPath = Join-Path $testParameters.CertificateDirectory 'profile-root.cer'
        $original = (Get-FileHash -LiteralPath $rootPath).Hash

        { Invoke-LocalArtifactSigning @testParameters -DownloadCertificates } | Should -Throw '*already exists*'

        (Get-FileHash -LiteralPath $rootPath).Hash | Should -Be $original
        Should -Invoke Get-AzArtifactSigningCertificateRoot -Times 1 -Exactly
    }

    It 'uses only explicitly approved CA files and verifies the signed MSI after building' {
        $download = Invoke-LocalArtifactSigning @testParameters -DownloadCertificates

        $result = Invoke-LocalArtifactSigning @testParameters -Force `
            -TrustedRootCertificatePath $download.RootCertificatePath `
            -IntermediateCertificatePath $download.IntermediateCertificatePath

        Should -Invoke Import-ArtifactSigningTrust -Times 1 -Exactly -ParameterFilter {
            $RootCertificateBase64 -ceq [Convert]::ToBase64String($acceptanceRoot.RawData) -and
            $IntermediateCertificatesBase64 -ceq [Convert]::ToBase64String($acceptanceIntermediate.RawData)
        }
        Should -Invoke Invoke-NativeTool -Times 1 -Exactly -ParameterFilter {
            $ToolArguments -contains '-Force' -and $ToolArguments[2] -like '*\build.ps1' -and
            $ToolArguments -contains $testParameters.AccountName -and
            $ToolArguments -contains $testParameters.CertificateProfileName -and
            $ToolArguments -contains $testParameters.Endpoint -and
            $ToolArguments -contains $testParameters.ExpectedSignerSubject
        }
        Should -Invoke Invoke-NativeTool -Times 1 -Exactly -ParameterFilter {
            $ToolArguments[2] -like '*\verify.ps1' -and $ToolArguments -contains '-ExpectedSignerSubject'
        }
        $result.MsiPath | Should -BeLike '*\out\*.msi'
        $result.SHA256 | Should -Be 'test-msi-hash'
    }

    It 'does not change trust when CAs are already installed' {
        $null = Invoke-LocalArtifactSigning @testParameters

        Should -Invoke Import-ArtifactSigningTrust -Times 0
        Should -Invoke Set-AzContext -Times 0
        Should -Invoke Import-Module -Times 0 -ParameterFilter { $Name -contains 'Az.ArtifactSigning' }
    }

    It 'stops after a failed build rather than verifying or reporting an old MSI as successful' {
        Mock Invoke-NativeTool { throw 'Signing failed' } -ParameterFilter {
            $ToolArguments[2] -like '*\build.ps1'
        }

        { Invoke-LocalArtifactSigning @testParameters -Force } | Should -Throw '*Signing failed*'

        Should -Invoke Invoke-NativeTool -Times 0 -ParameterFilter { $ToolArguments[2] -like '*\verify.ps1' }
        Should -Invoke Get-FileHash -Times 0 -ParameterFilter { $LiteralPath -like '*.msi' }
    }

    It 'keeps different profiles certificates in separate default cache directories' {
        $testParameters.Remove('CertificateDirectory')
        $testParameters.ProjectRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))

        $first = Invoke-LocalArtifactSigning @testParameters -DownloadCertificates
        $testParameters.CertificateProfileName = 'another-profile'
        $second = Invoke-LocalArtifactSigning @testParameters -DownloadCertificates

        $first.RootCertificatePath | Should -Exist
        $second.RootCertificatePath | Should -Exist
        $first.RootCertificatePath | Should -Not -Be $second.RootCertificatePath
    }

    It 'checks an expected subject retained in configuration when downloading again' {
        $testParameters.ExpectedSignerSubject = 'CN=Different publisher'

        { Invoke-LocalArtifactSigning @testParameters -DownloadCertificates } |
            Should -Throw '*Expected subject*Different publisher*'

        Should -Invoke Import-ArtifactSigningTrust -Times 0
        Should -Invoke Invoke-NativeTool -Times 0 -ParameterFilter { $Tool -ne 'az' }
    }
}

Describe 'Signing input validation' -Skip:(-not $IsWindows) {
    It 'rejects a certificate without a private key before building' {
        { & $buildPath -SigningCertificate $publicCertificate -Force } |
            Should -Throw '*must have an accessible private key*'
    }

    It 'rejects an expired certificate before building' {
        { & $buildPath -SigningCertificate $expiredCertificate -Force } |
            Should -Throw '*not currently valid*'
    }

    It 'rejects a certificate without Code Signing usage before building' {
        { & $buildPath -SigningCertificate $nonSigningCertificate -Force } |
            Should -Throw '*must have the Code Signing enhanced key usage*'
    }

    It 'rejects unsupported timestamp URL <Url>' -ForEach @(
        @{ Url = 'https://timestamp.example.test' }
        @{ Url = 'timestamp.example.test' }
        @{ Url = 'file:///C:/timestamp' }
    ) {
        { & $buildPath -SigningCertificate $certificate -TimestampServer $Url -Force } |
            Should -Throw '*TimestampServer must be an absolute http:// URL*'
    }

    It 'rejects invalid Key Vault certificate URI <Id>' -ForEach @(
        @{ Id = 'https://test.vault.azure.net/certificates/signing' }
        @{ Id = 'http://test.vault.azure.net/certificates/signing/0123456789abcdef0123456789abcdef' }
        @{ Id = 'https://test.vault.azure.net/certificates/signing/latest' }
        @{ Id = 'https://test.vault.azure.net/certificates/signing/0123456789abcdef0123456789abcdef?extra=true' }
        @{ Id = 'https://user:password@test.vault.azure.net/certificates/signing/0123456789abcdef0123456789abcdef' }
    ) {
        { & $buildPath -KeyVaultCertificateId $Id -Force } |
            Should -Throw '*KeyVaultCertificateId must be a versioned HTTPS certificate URI*'
    }

    It 'rejects invalid Artifact Signing endpoint <Endpoint>' -ForEach @(
        @{ Endpoint = 'http://neu.codesigning.azure.net' }
        @{ Endpoint = 'https://neu.codesigning.azure.net/extra' }
        @{ Endpoint = 'https://example.test' }
        @{ Endpoint = 'https://user:password@neu.codesigning.azure.net' }
    ) {
        {
            & $buildPath -ArtifactSigningEndpoint $Endpoint -ArtifactSigningAccountName 'test-account' `
                -ArtifactSigningCertificateProfileName 'test-profile' -ExpectedSignerSubject 'CN=Test' `
                -SignToolPath 'unused.exe' -ArtifactSigningDlibPath 'unused.dll' -Force
        } | Should -Throw '*ArtifactSigningEndpoint must be a regional HTTPS endpoint*'
    }

    It 'rejects selecting local and Artifact Signing together' {
        {
            & $buildPath -SigningCertificate $certificate -ArtifactSigningEndpoint 'https://neu.codesigning.azure.net' `
                -ArtifactSigningAccountName 'test-account' -ArtifactSigningCertificateProfileName 'test-profile' `
                -ExpectedSignerSubject 'CN=Test' -SignToolPath 'unused.exe' -ArtifactSigningDlibPath 'unused.dll' -Force
        } | Should -Throw '*Parameter set cannot be resolved*'
    }
}

Describe 'Artifact Signing tool cache' -Skip:(-not $IsWindows) {
    BeforeEach {
        $fixtureDirectory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $cacheDirectory = Join-Path $fixtureDirectory 'cache'
        $workDirectory = Join-Path $fixtureDirectory 'work'
        $null = New-Item -ItemType Directory -Path $cacheDirectory, $workDirectory -Force
        $source = Join-Path $fixtureDirectory 'package-content'
        $null = New-Item -ItemType Directory -Path (Join-Path $source 'bin\x64') -Force
        Set-Content -LiteralPath (Join-Path $source 'bin\x64\signtool.exe') -Value 'verified tool'
        Set-Content -LiteralPath (Join-Path $source 'bin\x64\companion.dll') -Value 'required dependency'
        $fixture = Join-Path $fixtureDirectory 'fixture.zip'
        [IO.Compression.ZipFile]::CreateFromDirectory($source, $fixture)
        $dependency = [pscustomobject] @{
            url = 'https://packages.example.test/signing-tools.1.0.nupkg'
            sha256 = (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash
            toolPath = 'bin\x64\signtool.exe'
        }
        Mock Invoke-WebRequest { Copy-Item -LiteralPath $fixture -Destination $OutFile }
    }

    It 'downloads a verified archive and extracts the tool with its adjacent dependencies' {
        $tool = Get-ArtifactSigningTool -Dependency $dependency `
            -CacheDirectory $cacheDirectory -WorkDirectory $workDirectory

        Get-Content -LiteralPath $tool | Should -Be 'verified tool'
        Get-Content -LiteralPath (Join-Path (Split-Path -Parent $tool) 'companion.dll') |
            Should -Be 'required dependency'
        Should -Invoke Invoke-WebRequest -Times 1 -Exactly -ParameterFilter { $Uri -eq $dependency.url }
    }

    It 'uses the verified cached archive offline and never reuses modified extracted binaries' {
        $first = Get-ArtifactSigningTool -Dependency $dependency `
            -CacheDirectory $cacheDirectory -WorkDirectory $workDirectory
        Set-Content -LiteralPath $first -Value 'modified extracted tool'
        $nextWorkDirectory = Join-Path $fixtureDirectory 'next-build'
        $null = New-Item -ItemType Directory -Path $nextWorkDirectory

        $next = Get-ArtifactSigningTool -Dependency $dependency `
            -CacheDirectory $cacheDirectory -WorkDirectory $nextWorkDirectory

        Get-Content -LiteralPath $next | Should -Be 'verified tool'
        Should -Invoke Invoke-WebRequest -Times 1 -Exactly
    }

    It 'refuses a tampered cached archive before extracting any executable' {
        Set-Content -LiteralPath (Join-Path $cacheDirectory 'signing-tools.1.0.nupkg') -Value 'tampered'

        { Get-ArtifactSigningTool -Dependency $dependency `
            -CacheDirectory $cacheDirectory -WorkDirectory $workDirectory } |
            Should -Throw '*SHA-256 mismatch for cached file*'

        @(Get-ChildItem -LiteralPath $workDirectory).Count | Should -Be 0
        Should -Invoke Invoke-WebRequest -Times 0
    }

    It 'cleans up a hash-mismatched download instead of caching or extracting it' {
        $dependency.sha256 = '0' * 64

        { Get-ArtifactSigningTool -Dependency $dependency `
            -CacheDirectory $cacheDirectory -WorkDirectory $workDirectory } |
            Should -Throw '*SHA-256 mismatch*'

        @(Get-ChildItem -LiteralPath $cacheDirectory).Count | Should -Be 0
        @(Get-ChildItem -LiteralPath $workDirectory).Count | Should -Be 0
    }

    It 'rejects a package missing the expected x64 tool' {
        $dependency.toolPath = 'bin\x64\missing.dll'

        { Get-ArtifactSigningTool -Dependency $dependency `
            -CacheDirectory $cacheDirectory -WorkDirectory $workDirectory } |
            Should -Throw '*does not contain the expected x64 tool*'
    }
}

Describe 'Artifact Signing runtime prerequisites' -Skip:(-not $IsWindows) {
    BeforeEach {
        $runtime = [pscustomobject] @{
            DotNetVersions = @('8.0.34')
            VisualCppInstalled = $true
        }
        Mock Get-ArtifactSigningRuntimeStatus { $runtime }
    }

    It 'accepts a supported x64 runtime <Version>' -ForEach @(
        @{ Version = '8.0.34' }
        @{ Version = '9.0.23' }
    ) {
        $runtime.DotNetVersions = @($Version)

        Assert-ArtifactSigningPrerequisites
    }

    It 'explains how to install the runtime when no supported stable x64 runtime exists' {
        $runtime.DotNetVersions = @('7.0.20', '8.0.0-preview.7')

        { Assert-ArtifactSigningPrerequisites } | Should -Throw '*x64 .NET runtime 8.0 or newer*'
    }

    It 'rejects an absent x64 runtime even when PowerShell itself can run' {
        $runtime.DotNetVersions = @()

        { Assert-ArtifactSigningPrerequisites } | Should -Throw '*x64 .NET runtime 8.0 or newer*'
    }

    It 'explains how to install a missing x64 Visual C++ runtime' {
        $runtime.VisualCppInstalled = $false

        { Assert-ArtifactSigningPrerequisites } | Should -Throw '*x64 Visual C++ v14 Redistributable*'
    }
}

Describe 'Artifact Signing' -Skip:(-not $IsWindows) {
    BeforeEach {
        $msiPath = Join-Path $TestDrive 'package.msi'
        $signing = @{
            Path = $msiPath
            Endpoint = 'https://neu.codesigning.azure.net/'
            AccountName = 'test-account'
            CertificateProfileName = 'test-profile'
            ExpectedSignerSubject = $certificate.Subject
            ExpectedProfileEku = $profileEku
            SignToolPath = 'C:\Signing Tools\signtool.exe'
            DlibPath = 'C:\Signing Tools\Azure.CodeSigning.Dlib.dll'
        }
        $signature = [pscustomobject] @{
            Status = 'Valid'
            StatusMessage = 'Verified'
            SignerCertificate = $certificate
            TimeStamperCertificate = $certificate
        }
        $script:observedMetadata = $null
        $script:observedMetadataPath = $null
        Mock Invoke-NativeTool {
            $script:observedMetadataPath = $ToolArguments[10]
            $script:observedMetadata = Get-Content -LiteralPath $script:observedMetadataPath -Raw | ConvertFrom-Json
        }
        Mock Get-AuthenticodeSignature { $signature }
    }

    It 'selects the exact account/profile, excludes alternate identities, and timestamps with SHA-256 by default' {
        Invoke-ArtifactMsiSigning @signing

        $script:observedMetadata.Endpoint | Should -Be $signing.Endpoint
        $script:observedMetadata.CodeSigningAccountName | Should -Be 'test-account'
        $script:observedMetadata.CertificateProfileName | Should -Be 'test-profile'
        $script:observedMetadata.ExcludeCredentials | Should -Contain 'EnvironmentCredential'
        $script:observedMetadata.ExcludeCredentials | Should -Contain 'WorkloadIdentityCredential'
        $script:observedMetadata.ExcludeCredentials | Should -Contain 'ManagedIdentityCredential'
        $script:observedMetadata.ExcludeCredentials | Should -Not -Contain 'AzureCliCredential'
        Should -Invoke Invoke-NativeTool -Times 1 -Exactly -ParameterFilter {
            $Tool -eq $signing.SignToolPath -and
            ($ToolArguments -join '|') -eq "sign|/fd|SHA256|/tr|http://timestamp.acs.microsoft.com|/td|SHA256|/dlib|$($signing.DlibPath)|/dmdf|$script:observedMetadataPath|$msiPath"
        }
        $script:observedMetadataPath | Should -Not -Exist
        Should -Invoke Get-AuthenticodeSignature -Times 1 -Exactly
    }

    It 'passes an explicitly selected RFC 3161 service' {
        Invoke-ArtifactMsiSigning @signing -TimestampServer 'https://timestamp.example.test'

        Should -Invoke Invoke-NativeTool -Times 1 -Exactly -ParameterFilter {
            $ToolArguments[4] -eq 'https://timestamp.example.test'
        }
    }

    It 'propagates signing failure and removes temporary metadata without accepting the MSI' {
        Mock Invoke-NativeTool {
            $script:observedMetadataPath = $ToolArguments[10]
            throw 'Artifact Signing authentication failed'
        }

        { Invoke-ArtifactMsiSigning @signing } |
            Should -Throw '*Artifact Signing authentication failed*'
        $script:observedMetadataPath | Should -Not -Exist
        Should -Invoke Get-AuthenticodeSignature -Times 0
    }

    It 'rejects an unsigned MSI even when the signing tool reports success' {
        $signature.Status = 'NotSigned'
        $signature.SignerCertificate = $null

        { Invoke-ArtifactMsiSigning @signing } | Should -Throw '*MSI signature verification failed*NotSigned*'
    }

    It 'rejects a signature from a different publisher' {
        $signing.ExpectedSignerSubject = 'CN=Another publisher'

        { Invoke-ArtifactMsiSigning @signing } | Should -Throw '*expected subject*Another publisher*'
    }

    It 'rejects a wrong durable certificate profile identity' {
        $signing.ExpectedProfileEku = '1.3.6.1.4.1.311.97.999'

        { Invoke-ArtifactMsiSigning @signing } | Should -Throw '*expected Artifact Signing profile EKU*'
    }

    It 'rejects a missing timestamp instead of publishing a short-lived signature' {
        $signature.TimeStamperCertificate = $null

        { Invoke-ArtifactMsiSigning @signing } | Should -Throw '*does not contain the requested timestamp*'
    }

    It 'rejects a certificate without Code Signing usage' {
        $signature.SignerCertificate = $nonSigningCertificate

        { Invoke-ArtifactMsiSigning @signing } | Should -Throw '*does not have the Code Signing enhanced key usage*'
    }

    It 'verifies a publisher without requiring an optional profile EKU' {
        $signing.Remove('ExpectedProfileEku')

        Invoke-ArtifactMsiSigning @signing

        Should -Invoke Get-AuthenticodeSignature -Times 1 -Exactly
    }
}

Describe 'Key Vault signing' -Skip:(-not $IsWindows) {
    BeforeEach {
        $certificateId = 'https://test.vault.azure.net/certificates/signing/0123456789abcdef0123456789abcdef'
        $msiPath = Join-Path $TestDrive 'package.msi'
        $signature = [pscustomobject] @{
            Status = 'Valid'
            StatusMessage = 'Verified'
            SignerCertificate = $certificate
            TimeStamperCertificate = $null
        }
        $credentialBeforeTest = [Environment]::GetEnvironmentVariable('AZURE_TOKEN_CREDENTIALS', 'Process')
        [Environment]::SetEnvironmentVariable('AZURE_TOKEN_CREDENTIALS', 'EnvironmentCredential', 'Process')
        $script:observedCredential = $null
        Mock Invoke-NativeTool {
            $script:observedCredential = [Environment]::GetEnvironmentVariable('AZURE_TOKEN_CREDENTIALS', 'Process')
        }
        Mock Get-AuthenticodeSignature { $signature }
    }

    AfterEach {
        [Environment]::SetEnvironmentVariable('AZURE_TOKEN_CREDENTIALS', $credentialBeforeTest, 'Process')
    }

    It 'pins the certificate version and uses only the existing CLI login for SHA-256 signing' {
        Invoke-KeyVaultMsiSigning -Path $msiPath -CertificateId $certificateId -Certificate $certificate -Tool 'signer.exe'

        Should -Invoke Invoke-NativeTool -Times 1 -Exactly -ParameterFilter {
            $Tool -eq 'signer.exe' -and
            ($ToolArguments -join '|') -eq "sign|-kvu|https://test.vault.azure.net|-kvc|signing|-kvcv|0123456789abcdef0123456789abcdef|-kvm|-fd|sha256|$msiPath"
        }
        $script:observedCredential | Should -Be 'AzureCliCredential'
        [Environment]::GetEnvironmentVariable('AZURE_TOKEN_CREDENTIALS', 'Process') |
            Should -Be 'EnvironmentCredential'
        Should -Invoke Get-AuthenticodeSignature -Times 1 -Exactly
    }

    It 'requests an RFC 3161 timestamp with SHA-256 and accepts HTTPS' {
        $signature.TimeStamperCertificate = $certificate

        Invoke-KeyVaultMsiSigning -Path $msiPath -CertificateId $certificateId -Certificate $certificate `
            -Tool 'signer.exe' -TimestampServer 'https://timestamp.example.test'

        Should -Invoke Invoke-NativeTool -Times 1 -Exactly -ParameterFilter {
            ($ToolArguments -join '|') -like '*|-tr|https://timestamp.example.test|-td|sha256|*'
        }
    }

    It 'restores credential selection and propagates a signer failure without verifying success' {
        Mock Invoke-NativeTool { throw 'signer.exe failed with exit code 1.' }

        { Invoke-KeyVaultMsiSigning -Path $msiPath -CertificateId $certificateId -Certificate $certificate -Tool 'signer.exe' } |
            Should -Throw '*signer.exe failed with exit code 1*'
        [Environment]::GetEnvironmentVariable('AZURE_TOKEN_CREDENTIALS', 'Process') |
            Should -Be 'EnvironmentCredential'
        Should -Invoke Get-AuthenticodeSignature -Times 0
    }

    It 'rejects a missing requested timestamp after remote signing' {
        { Invoke-KeyVaultMsiSigning -Path $msiPath -CertificateId $certificateId -Certificate $certificate `
                -Tool 'signer.exe' -TimestampServer 'http://timestamp.example.test' } |
            Should -Throw '*does not contain the requested timestamp*'
    }

    It 'retrieves the exact public certificate version without requiring a local private key' {
        Mock Invoke-NativeTool {
            @{
                id = $certificateId
                cer = [Convert]::ToBase64String($certificate.Export(
                    [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert
                ))
            } | ConvertTo-Json -Compress
        }

        $public = Get-KeyVaultSigningCertificate -CertificateId $certificateId
        try {
            $public.HasPrivateKey | Should -BeFalse
            $public.Thumbprint | Should -Be $certificate.Thumbprint
            Assert-CodeSigningCertificate -Certificate $public
        }
        finally { $public.Dispose() }
        Should -Invoke Invoke-NativeTool -Times 1 -Exactly -ParameterFilter {
            $Tool -eq 'az' -and
            ($ToolArguments -join '|') -eq "keyvault|certificate|show|--id|$certificateId|--query|{id:id,cer:cer}|--output|json|--only-show-errors"
        }
    }

    It 'rejects metadata from a different certificate version' {
        Mock Invoke-NativeTool {
            @{ id = 'https://test.vault.azure.net/certificates/signing/ffffffffffffffffffffffffffffffff' } |
                ConvertTo-Json -Compress
        }

        { Get-KeyVaultSigningCertificate -CertificateId $certificateId } |
            Should -Throw '*Key Vault returned a different certificate version*'
    }
}

Describe 'MSI signing' -Skip:(-not $IsWindows) {
    BeforeEach {
        $msiPath = Join-Path $TestDrive 'package.msi'
        $signature = [pscustomobject] @{
            Status = 'Valid'
            StatusMessage = 'Verified'
            SignerCertificate = $certificate
            TimeStamperCertificate = $null
        }
        Mock Set-AuthenticodeSignature { $signature }
        Mock Get-AuthenticodeSignature { $signature }
    }

    It 'signs with SHA-256 and verifies the requested signer without timestamping by default' {
        Invoke-MsiSigning -Path $msiPath -Certificate $certificate

        Should -Invoke Set-AuthenticodeSignature -Times 1 -Exactly -ParameterFilter {
            $LiteralPath -eq $msiPath -and $Certificate -eq $certificate -and
            $HashAlgorithm -eq 'SHA256' -and $IncludeChain -eq 'NotRoot' -and
            -not $TimestampServer
        }
        Should -Invoke Get-AuthenticodeSignature -Times 1 -Exactly -ParameterFilter {
            $LiteralPath -eq $msiPath
        }
    }

    It 'requests and verifies a timestamp when supplied' {
        $signature.TimeStamperCertificate = $certificate

        Invoke-MsiSigning -Path $msiPath -Certificate $certificate -TimestampServer 'http://timestamp.example.test'

        Should -Invoke Set-AuthenticodeSignature -Times 1 -Exactly -ParameterFilter {
            $TimestampServer -eq 'http://timestamp.example.test'
        }
    }

    It 'rejects a failed signing result' {
        Mock Set-AuthenticodeSignature {
            [pscustomobject] @{ Status = 'NotTrusted'; StatusMessage = 'Untrusted test signer' }
        }

        { Invoke-MsiSigning -Path $msiPath -Certificate $certificate } |
            Should -Throw '*MSI signing failed: NotTrusted*Untrusted test signer*'
        Should -Invoke Get-AuthenticodeSignature -Times 0
    }

    It 'propagates signing errors instead of falling back to unsigned output' {
        Mock Set-AuthenticodeSignature { throw 'Private key access denied' }

        { Invoke-MsiSigning -Path $msiPath -Certificate $certificate } |
            Should -Throw '*Private key access denied*'
        Should -Invoke Get-AuthenticodeSignature -Times 0
    }

    It 'rejects an invalid signature on readback' {
        Mock Get-AuthenticodeSignature {
            [pscustomobject] @{
                Status = 'HashMismatch'
                StatusMessage = 'File changed'
                SignerCertificate = $certificate
            }
        }

        { Invoke-MsiSigning -Path $msiPath -Certificate $certificate } |
            Should -Throw '*MSI signature verification failed*HashMismatch*'
    }

    It 'rejects a different signer on readback' {
        Mock Get-AuthenticodeSignature {
            [pscustomobject] @{
                Status = 'Valid'
                StatusMessage = 'Different signer'
                SignerCertificate = [pscustomobject] @{ Thumbprint = 'OTHER' }
            }
        }

        { Invoke-MsiSigning -Path $msiPath -Certificate $certificate } |
            Should -Throw '*MSI signature verification failed*'
    }

    It 'rejects a missing signer on readback' {
        $signature.SignerCertificate = $null

        { Invoke-MsiSigning -Path $msiPath -Certificate $certificate } |
            Should -Throw '*MSI signature verification failed*'
    }

    It 'rejects a missing requested timestamp even when signing reports success' {
        { Invoke-MsiSigning -Path $msiPath -Certificate $certificate -TimestampServer 'http://timestamp.example.test' } |
            Should -Throw '*does not contain the requested timestamp*'
    }
}

Describe 'Windows MSI signing integration' -Skip:(-not $IsWindows -or -not $IntegrationMsiPath) {
    It 'signs a real MSI but refuses to accept an untrusted signer' {
        $msiPath = Join-Path $TestDrive 'untrusted.msi'
        Copy-Item -LiteralPath $IntegrationMsiPath -Destination $msiPath

        { Invoke-MsiSigning -Path $msiPath -Certificate $certificate } |
            Should -Throw '*MSI signing failed*'

        $actual = Get-AuthenticodeSignature -LiteralPath $msiPath
        $actual.Status | Should -BeIn @('NotTrusted', 'UnknownError')
        $actual.SignerCertificate.Thumbprint | Should -Be $certificate.Thumbprint
    }
}
