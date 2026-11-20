# Unofficial PowerShell 7 MSI

This project builds an unofficial x64 MSI for PowerShell 7.7.0. Leave it
unsigned or sign it with your own local certificate, Azure Key Vault certificate,
or Microsoft Artifact Signing profile. It packages Microsoft's release ZIP
using installer authoring adapted from PowerShell 7.6.10.
Microsoft does not produce this installer.

The MSI uses the original x64 stable `UpgradeCode` and installation directory.
**Installing it is intended to replace an older official PowerShell 7 MSI**, not
to install alongside it. Building the MSI does not change your installed version.
Test installation, upgrades, repairs, and uninstall in a disposable Windows VM
before deployment.

## Choose how to build

Build on a Windows machine or in your organization's GitHub repository.
Signing is optional. Supply your own certificate or Azure signing configuration;
this project does not issue production certificates.

| Execution | Signing method | Where to get the MSI |
| --- | --- | --- |
| Local `build.ps1` | None (default) | Unsigned MSI in local `out` |
| Local `build.ps1 -SigningCertificate ...` | Your PFX or Windows certificate-store certificate | Signed MSI in local `out` |
| Local `build.ps1 -KeyVaultCertificateId ...` | Your Azure Key Vault certificate and key | Signed MSI in local `out` |
| Local `build.ps1 -ArtifactSigningEndpoint ...` | Your Microsoft Artifact Signing profile | Signed MSI in local `out` |
| GitHub Actions `build-unsigned-msi.yml` | None; builds, verifies, and runs signing/setup tests | Unsigned MSI attached to the successful workflow run |
| GitHub Actions `artifact-signing.yml` | Your Artifact Signing profile, authenticated through OIDC | Signed MSI attached to the successful workflow run |

"Local" means the build runs on your Windows machine, without GitHub Actions.
Key Vault and Artifact Signing still use Azure remotely and require network
access and an authorized Azure identity. The scripts do not upload the finished
MSI to GitHub. All local modes use the output filename shown below.

The supplied signing workflow covers Artifact Signing only. For a local
certificate or Key Vault, call `build.ps1` from your own Windows pipeline
after configuring certificate access or Azure CLI authentication.

Local Artifact Signing with a Private Trust profile has been tested successfully,
including repeat builds after installing the CA certificates. The GitHub signing
workflow has not yet been verified against the live service.

## Build

On Windows, use the latest patch of PowerShell 7.6 LTS, the oldest
Microsoft-supported release as of November 15, 2026, or a newer supported stable
release. PowerShell 7.4 and 7.5 both reached end of support on November 10, 2026.
See [Microsoft's support lifecycle](https://learn.microsoft.com/powershell/scripting/install/powershell-support-lifecycle#powershell-end-of-support-dates).
The scripts require at least PowerShell 7.2 to run, but that version is no
longer supported by Microsoft. Use a supported release.

Every `.ps1` file includes comment-based help with examples. Read it without
executing the script:

```powershell
Get-Help .\build.ps1 -Full
Get-Help .\setup-artifact-signing.ps1 -Examples
```

Build an unsigned MSI:

```powershell
pwsh -NoProfile -File .\build.ps1
```

The script downloads the official PowerShell ZIP and the portable WiX 3.14.1
tools into `cache`, verifies their pinned SHA-256 hashes, and builds
`out\PowerShell-7.7.0-win-x64-unofficial.msi`. Use `-Force` to replace an
existing output after the build and any signature checks succeed. It does not
bypass certificate trust checks or file locks. The ZIP hash comes from the
[PowerShell 7.7.0 release](https://github.com/PowerShell/PowerShell/releases/tag/v7.7.0);
the WiX hash is also recorded in
[Microsoft PowerToys' WiX setup](https://github.com/microsoft/PowerToys/blob/204427d127cb098fa1624f170ed6cee13a0633cc/.pipelines/installWiX.ps1).
The script also checks the signature and version of the extracted `pwsh.exe`.
WiX installer consistency checks run with the upstream ICE40, ICE57, and
ICE61 suppressions. No .NET SDK or system-wide WiX installation is required.

Some files in the official ZIP are Microsoft-signed; repackaging and signing the
MSI do not change those files' signatures.

To verify the MSI's identity, upgrade rule, and payload without installing it:

```powershell
pwsh -NoProfile -File .\verify.ps1
```

Verification creates and removes an administrative image. It does not test
installation, upgrades, repairs, uninstall, or remoting configuration.

## Optional code signing

### Local certificate

Pass `-SigningCertificate` from a PowerShell session to sign the MSI with SHA-256.
The certificate must be currently valid, have the Code Signing enhanced key
usage and an accessible private key, and chain to a root trusted by the build
machine. Target machines must also trust its chain. Your organization becomes
the package signer, not Microsoft.

Load a password-protected PFX without putting its password on the command line:

```powershell
$certificate = Get-PfxCertificate -FilePath 'C:\Signing\codesigning.pfx'
# Get-PfxCertificate prompts for the PFX password.
.\build.ps1 -SigningCertificate $certificate
```

Or select your certificate by its exact thumbprint from the Windows certificate
store (use `Cert:\LocalMachine\My` instead if appropriate):

```powershell
$certificate = Get-Item -LiteralPath 'Cert:\CurrentUser\My\<YOUR_CERTIFICATE_THUMBPRINT>'
.\build.ps1 -SigningCertificate $certificate
```

To keep the signature verifiable after the signing certificate expires, supply
your certificate provider's Authenticode timestamp service:

```powershell
.\build.ps1 -SigningCertificate $certificate -TimestampServer 'http://timestamp.digicert.com' -Force
```

Local signing does not request a timestamp unless you supply `-TimestampServer`.
It requires `-SigningCertificate` and an `http://` URL because PowerShell's
Authenticode timestamp API does not support HTTPS or RFC 3161-only services.
Without a timestamp, signature validity is limited by the signing certificate's
lifetime.

Signing and signature verification happen before the MSI is moved to `out`.
A signing, trust, or requested timestamp failure stops the build without
publishing an unsigned fallback or replacing an existing output, even with
`-Force`. The reported SHA-256 is calculated after signing. No Windows SDK or
SignTool installation is needed.

Check the resulting signature independently:

```powershell
Get-AuthenticodeSignature -LiteralPath .\out\PowerShell-7.7.0-win-x64-unofficial.msi |
    Format-List Status, StatusMessage, SignerCertificate, TimeStamperCertificate
```

Keep PFX files and passwords outside this repository; do not commit private keys.

### Azure Key Vault certificate

Use `-KeyVaultCertificateId` instead of `-SigningCertificate` to sign remotely
with a certificate in Azure Key Vault. The key can be non-exportable.
The script reads the public certificate and signs through Key Vault without
retrieving a secret or downloading the private key.

Install [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli)
and authenticate to the appropriate tenant/subscription before building.
The script uses only that existing CLI login. It does not log in, provision
resources, create credentials, or fall back to another Azure identity. A CI
pipeline can establish its CLI session using its own managed identity or
federated identity before running the build.

The signing identity needs permission to read the certificate and sign with
its associated key (`certificates/get` and `keys/sign`). With Azure RBAC, use
appropriately scoped Key Vault Reader and Key Vault Crypto User assignments.
Certificate creation and administration require separate permissions.

Resolve the desired certificate version, then build:

```powershell
$certificateId = az keyvault certificate show `
    --vault-name '<YOUR_VAULT_NAME>' --name '<YOUR_CERTIFICATE_NAME>' `
    --query id --output tsv
if ($LASTEXITCODE -ne 0) { throw 'Could not resolve the Key Vault certificate.' }

.\build.ps1 -KeyVaultCertificateId $certificateId `
    -TimestampServer 'http://timestamp.digicert.com' -Force
```

The ID must include an exact version:
`https://<vault>.vault.azure.net/certificates/<name>/<version>`.
The script reads and signs with that same version and verifies the resulting
signer thumbprint against its public certificate. This prevents a renewal
from changing the certificate partway through the build.
Local and Key Vault signing cannot be selected together.

For Key Vault signing, `-TimestampServer` is an optional HTTP or HTTPS
RFC 3161 service; both the MSI signature and timestamp digest use SHA-256.
There is no default timestamp service. The HTTP-only legacy Authenticode
timestamp restriction above applies only to local signing.

The script downloads the pinned, SHA-256-verified
[AzureSignTool 8.0.0 x64 executable](https://github.com/vcsjones/AzureSignTool/releases/tag/v8.0.0)
into `cache` only when Key Vault signing is selected. Its checksum is recorded
in `dependencies.json` from the release asset digest. This standalone executable
needs no .NET SDK or Windows SDK installation. AzureSignTool is an open-source
tool, distinct from Microsoft's Artifact Signing service.

The certificate must have Code Signing enhanced key usage, be currently valid,
and chain to a root trusted by the build and target machines. A default TLS
certificate or an untrusted self-signed test certificate is not sufficient.
Follow your CA's certificate issuance and HSM requirements.
Storing a certificate in Key Vault does not make it publicly trusted.
For certificate enrollment, see Microsoft's
[Key Vault CSR workflow](https://learn.microsoft.com/en-us/azure/key-vault/certificates/create-certificate-signing-request).

Key Vault authentication, signing, trust, and requested timestamp failures stop
the build without publishing an unsigned fallback or replacing existing output.
Signature verification, payload verification, and installation instructions are
the same as for local signing.

### Microsoft Artifact Signing

Local Private Trust signing has been tested against the live service. Automated
tests cover argument construction, identity checks, mandatory timestamping,
cleanup, and failure handling with mocked signing. Test your own profile before
distributing packages; the GitHub signing workflow still needs live acceptance.

The organization supplies an Artifact Signing account, completed identity
validation, and a Public Trust or Private Trust code-signing certificate profile.
CI Policy and VBS enclave profiles are not MSI-signing profiles.
Assign its signing identity the Artifact Signing Certificate Profile Signer role, scoped to the intended
profile. Public Trust and Private Trust availability depend on Microsoft's
onboarding requirements; a private profile is not a workaround for eligibility.
The build machine and recipients must trust the resulting chain.

#### Local download-and-sign workflow

Use the shared `local-artifact-signing.ps1` helper to download certificates, build,
sign, and verify. It has no built-in subscription, account, profile, or publisher.
Run these commands from the repository root, using the Windows and runtime
prerequisites described under [Tools and authentication](#tools-and-authentication).

Set your account details:

```powershell
$signing = @{
    SubscriptionId = '<SUBSCRIPTION_ID>'
    Endpoint = '<YOUR_REGIONAL_CODESIGNING_ENDPOINT>'
    AccountName = '<YOUR_ACCOUNT>'
    CertificateProfileName = '<YOUR_PROFILE>'
}
```

Replace `<YOUR_REGIONAL_CODESIGNING_ENDPOINT>` with your account's actual endpoint.
For example, `https://neu.codesigning.azure.net/` is only for North Europe.
For the first download, install the
download module once and authenticate both Azure CLI and Azure PowerShell if
you have not already done so:

```powershell
Install-Module Az.ArtifactSigning -Scope CurrentUser
az login --tenant '<TENANT_ID>'
if ($LASTEXITCODE -ne 0) { throw 'Azure CLI login failed.' }
Connect-AzAccount -Tenant '<TENANT_ID>' -Subscription $signing.SubscriptionId

$certificates = .\local-artifact-signing.ps1 @signing -DownloadCertificates
$signing.ExpectedSignerSubject = $certificates.SignerSubject
```

The download does not install certificates. It prints CA file paths and SHA-256
fingerprints, exports the intermediates, and returns the exact Windows signer
subject. Have the profile owner verify the CA fingerprints before trusting them.

For Private Trust, import the approved CA files and build the signed MSI:

```powershell
.\local-artifact-signing.ps1 @signing `
    -TrustedRootCertificatePath $certificates.RootCertificatePath `
    -IntermediateCertificatePath $certificates.IntermediateCertificatePath `
    -Force
```

For Public Trust, or when the CAs are already installed for your Windows user,
omit both CA path parameters:

```powershell
.\local-artifact-signing.ps1 @signing -Force
```

The helper creates the signed, timestamped MSI in `out`, then verifies its signature,
expected publisher, timestamp, installer properties, and complete payload.
`-Force` permits replacing an existing MSI after the build's signature checks
succeed. Omit it if there is no existing output. It does not bypass trust checks.
Signing uses Azure CLI only; Azure PowerShell is needed only for downloading
certificates.

To keep your settings across PowerShell sessions without committing them, save
them under the ignored `.local` directory:

```powershell
New-Item -ItemType Directory -Path .\.local -Force | Out-Null
$signing | ConvertTo-Json | Set-Content -LiteralPath .\.local\artifact-signing.json -Encoding utf8
```

For later runs, including when a signed MSI already exists:

```powershell
$signing = Get-Content -LiteralPath .\.local\artifact-signing.json -Raw | ConvertFrom-Json -AsHashtable
.\local-artifact-signing.ps1 @signing -Force
```

There is no need to download or import CAs again for the same Windows user unless
the CA chain changes. Routine signing-certificate rotation does not require CA
reinstallation. To refresh existing certificate downloads, use
`.\local-artifact-signing.ps1 @signing -DownloadCertificates -Force`; review any
changed CA fingerprints before importing them.

The sections below explain the equivalent manual steps. You do not need to
repeat them after using the helper.

#### Trust the profile's CA before building

**The Windows account running the build must trust the profile's root CA.**
The certificate chain must also be complete, including any required intermediate
CAs. Azure signing permission alone is not enough.

| Machine | Public Trust | Private Trust |
| --- | --- | --- |
| Local Windows | Normally trusted through Windows updates; install missing CA certificates if needed | Configure CA trust explicitly |
| GitHub-hosted Windows runner | Normally already trusted | The workflow retrieves and imports the profile's CA certificates automatically |

Installing a CA locally does not configure a GitHub-hosted runner.
The manual steps below are for local builds; the GitHub workflow configures its
own runner's trust automatically.
Test profiles can also need explicit trust setup.

Obtain the correct root and intermediate certificates from your organization's
PKI administrator or Microsoft's documentation for the profile. Verify their
fingerprints through a trusted source before installing them. Put the root in
Trusted Root Certification Authorities and intermediates in Intermediate
Certification Authorities, using the build account's stores or an
organization-managed machine-wide deployment. Recipients need the same trust.
Do not install the signer's leaf certificate as a trusted root.

To download the root and certificate chain for your Artifact Signing profile,
use the `Az.ArtifactSigning` Azure PowerShell module. This is separate from the
`ArtifactSigning` signing module. It is needed only for these download commands,
not for `build.ps1`.

```powershell
Install-Module Az.ArtifactSigning -Scope CurrentUser
New-Item -ItemType Directory -Path 'C:\Signing' -Force | Out-Null

# Azure PowerShell authentication is separate from az login.
Connect-AzAccount -Tenant '<TENANT_ID>' -Subscription '<SUBSCRIPTION_ID>'

$profileParameters = @{
    AccountName = '<YOUR_ACCOUNT>'
    ProfileName = '<YOUR_PROFILE>'
    EndpointUrl = '<YOUR_REGIONAL_CODESIGNING_ENDPOINT>'
}

Get-AzArtifactSigningCertificateRoot @profileParameters -Destination 'C:\Signing\profile-root.cer'

Get-AzArtifactSigningCertificateChain @profileParameters -Destination 'C:\Signing\profile-chain.der'
```

Use the same regional endpoint as your build. These commands download public
certificates, not private keys, and do not install them into a trust store.
See Microsoft's
[`Get-AzArtifactSigningCertificateRoot`](https://learn.microsoft.com/powershell/module/az.artifactsigning/get-azartifactsigningcertificateroot)
and
[`Get-AzArtifactSigningCertificateChain`](https://learn.microsoft.com/powershell/module/az.artifactsigning/get-azartifactsigningcertificatechain)
documentation.

The chain file contains several certificates, not a single intermediate `.cer`.
Open it in Windows Certificate Manager, select each required intermediate CA,
and choose **All Tasks > Export > DER encoded binary X.509 (.CER)**.
For the example below, save the required intermediate as
`C:\Signing\profile-intermediate.cer`. Repeat for any additional intermediates.
Do not import the whole chain into the root store.

For local builds, import any missing CA certificates after independently
verifying them. Skip this step if Windows already trusts the chain:

```powershell
# Trusts this CA for the current Windows user. Review it before importing.
Import-Certificate -FilePath 'C:\Signing\profile-root.cer' -CertStoreLocation 'Cert:\CurrentUser\Root'
# Only if the profile's chain requires this intermediate certificate:
Import-Certificate -FilePath 'C:\Signing\profile-intermediate.cer' -CertStoreLocation 'Cert:\CurrentUser\CA'
```

See [`Import-Certificate`](https://learn.microsoft.com/powershell/module/pki/import-certificate)
for certificate-store options and
[Artifact Signing trust models](https://learn.microsoft.com/azure/artifact-signing/concept-trust-models)
for how trust differs by profile.

`build.ps1` does not install CA certificates or change trust settings.
If SignTool reports success but verification says the chain ends in an
untrusted root, signing succeeded remotely but Windows rejected the signature
locally. The build deliberately stops without moving the MSI to `out`, and
leaves any previous output unchanged. Install the approved CA chain and rerun.
**Do not comment out `Assert-MsiSignature` or bypass verification.**
The timestamp certificate's chain must also be trusted.

#### Read the signer subject

Before the first build, read the signing certificate's exact subject from the
downloaded chain. This does not install any certificates:

```powershell
$chain = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
$chain.Import('C:\Signing\profile-chain.der')
$signers = @($chain | Where-Object {
    $constraints = $_.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' }
    $eku = $_.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' }
    -not ($constraints -and $constraints.CertificateAuthority) -and
        $eku -and '1.3.6.1.5.5.7.3.3' -in $eku.EnhancedKeyUsages.Value
})
if ($signers.Count -ne 1) { throw 'Expected one code-signing leaf certificate in the profile chain.' }
$expectedSignerSubject = $signers[0].Subject
$expectedSignerSubject
```

Keep `$expectedSignerSubject` for the build and setup examples below.
Use the complete subject, not a friendly publisher name or a CA's subject.
For an existing signed MSI, read its
`(Get-AuthenticodeSignature -LiteralPath '<MSI_PATH>').SignerCertificate.Subject`
instead.

#### Tools and authentication

Use Windows 10 version 1809 or newer, Windows 11, or Windows Server 2016 or newer
for Artifact Signing. These are signing-host requirements, not the MSI's target
OS requirements.

For command-line builds, the script downloads pinned
`Microsoft.Windows.SDK.BuildTools` and `Microsoft.ArtifactSigning.Client` NuGet
archives into `cache` only when this backend is selected. Versions, URLs, and
SHA-256 hashes are recorded in `dependencies.json`. Each build checks the
archives' hashes, extracts fresh copies into its temporary directory, and
resolves the matching x64 SignTool and dlib paths.
No PowerShell signing module, NuGet CLI, or full Windows SDK installation is
needed.

Install the x64 .NET runtime 8.0 or newer and the current x64 Visual C++ v14
Redistributable first. The pinned client's runtime configuration allows
roll-forward to a newer .NET major version. The script checks runtime
registration and reports missing prerequisites before downloading tools or
building. It does not install system-wide runtimes, and unpacking the tools
does not require administrator access. See Microsoft's
[Artifact Signing client prerequisites](https://learn.microsoft.com/en-us/azure/artifact-signing/how-to-signing-integrations).

Install [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli)
and authenticate separately from the Azure PowerShell login above.
The generated dlib metadata uses only this CLI session:

```powershell
az login --tenant '<TENANT_ID>'
if ($LASTEXITCODE -ne 0) { throw 'Azure CLI login failed.' }
az account set --subscription '<SUBSCRIPTION_ID>'
if ($LASTEXITCODE -ne 0) { throw 'Could not select the signing subscription.' }

.\build.ps1 `
    -ArtifactSigningEndpoint '<YOUR_REGIONAL_CODESIGNING_ENDPOINT>' `
    -ArtifactSigningAccountName '<YOUR_ACCOUNT>' `
    -ArtifactSigningCertificateProfileName '<YOUR_PROFILE>' `
    -ExpectedSignerSubject $expectedSignerSubject
```

The script does not log in or accept client secrets.

To use your own approved tools, pass `-SignToolPath` and/or
`-ArtifactSigningDlibPath`. Each supplied path bypasses the corresponding
package download. Use matching x64 tools and keep all adjacent dependency files.
Runtime prerequisite checks still apply.

Select the endpoint for the account's actual Azure region. Local, Key Vault,
and Artifact Signing parameters are mutually exclusive.

Artifact Signing always requires an RFC 3161 timestamp. If `-TimestampServer`
is omitted, this backend uses `http://timestamp.acs.microsoft.com`; both digests
are SHA-256. These defaults apply only to Artifact Signing and do not change
local or Key Vault timestamp behavior. Signing remains inside the temporary
build directory; signature or timestamp failures never publish an unsigned
fallback or replace existing output, even with `-Force`.

The script requires a valid Windows signature, matching subject, Code Signing
EKU, and timestamp. Optionally pass `-ExpectedProfileEku` with the profile's
durable identity EKU (`1.3.6.1.4.1.311.97...`) to distinguish profiles belonging
to the same publisher. Use it once you know the profile's EKU.
Do not use the common Public Trust EKU `1.3.6.1.4.1.311.97.1.0` as a profile pin.
Do not pin a leaf thumbprint. Artifact Signing certificates rotate daily and
last about 72 hours.
Public Trust Test signatures expire with the signing certificate even when
timestamped.
Deleting and recreating a profile changes its durable EKU.
See [certificate management](https://learn.microsoft.com/en-us/azure/artifact-signing/concept-certificate-management).

Verify a signed MSI's identity, timestamp, and complete payload with:

```powershell
.\verify.ps1 -ExpectedSignerSubject $expectedSignerSubject
```

Add the same `-ExpectedProfileEku` if configured at signing time. Without these
options, `verify.ps1` checks only the payload and installer properties and accepts
unsigned MSIs.

## GitHub Actions

### Unsigned build and validation workflow

`.github\workflows\build-unsigned-msi.yml` (Build and test unsigned MSI) builds
an unsigned MSI, verifies its payload, and runs the signing and setup tests on
Windows for pushes and pull requests. You can also run it manually.
It catches regressions when code, installer authoring, or pinned dependencies
change.

CI has read-only repository access and needs no Azure account. Signing tests
use mocks and an untrusted test certificate; setup tests mock all cloud changes.
Neither uses an organization's production signing identity. A successful CI
run checks the build and automated tests. It does not prove that live Azure
authentication, Artifact Signing, installation, or upgrades work.

Only after verification and all tests pass does the workflow upload the MSI
as `powershell-msi-unsigned`. Failed checks stop the upload. The package is
unsigned and available for evaluation or the organization's own signing
process. It is not a production-signed release. Push and pull-request runs
produce packages from the revision under test, not necessarily the default
branch. Pester's version is pinned in `dependencies.json`.

### Opt-in Artifact Signing workflow

`.github\workflows\artifact-signing.yml` uses Microsoft's official
[Artifact Signing action](https://github.com/azure/artifact-signing-action).
It runs only when manually started on the default branch, after you enable it.
It does not run for pull requests. Actions are pinned to commit SHAs.
It calls `build.ps1` in unsigned mode, then uses the official action to sign.
The action installs the `ArtifactSigning` PowerShell module and manages its
signing tools on the runner. This is separate from local execution, which uses
cached SignTool+dlib directly without that module.
For Private Trust, the workflow retrieves the configured profile's public CA
certificates and imports them on the runner after OIDC login. The signing action
does not configure that Windows trust itself. No local `.cer` files are needed.

The workflows are independent. `artifact-signing.yml` builds its own MSI
without reusing the unsigned artifact or waiting for a successful CI run.
It does not run Pester. Before upload, it checks the signed MSI's publisher,
timestamp, optional profile EKU, installer identity, and payload.

#### One-time setup and starting runs

Use `github-artifact-signing.ps1` locally only to set up Azure/GitHub resources
and trigger runs. It delegates setup to `setup-artifact-signing.ps1`.
All certificate retrieval, CA trust configuration, MSI building, signing,
timestamping, verification, and artifact upload happen on the Windows runner.
You do not need local certificates, Windows trust configuration, MSI tools,
Azure PowerShell, or a cached PowerShell ZIP for this approach.

First, push the current workflow and supporting scripts to your remote
repository's default branch. Enable GitHub Actions if needed. The runner uses
that remote revision, not uncommitted local changes. Neither setup script
commits or pushes for you.

Setup needs the Azure and GitHub permissions described in
[Automated local setup](#automated-local-setup). Permission to sign locally is
not enough to create an Entra application and assign its signing role.
No reviewer is required by default, so you can run this yourself.

Authenticate if you have not already done so:

```powershell
gh auth login --hostname github.com
az login --tenant '<TENANT_ID>'
if ($LASTEXITCODE -ne 0) { throw 'Azure CLI login failed.' }
```

Set the repository and your existing profile's resource ID and exact signer
subject, then preview and run setup once:

```powershell
$setup = @{
    Repository = 'YOUR_ORG/YOUR_REPOSITORY'
    CertificateProfileId = '/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RESOURCE_GROUP>/providers/Microsoft.CodeSigning/codeSigningAccounts/<ACCOUNT>/certificateProfiles/<PROFILE>'
    ExpectedSignerSubject = '<EXACT_SIGNER_SUBJECT>'
}

.\github-artifact-signing.ps1 -Setup @setup -WhatIf
.\github-artifact-signing.ps1 -Setup @setup
```

The same commands work for Public Trust and Private Trust. Setup derives the
regional endpoint from the Azure account and saves the workflow configuration
in GitHub. The preview makes no cloud changes; actual setup asks for confirmation.
Add `-ExpectedProfileEku` during setup if you also want that identity check.

Start a run after setup succeeds:

```powershell
$run = .\github-artifact-signing.ps1 -Repository 'YOUR_ORG/YOUR_REPOSITORY' -Run
$run
```

Open `RunUrl` and wait for the run to finish successfully. The helper returns
the exact dispatched `RunId`, without guessing which run is latest.
An approval step is needed only if you explicitly configured reviewers. You can
also start runs from the workflow's **Run workflow** button in GitHub.
Subsequent triggers need only GitHub authentication, not a local Azure login.
Repeat setup only when its configuration changes.

Download `powershell-msi-signed` from the successful run's **Artifacts** section
if you want a local copy. Verification has already completed on the runner.
Alternatively, download with GitHub CLI:

```powershell
gh run download $run.RunId --repo 'github.com/YOUR_ORG/YOUR_REPOSITORY' `
    --name powershell-msi-signed --dir ".\out\github\$($run.RunId)"
```

#### Automated local setup

Run `setup-artifact-signing.ps1` locally to configure the organization's
repository or fork. The script uses Azure CLI, GitHub CLI, and Microsoft Graph
REST calls. It does not require Azure PowerShell or the ArtifactSigning module.
Authenticate `az` and `gh` first. It does not log in, enroll an organization,
create a signing account/profile, or complete identity validation.

Before running, you need an existing Public Trust or Private Trust code-signing
profile, its full ARM resource ID, and its exact expected certificate subject.
Reviewers are optional. To require approval by another person, supply `-Reviewer`
with up to six GitHub usernames or `ORG/TEAM-SLUG` values with repository read
access. Without `-Reviewer`, setup configures no reviewer approval.
No local CA files or certificate installation are required for either profile type.

The GitHub caller needs repository administrator access and API permissions for
environments, Actions variables, OIDC settings, and reviewer metadata. Azure
permissions must allow reading the signing account/profile, creating or
managing Entra applications/service principals and federated credentials, and
assigning the signer role at that profile. These are setup permissions; the
workflow's signing identity receives only the profile signer assignment.
The workflow file must already exist on the repository's default branch.
This script supports GitHub.com, Azure public cloud, and the default GitHub
OIDC subject formats (name-only and immutable-ID). Custom subject templates
are not supported.

```powershell
$setup = @{
    Repository = 'YOUR_ORG/YOUR_REPOSITORY'
    CertificateProfileId = '/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RESOURCE_GROUP>/providers/Microsoft.CodeSigning/codeSigningAccounts/<ACCOUNT>/certificateProfiles/<PROFILE>'
    ExpectedSignerSubject = $expectedSignerSubject
}

.\setup-artifact-signing.ps1 @setup -WhatIf
.\setup-artifact-signing.ps1 @setup
```

`-WhatIf` performs read-only prerequisite checks and previews the operation.
The actual run asks for confirmation; use `-Confirm:$false` only when the
configuration has been reviewed. Optionally supply `-ExpectedProfileEku` and/or
`-ApplicationClientId` to use a known profile EKU or an existing Entra
application. By default, the script creates or reuses a dedicated application
named from the GitHub repository ID. Rerunning does not create duplicates.
It never creates a client secret. Tenant, subscription, regional endpoint, and
account/profile names are derived from the specified Azure resource.

For Private Trust, Azure login also enables an Azure PowerShell session on the
runner. The workflow uses `Az.ArtifactSigning`, pinned in `dependencies.json`,
to retrieve the selected profile's root and certificate chain. It checks the
expected signer subject and imports the root into `Cert:\LocalMachine\Root` and
intermediates into `Cert:\LocalMachine\CA` on that temporary runner. The hosted
Windows runner has administrator privileges; machine-level imports avoid the
interactive Windows trust prompt that current-user root imports can display.
Local signing still uses current-user stores. Public Trust normally uses the
runner's existing Windows trust. This requires no local Azure PowerShell session
or certificate-store changes.

The script first disables signing, then configures the `artifact-signing`
environment to allow only the default branch. It replaces the environment's
reviewer list; omitting `-Reviewer` removes any previously required reviewers.
If reviewers are supplied, GitHub prevents self-approval. Setup removes other
branch/tag policies but keeps any existing wait timer, and checks that GitHub
enforces the requested settings before creating an identity.
If the repository's GitHub plan cannot enforce them, setup fails. Private
repositories generally require GitHub Enterprise for optional required-reviewer
protection; that feature is not needed for solo runs without reviewers.

Next it configures an Entra federated credential for issuer
`https://token.actions.githubusercontent.com`, audience
`api://AzureADTokenExchange`, and the repository's GitHub-reported subject prefix
followed by `:environment:artifact-signing`. Depending on the repository's OIDC
settings, the prefix is `repo:OWNER/REPOSITORY` or
`repo:OWNER@OWNER_ID/REPOSITORY@REPOSITORY_ID`. Rerunning setup updates an existing
credential if the subject format has changed. Setup then assigns
Artifact Signing Certificate Profile Signer at the exact profile scope.
Existing unrelated application credentials and role assignments are not
removed. Reusing an application leaves its existing permissions in place.
See Microsoft's
[OIDC configuration](https://github.com/azure/artifact-signing-action/blob/main/docs/OIDC.md).

It then writes and verifies the environment variables below, rechecks the
protections, and enables the repository variable `ENABLE_ARTIFACT_SIGNING`.
That flag stays at repository scope because the workflow checks it before
entering its environment. An omitted profile EKU removes the optional
`EXPECTED_PROFILE_EKU` environment variable if it exists. GitHub does not accept
empty variable values.
If configuration fails after changes begin, the script tries to disable signing
and reports any failure to do so. It keeps created identities and permissions
for a rerun. You may need to wait for Azure permissions to propagate before
rerunning.

Add `-Dispatch` to start the workflow on the default branch after setup.
Reviewer approval is required only if reviewers were configured.
If dispatch fails, the verified configuration stays enabled. Do not
run setup concurrently or while signing jobs are running.
Successful setup does not prove that signing works. The maintainer has not
run live setup; its tests mock all cloud operations.

| Environment variable | Value |
| --- | --- |
| `AZURE_CLIENT_ID` | Federated signing identity's client ID |
| `AZURE_TENANT_ID` | Organization's tenant ID |
| `AZURE_SUBSCRIPTION_ID` | Signing account's subscription ID |
| `ARTIFACT_SIGNING_ENDPOINT` | Correct regional HTTPS endpoint |
| `ARTIFACT_SIGNING_ACCOUNT_NAME` | Organization's signing account |
| `ARTIFACT_SIGNING_CERTIFICATE_PROFILE_NAME` | Intended certificate profile |
| `ARTIFACT_SIGNING_PROFILE_TYPE` | `PublicTrust` or `PrivateTrust`, derived by setup |
| `EXPECTED_SIGNER_SUBJECT` | Complete, exact Windows certificate subject |
| `EXPECTED_PROFILE_EKU` | Optional durable profile identity EKU |

These are configuration values, not credentials. The signing job receives
only `contents: read` and `id-token: write` GitHub permissions. Azure login
exchanges the GitHub OIDC token for an Azure session; signing excludes other
Azure credential providers. The workflow supports Azure public cloud.

The workflow builds into staging, signs only that MSI with SHA-256 and
Microsoft's RFC 3161 timestamp service, and verifies its expected signer,
optional profile EKU, timestamp, installer identity, and payload. Only then is
it moved to `out` and uploaded as `powershell-msi-signed`.
Failed verification stops publication. No unsigned fallback is uploaded.
The post-signing SHA-256 is written to the run log.

Before distributing signed packages, run the workflow in an eligible
organization's configured environment and confirm its verification succeeds.
For an optional independent check, download the artifact and run
`Get-AuthenticodeSignature` on a trusted Windows machine. Confirm `Valid`,
the intended subject/profile EKU, a populated `TimeStamperCertificate`, and the
logged SHA-256. Confirm the run's full payload verification succeeded.
The GitHub signing workflow has not yet been exercised against the live service.
Successful local signing does not replace that workflow acceptance test.

### Downloads, releases, and privacy

After a successful run, open the repository's **Actions** tab, select the run,
and download the appropriate package from its **Artifacts** section:

| Workflow name | Artifact | MSI signature |
| --- | --- | --- |
| Build and test unsigned MSI | `powershell-msi-unsigned` | Unsigned |
| Build and sign with Artifact Signing | `powershell-msi-signed` | Signed and timestamped |

Extract the downloaded archive to get the MSI. The build-and-test workflow
provides the unsigned package; the signing workflow provides only its verified
signed package.

Neither workflow creates a GitHub Release or attaches release assets.
Your organization downloads its MSI and distributes it through its own
channels. Workflow artifacts have limited retention, controlled by repository
and organization settings. Copy packages to your approved storage if you need
to keep them longer.

Skipping GitHub Releases does not make a package confidential.
Workflow artifacts follow GitHub's repository access rules. Do not treat
artifacts in a public repository as private. Use a private repository and
appropriate access controls for internal packages. GitHub Releases in a
private repository are private too. Whether to use releases is a distribution
choice, not a privacy control.

## Installation and servicing

Installing requires administrator privileges. For example, in a test VM:

```powershell
msiexec.exe /i .\out\PowerShell-7.7.0-win-x64-unofficial.msi /l*v .\powershell-msi.log
```

The legacy installer options for PATH, the event manifest, remoting, telemetry,
and Explorer context menus are retained. The manifest and remoting custom
actions fail the installation if their processes fail.

**Microsoft Update does not service this unofficial MSI.** Rebuild and deploy
new packages yourself. For new installations, the obsolete `USE_MU=1` and
`ENABLE_MU=1` properties are rejected.
Review the supported OS versions and test any required installer options before
deployment.

## Source and license

The authoring and artwork in `assets` come from
[PowerShell v7.6.10](https://github.com/PowerShell/PowerShell/tree/16ac95d24d87c61a5d8300dae2d0619db06c555c/assets/wix)
and are covered by `LICENSE-PowerShell.txt`. The authoring is modified to label
the package as unofficial, require Windows 10 version 1607/Server 2016 or later,
remove Microsoft Update integration, report custom-action failures, and shorten
an overlong tooltip.

## Local development files

The `.local` directory and everything inside it are ignored by Git. Keep personal
scripts, `notes.md`, screenshots in `images`, and local signing configuration
there. Create it with `New-Item -ItemType Directory -Path .\.local -Force` if it
does not exist. Shared scripts such as `local-artifact-signing.ps1` stay at the
repository root. Automated tests must not depend on files in `.local`.

## Signing tests

On Windows with Pester 5 installed:

```powershell
Invoke-Pester -Path .\tests\build.Tests.ps1
```

Test setup automation without creating cloud resources or changing repository
settings:

```powershell
Invoke-Pester -Path .\tests\setup.Tests.ps1
```

To also exercise native signing, pass an existing MSI. The test signs a temporary
copy with an untrusted test certificate and checks that it is rejected; it does
not modify the original MSI or any certificate store.

```powershell
$container = New-PesterContainer -Path .\tests\build.Tests.ps1 -Data @{
    IntegrationMsiPath = (Resolve-Path .\out\PowerShell-7.7.0-win-x64-unofficial.msi).Path
}
Invoke-Pester -Container $container
```
