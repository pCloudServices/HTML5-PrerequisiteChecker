# Test-HTML5Certificate

## Information
Script to assist in testing of certificates for suitability, creation of certificates and configuration of Remote Desktop Services

The script is provided in a zip file containing:
- Readme.md file
- Test-HTML5Certificate.ps1 - script to run

## Usage
The script has three operating modes.

TestCertificate mode will:
- Prompt the user to select the certificate to test for suitability
- Test the selected certificate
- Optionally configure RDS to use the selected certificate

Example syntax:  
`PS C:\> .\Test-HTML5Certificate.ps1 -TestCertificate`

CreateCertificates mode will:
- Create a self-signed signing certificate if it does not already exist
  - This certificate must be provided to your CyberArk representative
- Create a certificate for each server specified in -ConnectorServers

Example syntax:  
`PS C:\> .\Test-HTML5Certificate.ps1 -CreateCertificates -ConnectorServers <comma-separated list of connector servers>`

InstallCertificate mode will:
- Import a PFX file into the Windows certificate store
- Configure Remote Desktop Services to use the imported certificate

Example syntax:  
`PS C:\> .\Test-HTML5Certificate.ps1 -InstallCertificate -CertificateFile <path to pfx file to install>`

The script will prompt for a password to use to export and import the PFX files for the second and third operating modes respectively.

## Parameters
### When testing certificates
#### Mandatory Parameters

| Parameter       | Description                            |
| --------------- | -------------------------------------- |
| TestCertificate | Run the script in TestCertificate mode |

#### Optional Parameters
| Parameter      | Description                                   |
| -------------- | --------------------------------------------- |
| SetCertificate | Configure RDS to use the selected certificate |

#### When generating certificates
#### Mandatory Parameters

| Parameter          | Description                                                          |
| ------------------ | -------------------------------------------------------------------- |
| CreateCertificates | Run the script in CreateCertificates mode                            |
| ConnectorServers   | A comma-separated list of servers for which to generate certificates |

### Optional Parameters

| Parameter               | Valid values               | Description                                                                                                                          |
| ----------------------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| SubjectAlternativeNames | Fully-qualified host names | A comma-separated list of subject alternate names that will be added to each certificate                                             |
| ValidityYears           | Whole numbers              | The number of years in the future for which generated certificates should be valid. Default: 20 years                                |
| KeyLength               | 1024, 2048, 4096           | The length in bits of the private key for the certificate. Default: 4096                                                             |
| CertificateFriendlyName | Alphanumeric String        | A friendly name for the certificate to help identity its purpose in the future. Default: CyberArk Session Management RDP Certificate |

### When installing certificates
#### Mandatory Parameters

| Parameter          | Description                                                 |
| ------------------ | ----------------------------------------------------------- |
| InstallCertificate | Run the script in InstallCertificate mode                   |
| CertificateFile    | The path to the PFX file of the certificate to be installed |
