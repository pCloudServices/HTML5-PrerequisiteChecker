[CmdletBinding()]
param (
    [Parameter(Mandatory = $true,
        ParameterSetName = 'TestCertificate',
        HelpMessage = 'Test a certificate for suitability for use with RDS')]
    [Switch]$TestCertificate
    ,
    [Parameter(Mandatory = $true,
    ParameterSetName = 'CreateCertificates',
    HelpMessage = 'Create certificates for servers')]
    [Switch]$CreateCertificates
    ,
    [Parameter(Mandatory = $true,
        ParameterSetName = 'InstallCertificate',
        HelpMessage = 'Install certificate from a PFX file and configure RDS')]
    [Switch]$InstallCertificate
    ,

    [Parameter(Mandatory = $false,
        ParameterSetName = 'TestCertificate',
        HelpMessage = 'A comma-separated list of names of the connector servers for which to create certificates')]
    [Switch]$SetCertificate
    ,

    [Parameter(Mandatory = $true,
        ParameterSetName = 'InstallCertificate',
        HelpMessage = 'A comma-separated list of names of the connector servers for which to create certificates')]
    [String]$CertificateFile
    ,

    [Parameter(Mandatory = $true,
        ParameterSetName = 'CreateCertificates',
        HelpMessage = 'A comma-separated list of names of the connector servers for which to create certificates')]
    [String[]]$ConnectorServers
    ,
    [Parameter(Mandatory = $false,
        ParameterSetName = 'CreateCertificates',
        HelpMessage = 'Alternative names for the connector servers; e.g. the FQDNs of load balancers used by these servers. Default: none')]
    [Parameter(Mandatory = $false)]
    [String[]]$SubjectAlternativeNames = @()
    ,
    [Parameter(Mandatory = $false,
        ParameterSetName = 'CreateCertificates',
        HelpMessage = 'The number of years the certificate should be valid. Default: 20')]
    [Int]$ValidityYears = 20
    ,
    [Parameter(Mandatory = $false,
        ParameterSetName = 'CreateCertificates',
        HelpMessage = 'Length of the RSA key for the generated certificates. Default: 4096 bits')]
    [Int]$KeyLength = 4096
    ,
    [Parameter(Mandatory = $false,
        ParameterSetName = 'CreateCertificates',
        HelpMessage = 'The friendly name assigned to the generated certificate to help with future identification. Default: CyberArk Session Management RDP Certificate')]
    [String]$CertificateFriendlyName = "CyberArk Session Management RDP Certificate"
)

Function Write-LogMessage {
    <# 
.SYNOPSIS 
	Method to log a message on screen and in a log file

.DESCRIPTION
	Logging The input Message to the Screen and the Log File. 
	The Message Type is presented in colours on the screen based on the type

.PARAMETER LogFile
	The Log File to write to. By default using the LOG_FILE_PATH
.PARAMETER MSG
	The message to log
.PARAMETER Header
	Adding a header line before the message
.PARAMETER SubHeader
	Adding a Sub header line before the message
.PARAMETER Footer
	Adding a footer line after the message
.PARAMETER Type
	The type of the message to log (Info, Warning, Error, Debug)
#>
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [String]$MSG,
        [Parameter(Mandatory = $false)]
        [Switch]$Header,
        [Parameter(Mandatory = $false)]
        [Switch]$Early,
        [Parameter(Mandatory = $false)]
        [Switch]$SubHeader,
        [Parameter(Mandatory = $false)]
        [Switch]$Footer,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Debug", "Verbose", "Success", "LogOnly")]
        [String]$type = "Info",
        [Parameter(Mandatory = $false)]
        [String]$LogFile = $LOG_FILE_PATH
    )
    Try {
        If ($Header) {
            "=======================================" | Out-File -Append -FilePath $LogFile 
            Write-Host "=======================================" -ForegroundColor Magenta
        }
        ElseIf ($SubHeader) { 
            "------------------------------------" | Out-File -Append -FilePath $LogFile 
            Write-Host "------------------------------------" -ForegroundColor Magenta
        }
		
        $msgToWrite = "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t"
        $writeToFile = $true
        # Replace empty message with 'N/A'
        if ([string]::IsNullOrEmpty($Msg)) { $Msg = "N/A" }
		
        # Mask Passwords
        if ($Msg -match '((?:password|credentials|secret)\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=([\w`~!@#$%^&*()-_\=\+\\\/|;:\.,\[\]{}]+))') {
            $Msg = $Msg.Replace($Matches[2], "****")
        }
        # Check the message type
        switch ($type) {
            { ($_ -eq "Info") -or ($_ -eq "LogOnly") } { 
                If ($_ -eq "Info") {
                    Write-Host $MSG.ToString() -ForegroundColor $(If ($Header -or $SubHeader) { "magenta" } Elseif ($Early) { "DarkGray" } Else { "White" })
                }
                $msgToWrite += "[INFO]`t$Msg"
            }
            "Success" { 
                Write-Host $MSG.ToString() -ForegroundColor Green
                $msgToWrite += "[SUCCESS]`t$Msg"
            }
            "Warning" {
                Write-Host $MSG.ToString() -ForegroundColor Yellow
                $msgToWrite += "[WARNING]`t$Msg"
            }
            "Error" {
                Write-Host $MSG.ToString() -ForegroundColor Red
                $msgToWrite += "[ERROR]`t$Msg"
            }
            "Debug" { 
                if ($InDebug -or $InVerbose) {
                    Write-Debug $MSG
                    $msgToWrite += "[DEBUG]`t$Msg"
                }
                else { $writeToFile = $False }
            }
            "Verbose" { 
                if ($InVerbose) {
                    Write-Verbose -Msg $MSG
                    $msgToWrite += "[VERBOSE]`t$Msg"
                }
                else { $writeToFile = $False }
            }
        }

        If ($writeToFile) { $msgToWrite | Out-File -Append -FilePath $LogFile }
        If ($Footer) { 
            "=======================================" | Out-File -Append -FilePath $LogFile 
            Write-Host "=======================================" -ForegroundColor Magenta
        }
    }
    catch {
        Throw $(New-Object System.Exception ("Cannot write message"), $_.Exception)
    }
}

Function CheckCertificate {
    param($certToCheck)
    $errorCount = 0
    $certToCheck.Thumbprint
    $hasPrivateKey = $certToCheck.HasPrivateKey
    if (!$hasPrivateKey) {
        $errorCount++
        Write-Warning "We couldn't detect a private key installed for this certificate. This certifiate can't be used."
    }

    $certHasExpired = $certToCheck.NotAfter -lt (Get-Date)
    if ($certHasExpired) {
        $errorCount++
        Write-Warning "This certificate has expired. This certificate can't be used"
    }

    $certNotValidYet = $certToCheck.NotBefore -gt (Get-Date)
    if ($certNotValidYet) {
        $errorCount++
        Write-Warning "This certificate isn't yet valid. This certificate can't be used"
    }

    $certMissingKeyUsage = $certToCheck.EnhancedKeyUsageList.ObjectId -contains "1.3.6.1.5.5.7.3.1"
    if (!$certMissingKeyUsage) {
        $errorCount++
        Write-Warning "This certificate appears to be missing the `"Server Authentication`" Enhanced Key Usage. This certificate can't be used"
    }

    $certMissingDnsName = $certToCheck.DnsNameList -contains ([system.net.dns]::GetHostByName("localhost")).hostname
    if (!$certMissingDnsName) {
        $errorCount++
        Write-Warning "This certificate doesn't appear to match the hostname of the machine. This certificate can't be used"
    }

    if ($errorCount -gt 0) {
        Write-Error "This certificate can't currently be used - please review the warning messages above"
    }
    else {
        Write-Host "This certificate passed the checks and looks ready to use."
    }
}

$global:InVerbose = $PSBoundParameters.Verbose.IsPresent
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path
$global:LOG_FILE_PATH = "$ScriptLocation\_Test-HTML5Certificate.log"

$CertStoreLocation = "Cert:\LocalMachine\My\"

Write-LogMessage -type LogOnly "Script started."

If ($TestCertificate) {
    $selectedCert = Get-ChildItem Cert:\LocalMachine\My | Select-Object -Property * | Out-GridView -PassThru -Title "Select the certificate to use for PSM"
    CheckCertificate $selectedCert
    
    if ($SetCertificate) {
        # This won't run if errorCount is greater than 0, as that generates an Error and will end execution
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if (!$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Error "Will not attempt to set the certificate. Must be running as administrator to update the RDS certificate"
        }
    
        Write-Host "Attempting to set certificate for use in RDS.."
        $CimInstance = Get-CimInstance -ClassName Win32_TSGeneralSetting -Namespace ROOT\CIMV2\TerminalServices
        $thumb = $selectedCert.Thumbprint
        Set-CimInstance -CimInstance $CimInstance -property @{SSLCertificateSHA1Hash = $thumb } -PassThru
    }
}
ElseIf ($InstallCertificate) {
    # We are installing an existing certificate
    $CertificateImportPassword = Read-Host -AsSecureString -Prompt "Please enter a password for encrypting the private keys of the exported certificates"
    try {
        $CertificateObject = Import-PfxCertificate -CertStoreLocation $CertStoreLocation -FilePath $CertificateFile -Password $CertificateImportPassword -Exportable:$false
    }
    catch {
        Write-LogMessage -type Error -MSG ("Import of certificate failed. Please ensure it is a valid certificate, Powershell is running as an administrator and that the encryption passphrase is correct. Error: {0}" -f $_.Exception.Message)
        exit 1
    }
    $Thumbprint = $CertificateObject.Thumbprint

    try {
        $session = Get-CimInstance -ClassName Win32_TSGeneralSetting -Namespace ROOT\CIMV2\TerminalServices
        $Result = Set-CimInstance -CimInstance $session -property @{SSLCertificateSHA1Hash = $Thumbprint } -PassThru
    }
    catch {
        Write-LogMessage -type Error -MSG ("Failed to configure RDS to use the newly generated certificate. Error: {0}" -f $_.Exception.Message)
        try {
            Remove-Item $CertificateObject.PSPath
        }
        catch {
            Write-LogMessage -type Error -MSG ("Could not remove generated certificate. Please delete manually before trying to run script again. Thumbprint: {0}; Error: {1}" -f $CertificateObject.Thumbprint, $_.Exception.Message)
        }
        exit 1
    }

    If ($Result.SSLCertificateSHA1Hash -like "$Thumbprint") {
        Write-LogMessage -type Info -MSG "Successfully configured RDS to use the newly generated certificate"
    }
    else {
        Write-LogMessage -type Error -MSG ("Failed to set RDP certificate. Error: {0}" -f $_.Exception.Message)
        try {
            Remove-Item $CertificateObject.PSPath
        }
        catch {
            Write-LogMessage -type Error -MSG ("Could not remove generated certificate. Please delete manually before trying to run script again. Thumbprint: {0}; Error: {1}" -f $CertificateObject.Thumbprint, $_.Exception.Message)
        }
        exit 1
    }
    Write-LogMessage -type Info -MSG ("{0} should now be deleted." -f $CertificateFile)
}
ElseIf ($CreateCertificates) {
    $CertificateExportPassword = Read-Host -AsSecureString -Prompt "Please enter a password for encrypting the private keys of the exported certificates"
    # We are generating (or using) a CA, generating new certificates, using the CA to sign them and exporting them
    # Search for and generate CA certificate if required
    $CACertificateObject = Get-ChildItem $CertStoreLocation | Where-Object Subject -like "CN=CyberArk Session Management CA"

    If ($null -eq $CACertificateObject) {
        $PromptQuestion = ("No Certificate Authority information was provided.`nShould a new Certificate Authority be generated now?")
    
        $PromptOptions = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
        $PromptOptions.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList "&Yes", "Generate a new CA Certificate now"))
        $PromptOptions.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList "&No", "Exit the script so that the CA information can be provided"))
    
        $CAPromptSelection = $Host.UI.PromptForChoice("", $PromptQuestion, $PromptOptions, 1)
        If ($CAPromptSelection -eq 0) {
            Write-LogMessage -Type Info "New CA Certificate will be generated"
        }
        Else {
            Write-LogMessage -Type Error -MSG "Cancelled. Please run this script on the server where the CA has been created, or create a new CA"
            exit 1
        }
        # Generate a CA
        $CACertificateArguments = @{
            DnsName           = "CyberArk Session Management CA"
            FriendlyName      = "CyberArk Session Management CA"
            HashAlgorithm     = 'SHA256'
            NotAfter          = (Get-Date).AddYears(25)
            KeyAlgorithm      = 'RSA'
            KeyLength         = 4096
            CertStoreLocation = 'Cert:\LocalMachine\My'
            KeyUsage          = 'CertSign', 'CRLSign'
        }
        $CACertificateObject = New-SelfSignedCertificate @CACertificateArguments
        $GeneratedCACertificate = $true
    }
    $CACertificateRawData = $CACertificateObject.RawData
    $CACertificateOutputPath = ("$ScriptLocation\{0}-CA.crt" -f $env:COMPUTERNAME)
    $CACertificateBase64Format = @(
        "-----BEGIN CERTIFICATE-----",
        ([convert]::ToBase64String($CACertificateRawData, "InsertLineBreaks")),
        "-----END CERTIFICATE-----"
    )

    Set-Content -Path $CACertificateOutputPath -Value $CACertificateBase64Format -Encoding Ascii

    # CA generation and export completed
    # Move to new certificate generation and signing

    $NotAfter = (Get-Date).AddYears($ValidityYears)

    # Generate and export certificate and key for each connector server
    ForEach ($ConnectorServerName in $ConnectorServers) {
        # Add the connector server name and SANs together
        $DnsNames = @($ConnectorServerName) + $SubjectAlternativeNames
        
        # Set arguments for the New-SelfSignedCertificate command
        $CertificateArguments = @{
            DnsName           = $DnsNames 
            CertStoreLocation = $CertStoreLocation
            TextExtension     = @("2.5.29.37={text}1.3.6.1.5.5.7.3.1") 
            KeyLength         = $KeyLength 
            NotAfter          = $NotAfter 
            FriendlyName      = $CertificateFriendlyName
            Signer            = $CACertificateObject
        }
    
        try {
            # Generate the cert and store in $CertificateObject
            $CertificateObject = New-SelfSignedCertificate @CertificateArguments
        }
        catch {
            Write-LogMessage -type Error -MSG "Failed to generate new self-signed certificate. Error: {0}" -f $_.Exception.Message
            exit 1
        }
        try {
            $null = Export-PfxCertificate -Cert $CertificateObject -FilePath "$ScriptLocation\$ConnectorServerName.pfx" -Password $CertificateExportPassword
        }
        catch {
            Write-LogMessage -type Error -MSG "Failed to export certificate for {0}. Error: {1}" -f $ConnectorServerName, $_.Exception.Message
        }
        try {
            $null = Remove-Item $CertificateObject.PSPath
        }
        catch {
            Write-LogMessage -type Error -MSG "Failed to delete generated certificate for {0}. Error: f{1}" -f $ConnectorServerName, $_.Exception.Message
        }
        Write-LogMessage -type Info -MSG "Generated, issued and exported certificate for $ConnectorServerName"
    }

    If ($GeneratedCACertificate) {
        Write-LogMessage -type Info -MSG ("New CA Certificate was generated and its public certificate exported to {0}" -f $CACertificateOutputPath)
    }
    else {
        Write-LogMessage -type Info -MSG ("Used existing CA and exported its public certificate to {0}" -f $CACertificateOutputPath)
    }
    Write-LogMessage -type Info -MSG "Please provide this file or the Base64 output below to CyberArk support"
    Write-LogMessage -type Info -MSG ($CACertificateBase64Format -join "`n")
    
    Write-LogMessage -type Info -MSG "Certificates were generated for the following systems:"
    ForEach ($ConnectorServerName in $ConnectorServers) {
        Write-LogMessage -type Info -MSG "- $ConnectorServerName"
    }
    Write-LogMessage -type Info -MSG "Copy this script and the generated certificates to each of those servers and run this script with the -InstallCertificate option."
    Write-LogMessage -type Info -MSG "Note: It's recommended to delete the exported certificates once they have been imported."
}
Write-LogMessage -type LogOnly "Script ended."
