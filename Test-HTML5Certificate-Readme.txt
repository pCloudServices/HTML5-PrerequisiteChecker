#########################################################################
#                                                                    	  #
#                                                                    	  #
#   Test-HTML5Certificate          									 	                  #
#                                                                    	  #
#   Script to help with creation of certificates and            		    #
#   configuration of Remote Desktop Services for Remote Access          #
#                                                                    	  #
#                                          		         		     	        #
#########################################################################

  .EXAMPLES
  PS C:\> .\Test-HTML5Certificate.ps1 -TestCertificate [-SetCertificate]
  PS C:\> .\Test-HTML5Certificate.ps1 -CreateCertificates -ConnectorServers (Servers to generate certificates for and export as PFX) [-SubjectAlternativeNames (additional FQDNs to include in the certificate, such as for load-balancers)]
  PS C:\> .\Test-HTML5Certificate.ps1 -InstallCertificate -CertificateFile (PFX file to install)

The script is provided in a zip file containing:
 - Readme.txt file.
 - Test-HTML5Certificate.ps1 - script to run
================================================

Mandatory parameters:
  When testing a certificate
    - TestCertificate - Run the script in the TestCertificate operating mode
  When creating new certificates
	  - CreateCertificates - Run in CreateCertificates operating mode
    - ConnectorServers - A comma-separated list of server names. The script will generate a certificate for each server and export it to the script location.
  To install a generated certificate
    - InstallCertificate - Run in InstallCertificate operating mode
    - CertificateFile - Path of a PFX file which will be installed and RDS configured to use

Optional parameters:
  When testing a certificate
    - SetCertificate - Configure RDS to use the certificate selected for testing
  When creating new certificates
    - SubjectAlternativeNames - A comma-separated list of subject alternate names that will be added to each certificate
    - ValidityYears - The number of years in the future for which generated certificates should be valid. Default: 20 years
    - KeyLength - The length in bits of the private key for the certificate. Default: 4096
    - CertificateFriendlyName - A friendly name for the certificate to help identity its purpose in the future. Default: CyberArk Session Management RDP Certificate

