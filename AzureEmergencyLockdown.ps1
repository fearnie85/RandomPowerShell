<#
.Synopsis
    Emergency Lockout Process...

.DESCRIPTION
    This script finds users who have been locked out in the last few minutes and then;
    
    1 - Disables Accounts
    2 - Revokes Signin Sessions
    3 - Changes password...
    4 - Assigns any registered apps to manager...

.DIRECTIONS
    This script is intended to be scheduled. No inputs are required for this script to run.

.AUTHOR
    Steven James Fearn
    steven.fearn@softwareone.com

.PERMISSIONS NEEDED
    Microsoft Graph;
        Application.ReadWrite.All
        AuditLog.Read.All
        Directory.Read.All
        Directory.ReadWrite.All
        Policy.Read.All
        User.Read
        User.ReadWrite.All

.VERSION
    v1.0 - 10/12/2023

.VERSION HISTORY
    ENTER CHANGES HERE!!! - follow this example for version history = V #Major. #Minor #DATE(mm/DD/yyyy) eg, V1.2 10/12/2023
    #EXAMPLE
    V1.1 - 10/12/2023 - Minor Update - Added Write-Output for RevokeSignInSessions...
    V1.2 - 10/12/2023 - Minor Update - Corrected a typo in the Write-Output of RevokeSignInSessions
    V2.0 - 10/12/2023 - Major Update - Expanded on RevokeSignInSessions to list the available sessions, and only Revoke the recent signins.
    V3.0 - 10/12/2023 - Major Update - Expanded on the tool to include the removal of assigned devices.
    #EndofExample.



#>

# Logging
## Change logfile for the location of the logs.
### uncomment when scheduling CTRL+F find #TEST and then remove.

#TEST $timestamp = Get-Date -Format "yyyyMMdd_HHmm"
#TEST $logFile   = ".\Logs\log_$timestamp.txt"
#TEST Start-Transcript -Path $logFile -Append

### Global Variables ###
## change $filesec for path of the encrypted CLIXML 

$FileSec      = Import-Clixml -Path ".\Dependencies\Secured.xml"
$clientId     = $FileSec.clientId
$clientSecret = $FileSec.clientSecret
$tenantId     = $FileSec.tenantId
$ODataPassSec = $FileSec.OmadaAPIpass | ConvertTo-SecureString -AsPlainText -Force
$ODataUser    = "###DOMAIN###\###USER###"

### Functions used ###
# GetGraphToken - used to generate a Token from MS Graph.
# GenerateRandomPassword - used to generate a random password string.

#region FUNCTIONS

function GetGraphToken {
    try {
        $token = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Body @{
            client_id = $clientId
            scope = "https://graph.microsoft.com/.default"
            client_secret = $clientSecret
            grant_type = "client_credentials"
        }
        $global:tokenExpires = (Get-Date).AddSeconds($token.expires_in - 1000)
        return $token.access_token
    } catch {
        Write-Error "Error fetching token: $_"
        throw $_
    }
} # Endof GetGraphToken Function

function GenerateRandomPassword {
    param (
        [Parameter(Mandatory=$true)][int]$Length,
        [Parameter(Mandatory=$true)][int]$NumberCount,
        [Parameter(Mandatory=$true)][int]$SpecialCharCount
    )

    if ($NumberCount + $SpecialCharCount > $Length)
    { Write-Error "The sum of NumberCount and SpecialCharCount exceeds the total Length."
      throw "The sum of NumberCount and SpecialCharCount exceeds the total Length."
    }

    $lowercase = 'abcdefghijklmnopqrstuvwxyz' ; $uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' ; $numbers = '0123456789' ; $specialChars = '!@#$%^&+[]{}|?'
    $password = -join ($lowercase | Get-Random -Count ($Length - $NumberCount - $SpecialCharCount))
    $password += -join ($uppercase | Get-Random -Count ($Length - $NumberCount - $SpecialCharCount))
    $password += -join ($numbers | Get-Random -Count $NumberCount)
    $password += -join ($specialChars | Get-Random -Count $SpecialCharCount)

    return (-join ($password.ToCharArray() | Get-Random -Count $Length))
} # Endof GenerateRandomPassword Function

#endregion

# Omada API bit...
$BSTR            = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ODataPassSec)
$ODataPass       = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
$Minutes         = 30
$currentdate     = (Get-Date).AddMinutes(-$Minutes).ToString("yyyy-MM-ddTHH:mm:ssZ")
$headersOmadaAPI = @{ 'Accept' = 'application/json' ; 'Authorization' = "Basic $authB64" ; 'Content-Type' = 'application/json' }
$uriGetId        = "http://###OMADA_API###.local/OData/DataObjects/Identity?$filter=IDENTITYSTATUS/Value eq 'Locked' and C_LOCKOUTTIMESTAMP gt $currentdate"
$query           = (Invoke-RestMethod -Uri $uriGetId -Method Get -Headers $headersOmadaAPI).value | Select-Object EMAIL

if ($query -ne $null)
{
    foreach ($item in $query.email)
    {
        $emailAddress = $item
        $token = GetGraphToken
        $headers = @{ Authorization = "Bearer $token" ; "Content-Type" = "application/json" }
        $graphUrl = "https://graph.microsoft.com/v1.0/users?$filter=mail eq '$emailAddress'"

        try {

            $user = (Invoke-RestMethod -Method Get -Uri $graphUrl -Headers $headers).value | where { $_.mail -like "$emailAddress" }
            $userid = $user.id
            $bodyPatch = (@{ AccountEnabled = $false }) | ConvertTo-Json
            $GetUser = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/users/$userid" -Headers $headers

            # Disable Account #
            if ($GetUser.AccountEnabled -eq $true){ Invoke-RestMethod -Method Patch -Uri "https://graph.microsoft.com/beta/users/$userid" -Headers $headers -Body $bodyPatch ; Write-Output "Disabled user $userid" }
            else { Write-Output "$GetUser.displayName is not enabled... Skipping..." }

            # Revoke Signins #
            Invoke-RestMethod -Method Post -Uri "https://graph.microsoft.com/v1.0/users/$userid/revokeSignInSessions" -Headers $headers
            Write-Output "Revoked sign-in sessions for user $userid"

            # Change Password bit #
            $Newpassword = GenerateRandomPassword -Length 15 -NumberCount 3 -SpecialCharCount 4 ; $bodyPassword = @{ passwordProfile = @{ password = $Newpassword ; forceChangePasswordNextSignIn = $true } } | ConvertTo-Json      
            Invoke-RestMethod -Method Patch -Uri "https://graph.microsoft.com/v1.0/users/$userId" -Headers $headers -Body $bodyPassword ; Write-Output "Password changed for user $userid" 

            # Reassign any owned apps #
            $manager = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$userId/manager" -Headers $headers

            if ($manager -ne $null)
            {
                $TheManager = $manager.id ; $apps = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$userId/ownedObjects" -Method Get -Headers $headers).value

                if ($apps -ne $null)
                {
                    foreach ($app in $apps)
                    { 
                    
                        $APPNAME = $app.displayName ; $ManagerName = $manager.displayName ; $AppID = $app.id

                        Write-Output "Application Named: $APPNAME - found assigned to user $userid. Assigning to manager - $TheManager"

                        # Remove user as owner
                        $Duri    = "https://graph.microsoft.com/v1.0/applications/$AppID/owners/$userid/`$ref"
                        try { Invoke-RestMethod -Uri $Duri -Method Delete -Headers $headers ; Write-Output "Removed user $userid as owner of app $AppID" }
                        catch { Write-Error "Error removing user $userid as owner of app $AppID $_" }

                        # Add manager as owner
                        $bodyPUT = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/users/$TheManager" } | ConvertTo-Json
                        $Puri    = "https://graph.microsoft.com/v1.0/applications/$AppID/owners/`$ref"
                        try { Invoke-RestMethod -Uri $Puri -Method Post -Headers $headers -Body $bodyPUT ; Write-Output "Assigned app $AppID to manager $TheManager" }
                        catch { Write-Error "Error assigning app $AppID to manager $TheManager $_" }

                    } # End of for each App...
                } # end of IF has apps...
            } # end of IF manager...
            else { Write-Output "Manager is null for user $userid... Skipping..." }
        } # end of TRY
        catch {  Write-Error "Error processing user $emailAddress $_" }
    } # end of foreach user to lock out!
} # end of IF the Query is not NULL
else {  Write-Output "No users to process..." }

           
#TEST Stop-Transcript

