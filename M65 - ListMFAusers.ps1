#Install-Package MSOnline
$mfaPolicies = $null
$upn = $null
$CARules = $null
$CArule = $null
    
#Auth
Connect-AzureAD
#$accessToken = Get-AzureADAccessToken
#Connect-MsolService -AzureADAccessToken $accessToken.AccessToken
Connect-MsolService

Write-Host "Finding Azure Active Directory Accounts..."
$Users = Get-MsolUser -All | Where-Object { $_.UserType -ne "Guest" }
$Report = [System.Collections.Generic.List[Object]]::new() # Create output file
Write-Host "Processing" $Users.Count "accounts..." 
ForEach ($User in $Users) {

    #CA validation
   $mfaPolicies = Get-AzureADMSConditionalAccessPolicy | Where {$_.GrantControls.BuiltInControls -contains "Mfa" -and $_.State -ne "disabled"} 
   $upn = $user.UserPrincipalName
   $aadUser = Get-AzureADUser -filter "UserPrincipalName eq '$upn'"
   $userObjectId = $aadUser.ObjectId
   $userMembership = ($aadUser | Get-AzureADUserMembership).ObjectId
   if (!$userMembership) {
     $userMembership = ""
   }
   if ($mfaPolicies | Where {
     $_.Conditions.Users.IncludeUsers -eq "All" -or `
     $_.Conditions.Users.IncludeUsers -contains $aadUser.ObjectId -or `
     (Compare-Object -ReferenceObject $_.Conditions.Users.IncludeGroups -DifferenceObject $userMembership -IncludeEqual -ErrorAction SilentlyContinue).SideIndicator -contains "==" -or `
     (Compare-Object -ReferenceObject $_.Conditions.Users.IncludeRoles -DifferenceObject $userMembership -IncludeEqual -ErrorAction SilentlyContinue).SideIndicator -contains "==" -and `
     $_.Conditions.Users.ExcludeUsers -notcontains $aadUser.ObjectId -or `
     (Compare-Object -ReferenceObject $_.Conditions.Users.ExcludeGroups -DifferenceObject $userMembership -IncludeEqual -ErrorAction SilentlyContinue).SideIndicator -contains "==" -or `
     (Compare-Object -ReferenceObject $_.Conditions.Users.ExcludeRoles -DifferenceObject $userMembership -IncludeEqual -ErrorAction SilentlyContinue).SideIndicator -contains "==" -and `
     $_.State -eq "enabled"
   }) {
    $CArule = $mfaPolicies.DisplayName
    $MFAStatus="Enabled via CA polices: $CArule"
  } else {
     $MFAStatus="Disabled"
   }
   
 #Original Script

    $MFADefaultMethod = ($User.StrongAuthenticationMethods | Where-Object { $_.IsDefault -eq "True" }).MethodType


    If ($User.StrongAuthenticationRequirements) {
        $MFAState = $User.StrongAuthenticationRequirements.State
    }
    Else {
        $MFAState = 'Disabled'
    }

    If ($MFADefaultMethod) {
        Switch ($MFADefaultMethod) {
            "OneWaySMS" { $MFADefaultMethod = "Text code authentication phone" }
            "TwoWayVoiceMobile" { $MFADefaultMethod = "Call authentication phone" }
            "TwoWayVoiceOffice" { $MFADefaultMethod = "Call office phone" }
            "PhoneAppOTP" { $MFADefaultMethod = "Authenticator app or hardware token" }
            "PhoneAppNotification" { $MFADefaultMethod = "Microsoft authenticator app" }
        }
    }
    Else {
        $MFADefaultMethod = "Not enabled"
    }
  
    $ReportLine = [PSCustomObject] @{
        UserPrincipalName = $User.UserPrincipalName
        DisplayName       = $User.DisplayName
        MFAperuser          = $MFAState
        MFADefaultMethod  = $MFADefaultMethod
        PWDLstset          = $user.LastPasswordChangeTimeStamp
        MFAviaCA           = $MFASTATUS
        z
    }
                 
    $Report.Add($ReportLine)
}

Write-Host "Report is in c:\temp\MFAUsers.csv"
$Report | Select-Object UserPrincipalName, DisplayName, MFADefaultMethod, MFAperUser,MFAviaCA,PWDLstSet  | Sort-Object UserPrincipalName | Out-GridView
$Report | Sort-Object UserPrincipalName | Export-CSV -Encoding UTF8 -NoTypeInformation c:\temp\MFAUsers.csv

<#Technical Reference:
https://www.alitajran.com/export-office-365-users-mfa-status-with-powershell/#:~:text=Navigate%20to%20Users%20%3E%20Active%20Users,MFA%20enabled%2C%20and%20MFA%20enforced.
https://thesysadminchannel.com/get-per-user-mfa-status-using-powershell/
https://www.cyberdrain.com/automating-with-powershell-enabling-secure-defaults-and-sd-explained/
https://techcommunity.microsoft.com/t5/azure/report-on-mfa-status-with-conditional-access/m-p/1420735