###########
#region ### global:Redirect-PlatformMFAUser # CMDLETDESCRIPTION : Redirects MFA authentication from one user to another or clears it :
###########
function global:Redirect-PlatformMFAUser
{
    <#
    .SYNOPSIS
    Redirects MFA authentication from one user to another. Or it clears MFA redirection on a user.

    .DESCRIPTION
	Enables redirection of MFA authentication from one user to another. Typically this is so that
	MFA authentication from a privileged account can be redirect to a user's standard account. For
	example, redirecting the account 'bsmith-adm' MFA attempts to account 'bsmith'. This helps
	consolidates MFA tokens to fewer accounts.

	This cmdlet can also be used to clear MFA redirection.

	This cmdlet requires Sysadmin level privileges on the connected PAS tenant.

    .PARAMETER User
	The user account to set redirection on. For example, 'bsmith-adm'.

	.PARAMETER RedirectMFAToUser
	The user account to redirect MFA authentication to. For example, 'bsmith'.

	.PARAMETER ClearMFARedirect
	Clears MFA redirection.
	
    .INPUTS
    None. You can't redirect or pipe input to this function.

    .OUTPUTS
    This function returns True if successful, False if it was not successful.

    .EXAMPLE
    C:\PS> Redirect-PlatformMFAUser -User "bsmith-adm@domain.com" -RedirectMFAToUser "bsmith@domain.com"
	Redirects "bsmith-adm@domain.com" MFA authentication to "bsmith@domain.com" account.

	.EXAMPLE
    C:\PS> Redirect-PlatformMFAUser -User "bsmith-adm@domain.com" -ClearMFARedirect
	Clears MFA redirection on account "bsmith-adm@domain.com".
    #>
    [CmdletBinding(DefaultParameterSetName="All")]
    param
    (
		[Parameter(Mandatory = $true, Position = 0, HelpMessage = "The PAS Sets to determine the owner", ParameterSetName = "Redirect")]
		[Parameter(Mandatory = $true, Position = 0, HelpMessage = "The PAS Sets to determine the owner", ParameterSetName = "ClearRedirect")]
		[System.String]$User,

		[Parameter(Mandatory = $true, Position = 1, HelpMessage = "The PAS Sets to determine the owner", ParameterSetName = "Redirect")]
		[System.String]$RedirectMFAToUser,

		[Parameter(Mandatory = $true, Position = 0, HelpMessage = "The PAS Sets to determine the owner", ParameterSetName = "ClearRedirect")]
		[Switch]$ClearMFARedirect
    )

    # verifying an active Platform connection
    Verify-PlatformConnection

	# first get the UUID of the target user
	Try
	{
		#$UserUUID = Get-PASObjectUuid -Type User -Name $User
        $UserUUID = Find-PlatformUser -User $User

        # if no user was found
		if ($UserUUID -eq $false)
		{
			Write-Host ("User [{0}] not found." -f $User)
			return $false
		}

        # if more than one user was found
        if ($UserUUID.Count -gt 1)
        {
            Write-Host ("More than 1 user found.  Please narrow search down to one user.")
            return $false
        }

        # setting it to just the ID
        $UserUUID = $UserUUID | Select-Object -ExpandProperty ID
	}# Try
	Catch
	{
		# if an error occurred Getting the UUID, create a new PlatformPCMException and return that with the relevant data
		$e = New-Object PlatformPCMException -ArgumentList ("Error during getting the UUID of the target user.")
		$e.AddExceptionData($_)
		$e.AddData("User",$User)
		$e.AddData("UserUUID",$UserUUID)
		$e.AddData("RedirectMFAToUser",$RedirectMFAToUser)
		return $e
	}# Catch
	
	if ($ClearMFARedirect.IsPresent)
	{
		$RedirectedUUID = $null
	}
	else
	{
		# first get the UUID of the user to redirect MFA to
		Try
		{
			#$RedirectedUUID = Get-PASObjectUuid -Type User -Name $RedirectMFAToUser
            $RedirectedUUID = Find-PlatformUser -User $RedirectMFAToUser

            # if no user was found
			if ($RedirectedUUID -eq $false)
			{
				Write-Host ("Redirected User [{0}] not found." -f $RedirectMFAToUser)
				return $false
			}

            # if more than one user was found
            if ($RedirectedUUID.Count -gt 1)
            {
                Write-Host ("More than 1 redirected user found.  Please narrow search down to one user.")
                return $false
            }

            # setting it to just the ID
            $RedirectedUUID = $RedirectedUUID | Select-Object -ExpandProperty ID
		}# Try
		Catch
		{
			# if an error occurred Getting the UUID, create a new PlatformPCMException and return that with the relevant data
			$e = New-Object PlatformPCMException -ArgumentList ("Error during getting the UUID of the redirected user.")
			$e.AddExceptionData($_)
			$e.AddData("User",$User)
			$e.AddData("UserUUID",$UserUUID)
			$e.AddData("RedirectedUUID",$RedirectedUUID)
			$e.AddData("RedirectMFAToUser",$RedirectMFAToUser)
			return $e
		}# Catch
	}# else
	
	# attempt the redirect
	Try
	{
		Invoke-PlatformAPI -APICall identity/api//UserMgmt/ChangeUserAttributes -Body (@{ID=$UserUUID;CmaRedirectedUserUuid=$RedirectedUUID} | ConvertTo-Json) -Method POST

		return $true
	}# Try
	Catch
	{
		# if an error occurred Getting the UUID, create a new PlatformPCMException and return that with the relevant data
		$e = New-Object PlatformPCMException -ArgumentList ("Error during setting the MFA Redirect.")
		$e.AddExceptionData($_)
		$e.AddData("User",$User)
		$e.AddData("UserUUID",$UserUUID)
		$e.AddData("RedirectedUUID",$RedirectedUUID)
		$e.AddData("RedirectAttempt",$RedirectAttempt)
		$e.AddData("RedirectMFAToUser",$RedirectMFAToUser)
		return $e
	}# Catch
	Finally
	{
		# nulling values to free memory
		$User = $null
		$UserUUID = $null
		$RedirectedUUID = $null
		$RedirectAttempt = $null
		$RedirectMFAToUser = $null
	}# Finally

	# if we get here, the attempt failed
	return $false
}# function global:Redirect-PlatformMFAUser
#endregion
###########