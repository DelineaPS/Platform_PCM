###########
#region ### global:Show-PlatformUser # CMDLETDESCRIPTION : Make a user display in the Users section :
###########
function global:Show-PlatformUser
{
    <#
    .SYNOPSIS
    Causes a user to display in the Users section of the Delinea Platform.

    .DESCRIPTION
	This cmdlet causes a user to appear in the Users section of the Delinea Platform. By default,
	not all users are displayed in the Users section of the Platform. This is for performance reasons.
	But if there is a need to set information about a user, that user either needs to be invited via
	email, or log onto the tenant first.

	However in some situations, this may not be desirable. So this cmdlet will cause a user to display
	without sending them an invite or having them log in first.

    .PARAMETER Users
	The user accounts to appear in the Users section.
	
    .INPUTS
    None. You can't redirect or pipe input to this function.

    .OUTPUTS
    This function returns True if successful, False if it was not successful.

    .EXAMPLE
    C:\PS> Show-PlatformUser -Users "bsmith@domain.com"
	Makes the users "bsmith@domain.com" appear in the Users section of the Platform.

	.EXAMPLE
    C:\PS> Show-PlatformUser -Users "bsmith@domain.com","mjohnson@domain.com"
	Makes the users "bsmith@domain.com" and "mjohnson@domain.com" appear in the Users 
	section of the Platform.
    #>
    [CmdletBinding(DefaultParameterSetName="All")]
    param
    (
		[Parameter(Mandatory = $true, Position = 0, HelpMessage = "The users to appear in the Users section.")]
		[System.String]$User
    )

    # verifying an active Platform connection
    Verify-PlatformConnection

    # find the user
    if (-Not ($userfound = Find-PlatformUser -User $User))
    {
        Write-Host ("User [{0}] not found." -f $User)
        return $false
    }

	# arraylist to set user information
	$Entities = New-Object System.Collections.ArrayList

    # preparing the base body
    $obj = @{}
    $obj.Type = "User"
    $obj.Guid = $userfound.ID
    $obj.Name = $userfound.username
    $Entities.Add($obj) | Out-Null

	# preparing the json data
	$Json = @{}
	$Json.Entities    = $Entities
	$Json.EmailInvite = $false
	$Json.SmsInvite   = $false

	Try
	{
		# make the attempt
		Invoke-PlatformAPI -APICall identity/api/UserMgmt/InviteUsers -Body ($Json | ConvertTo-Json -Compress)

		return $true
	}
	Catch
	{
		# if an error occurred during the call, create a new PlatformPCMException and return that with the relevant data
		$e = New-Object PlatformPCMException -ArgumentList ("Error showing Platform Users.")
		$e.AddExceptionData($_)
		$e.AddData("User",$User)
		$e.AddData("userfound",$userfound)
		return $e
	}

	# if we get here, the attempt failed
	return $false
}# function global:Show-PlatformUser
#endregion
###########