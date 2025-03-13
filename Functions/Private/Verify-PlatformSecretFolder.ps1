###########
#region ### global:Verify-PlatformSecretFolder # CMDLETDESCRIPTION : Verifies if a Secret Server Folder exists or not :
###########
function global:Verify-PlatformSecretFolder
{
    <#
    .SYNOPSIS
    Determines if a Secret Server Folder is missing or not.

    .DESCRIPTION
    This cmdlet will throw an exception if the provided ID or Name does not exist for the user.

    Note: it may be possible that the folder does exist, but this user does not have any permissions to see
    it.

    .PARAMETER Name
    Specify the name of the folder to check if it is missing. Only exact name matches will work.

    .PARAMETER FolderId
    Specify the id of the folder to check if it is missing.

    .INPUTS
    None. You can't pipe input to this function.

    .OUTPUTS
    This function throws an error if the folder is not found.

    .EXAMPLE
    C:\PS> Verify-PlatformSecretFolder -Name "Infrastructure Team"
    This cmdlet will check if the Secret Server Folder "Infrastructure Team" exists for this user. 
    - if it does not exist, throw an exception.

    .EXAMPLE
    C:\PS> Verify-PlatformSecretFolder -FolderId 44
    This cmdlet will check if the Secret Server Folder Id 44 exists for this user. 
    - if it does not exist, throw an exception.
    #>
    [CmdletBinding(DefaultParameterSetName="All")]
    param
    (
        [Parameter(Mandatory = $true, HelpMessage = "The name of the Account to search.", ParameterSetName = "Name")]
        [System.String]$Name,

        [Parameter(Mandatory = $false, HelpMessage = "The name of the Account to search.", ParameterSetName = "ID")]
        [System.Int32]$FolderId
    )

    # verifying an active Platform connection
    Verify-PlatformConnection

    if ($PSBoundParameters.ContainsKey("Name"))
    {
        if (Is-FolderMissing -Name $Name)
        {
            throw ("Folder [{0}] not found." -f $Name)
        }
    }
    else 
    {
        if (Is-FolderMissing -FolderId $FolderId)
        {
            throw ("Folder ID [{0}] not found." -f $FolderId)
        }
    }
    
}# function global:Verify-PlatformSecretFolder
#endregion
###########