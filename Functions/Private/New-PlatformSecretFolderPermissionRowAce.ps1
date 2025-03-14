###########
#region ### global:New-PlatformSecretFolderPermissionRowAce # CMDLETDESCRIPTION : Creates a new PlatformSecretFolderPermissionRowAce object :
###########
function global:New-PlatformSecretFolderPermissionRowAce
{
    <#
    .SYNOPSIS
    Creates a new PlatformSecretFolderPermissionRowAce object.

    .DESCRIPTION
    Creates a new PlatformSecretFolderPermissionRowAce object.

    .PARAMETER folderAccessRoleId
    Specify the Folder Role permission id.

    .PARAMETER groupId
    Specify the group id of the principal.

    .PARAMETER secretAccessRoleId
    Specify the Secret Role permission id.

    .PARAMETER userId
    Specify the user id of the principal.

    .INPUTS
    None. You can't pipe input to this function.

    .OUTPUTS
    This function outputs a PlatformSecretFolderPermissionRowAce class object.

    .EXAMPLE
    C:\PS> New-PlatformSecretFolderPermissionRowAce -folderAccessRoleId 11 -groupId 13 -secretAccessRoleId 10 -userId 13
    Create a new PlatformSecretFolderPermissionRowAce with a Folder Role ID of 11, a group ID of 13, a Secret Role ID of 
    10 and a User ID of 13.
    #>
    [CmdletBinding(DefaultParameterSetName="All")]
    param
    (
        [Parameter(Mandatory = $false, HelpMessage = "The Folder Permission Role ID.")]
        [System.Int32]$folderAccessRoleId,

        [Parameter(Mandatory = $false, HelpMessage = "The Group ID of the principal.")]
        [System.Int32]$groupId,

        [Parameter(Mandatory = $false, HelpMessage = "The Secret Permission Role ID.")]
        [System.Int32]$secretAccessRoleId,

        [Parameter(Mandatory = $false, HelpMessage = "The User ID of the principal.")]
        [System.Int32]$userId 
    )

    # verifying an active Platform connection
    Verify-PlatformConnection

    # creating a new PlatformSecretFolderPermissionRowAce object
    $permissionrow = New-Object PlatformSecretFolderPermissionRowAce -ArgumentList ($folderAccessRoleId, $groupId, $secretAccessRoleId, $userId)

    return $permissionrow
}# function global:New-PlatformSecretFolderPermissionRowAce
#endregion
###########