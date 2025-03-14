###########
#region ### global:Build-PlatformSecretFolderPermissionRowAce # CMDLETDESCRIPTION : Build a custom PlatformSecretFolderPermissionRoWAce object :
###########
function global:Build-PlatformSecretFolderPermissionRowAce
{
    <#
    .SYNOPSIS
    Build a custom PlatformSecretFolderPermissionRoWAce object.

    .DESCRIPTION
    Build a custom PlatformSecretFolderPermissionRoWAce object.

    .PARAMETER PlatformSecretPrincipal
    Specify the PlatformSecretPrincipals to used for this permission row ace.

    .PARAMETER FolderPermissionRole
    Specify the Folder Permission Role the principals will be assigned.

    .PARAMETER SecretPermissionRole
    Specify the Secret Permission Role the principals will be assigned.

    .INPUTS
    None. You can't pipe input to this function.

    .OUTPUTS
    This function outputs a custom hashtable object.

    .EXAMPLE
    C:\PS> Build-PlatformSecretFolderPermissionRowAce -PlatformSecretPrincipal $principals -FolderPermissionRole $folderrole -SecretPermissionRole $secretrole
    Builds the permission row aces needed for the $prinipals specified using the $folderrole for folder permission on the folder and $secretrole for secret
    permissions on the folder.

    #>
    [CmdletBinding(DefaultParameterSetName="All")]
    param
    (
        [Parameter(Mandatory = $false, HelpMessage = "The principals to assign permissions.")]
        [PlatformSecretPermissionPrincipal[]]$PlatformSecretPrincipal,

        [Parameter(Mandatory = $false, HelpMessage = "The folder roles the principals should have.")]
        [PlatformSecretPermissionFolderRole]$FolderPermissionRole,

        [Parameter(Mandatory = $false, HelpMessage = "The secret roles the principals should have.")]
        [PlatformSecretPermissionSecretRole]$SecretPermissionRole

    )

    # verifying an active Platform connection
    Verify-PlatformConnection

    # arraylist for the permission row aces
    $PermissionRowAces = New-Object System.Collections.ArrayList

    # for each principal specified
    foreach ($principal in $PlatformSecretPrincipal)
    {
        # create a custom hashtable and add in the relevant properties
        $row = @{}
        $row.groupId = $principal.groupId
        $row.secretAccessroleId = $SecretPermissionRole.id
        $row.folderAccessroleId = $FolderPermissionRole.id
        $row.userId = $principal.userId
        $PermissionRowAces.Add($row) | Out-Null
    }
    
    # return the hasttable arraylist
    return $PermissionRowAces
}# function global:Build-PlatformSecretFolderPermissionRowAce
#endregion
###########