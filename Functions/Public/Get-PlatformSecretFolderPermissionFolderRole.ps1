###########
#region ### global:Get-PlatformSecretFolderPermissionFolderRole # CMDLETDESCRIPTION : Gets the Folder Roles from a Secret Server Folder :
###########
function global:Get-PlatformSecretFolderPermissionFolderRole
{
    <#
    .SYNOPSIS
    Gets the Folder Roles from a Secret Server Folder.

    .DESCRIPTION
    Gets the Folder Roles from a Secret Server Folder. Returns a PlatformSecretPermissionFolderRole class 
    object for the roles found, or returns $false if none or found, or if the specified Permission is not found.

    .PARAMETER FolderId
    Specify the FolderId to search.

    .PARAMETER Permission
    Specify the Permission to search.

    .INPUTS
    None. You can't pipe input to this function.

    .OUTPUTS
    This function outputs a PlatformSecretPermissionFolderRole for the permissions found. 
    This function outputs $false if none are found, or if the requested permission is not found.

    .EXAMPLE
    C:\PS> Get-PlatformSecretFolderPermissionFolderRole -FolderId 45
    Gets all the Folder Permission Roles for the Folder Id of 45.

    .EXAMPLE
    C:\PS> Get-PlatformSecretFolderPermissionFolderRole -FolderId 45 -Permission Owner
    Gets all the Folder Permission Roles for the Folder Id of 45 and returns one with a role of Owner.
    #>
    [CmdletBinding(DefaultParameterSetName="All")]
    param
    (   
        [Parameter(Mandatory = $false, HelpMessage = "The ID of the Folder to search.")]
        [System.Int32]$FolderId,

        [Parameter(Mandatory = $false, HelpMessage = "The string of the Permission to search.")]
        [System.String]$Permission
    )

    # verifying an active Platform connection
    Verify-PlatformConnection

    # building the base endpoint
    $baseurlendpoint = ("{0}.secretservercloud.com/internals/folder/{1}" -f $PlatformConnection.TenantHostName, $FolderId)

    Write-Verbose ("baseurlendpoint is {0}" -f $baseurlendpoint)

    # making the query
    $basequery = Invoke-PlatformAPI -OverrideUriAPI $baseurlendpoint -Method Get

    # arraylist for all the roles
    $FolderPermissionRoles = New-Object System.Collections.ArrayList

    # if the query for folder roles is not null
    if ($basequery.folderRoles -ne $null)
    {
        # for each folder role
        foreach ($role in $basequery.folderRoles)
        {
            # create a new PlatformSecretPermissionFolderRole class object
            $r = New-Object PlatformSecretPermissionFolderRole -ArgumentList $role
            
            # and add it to our arraylist
            $FolderPermissionRoles.Add($r) | Out-Null
        }# foreach ($role in $basequery.folderRoles)
    }# if ($basequery.folderRoles -ne $null)
    else # otherwise
    {
        return $false
    }

    # if the query is not null and the -Permission parameter was used
    if ($PSBoundParameters.ContainsKey("Permission"))
    {
        # search for this permission
        $thismatch = $FolderPermissionRoles | Where-Object -Property Name -eq $Permission

        # if the match is null
        if ($thismatch -eq $null)
        {
            return $false
        }
        else # otherwise
        {
            return $thismatch
        }
    }# if ($PSBoundParameters.ContainsKey("Permission"))
    else
    {
        return $FolderPermissionRoles
    }
}# function global:Get-PlatformSecretFolderPermissionFolderRole
#endregion
###########