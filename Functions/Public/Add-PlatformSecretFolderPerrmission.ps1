###########
#region ### global:Add-PlatformSecretFolderPermission # CMDLETDESCRIPTION : Adds Secret Server Folder permissions to a principal :
###########
function global:Add-PlatformSecretFolderPermission
{
    <#
    .SYNOPSIS
    Adds Secret Server Folder permissions to a principal.

    .DESCRIPTION
    This function will add a principal to a Secret Server Folder and give them the specified Folder and Secret permissions for
    that folder. Permission inheritance must be disabled for this this function to work.

    .PARAMETER FolderId
    Specify the Folder Id of the Secret Server Folder to modify.
    Can also be obtained using Get-PlatformSecretFolderId.

    .PARAMETER PlatformSecretPrincipal
    Specify the principals to add to this Secret Folder.
    Must use Get-PlatformSecretPermissionPrincipal.

    .PARAMETER FolderPermission
    Specify the permission these principals will have on the folder.
    Options are : "Owner", "Edit", "Add secret", and "View"

    .PARAMETER SecretPermission
    Specify the permission these principals will have on secrets in this folder.
    Options are : "Owner", "Edit", "View", "List", and "None"

    .INPUTS
    None. You can't pipe input to this function.

    .OUTPUTS
    This function outputs $true if it succeeds, $false if it does not.

    .EXAMPLE
    C:\PS> Add-PlatformSecretFolderPermission -FolderId 47 -PlatformSecretPrincipal $principals -FolderPermission Owner -SecretPermission Owner
    For each principal in $principals, give the Owner permission on the Folder and Owner permissions on all Secrets for Folder ID 47.

    #>
    [CmdletBinding(DefaultParameterSetName="All")]
    param
    (   
        [Parameter(Mandatory = $true, HelpMessage = "The Id of the Folder.")]
        [System.Int32]$FolderId,

        [Parameter(Mandatory = $true, HelpMessage = "The principals to assign permissions to.")]
        [PlatformSecretPermissionPrincipal[]]$PlatformSecretPrincipal,

        [Parameter(Mandatory = $true, HelpMessage = "The name of the folder permission.")]
        [System.String]$FolderPermission,

        [Parameter(Mandatory = $true, HelpMessage = "The name of the secret permission.")]
        [System.String]$SecretPermission
    )

    # verifying an active Platform connection
    Verify-PlatformConnection

    # building base endpoint url
    $baseurlendpoint = ("{0}.secretservercloud.com/api/v1/folder/{1}/permissions" -f $PlatformConnection.TenantHostName, $FolderId)

    Write-Verbose ("baseurlendpoint is {0}" -f $baseurlendpoint)

    # arraylist for our permissionrowaces
    $permissionrows = New-Object System.Collections.ArrayList

    # for each prinipal specified
    foreach ($principal in $PlatformSecretPrincipal)
    {

        # build the permission row ace based on the named permission
        $r = Build-PlatformSecretFolderPermissionRowAce -PlatformSecretPrincipal $principal `
            -FolderPermission (Get-PlatformSecretFolderPermissionFolderRole -FolderId $FolderId -Permission $FolderPermission) `
            -SecretPermission (Get-PlatformSecretFolderPermissionSecretRole -FolderId $FolderId -Permission $SecretPermission)

        # add it to our arraylist
        $permissionrows.add($r) | Out-Null
    }# # for each prinipal specified

    # building the payload data
    $payload                         = @{}
    $payload.data                    = @{}
    $payload.data.inheritPermissions = $null
    $payload.data.removeItems        = @()
    $payload.data.addOrUpdateItems   = @($permissionrows)
    $payload.data.allowRemoveOwner   = $false

    # making the query
    $basequery = Invoke-PlatformAPI -OverrideUriAPI $baseurlendpoint -Method PATCH -Body ($payload | ConvertTo-Json -Depth 5)

    return $basequery.Success
}# function global:Add-PlatformSecretFolderPermission
#endregion
###########