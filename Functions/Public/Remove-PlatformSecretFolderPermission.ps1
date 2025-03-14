###########
#region ### global:Remove-PlatformSecretFolderPermission # CMDLETDESCRIPTION : Removes Secret Server Folder permissions from a principal :
###########
function global:Remove-PlatformSecretFolderPermission
{
    <#
    .SYNOPSIS
    Removes Secret Server Folder permissions from a principal.

    .DESCRIPTION
    This function will remove a principal from their Secret Server Folder permissions. 
    Permission inheritance must be disabled for this this function to work.

    .PARAMETER FolderId
    Specify the Folder Id of the Secret Server Folder to modify.
    Can also be obtained using Get-PlatformSecretFolderId.

    .PARAMETER PlatformSecretPrincipal
    Specify the principals to remove from this Secret Folder.
    Must use Get-PlatformSecretPermissionPrincipal. 

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

        [Parameter(Mandatory = $true, HelpMessage = "The principals to remove permissions from.")]
        [PlatformSecretPermissionPrincipal[]]$PlatformSecretPrincipal
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
        $r = @{}
        $r.groupId = $principal.groupId
        $r.userId  = $principal.userId

        # add it to our arraylist
        $permissionrows.add($r) | Out-Null
    }# # for each prinipal specified

    # building the payload data
    $payload                         = @{}
    $payload.data                    = @{}
    $payload.data.inheritPermissions = $null
    $payload.data.removeItems        = @($permissionrows)
    $payload.data.addOrUpdateItems   = @()
    $payload.data.allowRemoveOwner   = $false

    # making the query
    $basequery = Invoke-PlatformAPI -OverrideUriAPI $baseurlendpoint -Method PATCH -Body ($payload | ConvertTo-Json -Depth 5)

    return $basequery.Success
}# function global:Remove-PlatformSecretFolderPermission
#endregion
###########