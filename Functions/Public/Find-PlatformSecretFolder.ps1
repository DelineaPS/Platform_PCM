###########
#region ### global:Find-PlatformSecretFolder # CMDLETDESCRIPTION : Finds Secret Server Folders :
###########
function global:Find-PlatformSecretFolder
{
    <#
    .SYNOPSIS
    Find Platform Secret Server Folders.

    .DESCRIPTION
    This function will search for Secret Server folders based on the provided input. This function 
    will return all folders visible to the user if no parameters are used. This is a direct return
    from the base RestAPI endpoint of api/v1/folders.

    .PARAMETER Name
    Search for folders with this name. This is a like operator and will find all folders with this string in the name.

    .PARAMETER ID
    Search for a folder with this ID. This option modifies the base url of the RestAPI endpoint.

    .PARAMETER LimitToDirectDescendents
    Limits the results to be direct descendents of the specified parent folder. Can only be used with the 
    ParentFolderId parameter.

    .PARAMETER OnlyIncludeRootFolders
    Limits the results to just direct descendents of the root folder.

    .PARAMETER ParentFolderId
    Limits the results to only descendents of the specified Folder Id. Will recurvsively get all child folders unless
    the LimitToDirectDescendents Switch is used.

    .PARAMETER Skip
    Skip the first this number of folders found.

    .PARAMETER Limit
    Limits the number of results to return.

    .INPUTS
    None. You can't pipe input to this function.

    .OUTPUTS
    This function outputs the direct output from the RestAPI endpoint as a PSCustomObject.

    .EXAMPLE
    C:\PS> Find-PlatformSecretFolder
    Finds all Secret Server Folders visible to the user.

    .EXAMPLE
    C:\PS> Find-PlatformSecretFolder -Name "AAB"
    Finds all Secret Server Folders with "AAB" in the name.

    .EXAMPLE
    C:\PS> Find-PlatformSecretFolder -ID 599
    Finds the Secret Server Folder with the Folder ID of 599.

    .EXAMPLE
    C:\PS> Find-PlatformSecretFolder -ParentFolderId 599
    Recursively finds all child folders under the Secret Server Folder with the Folder Id 599.

    .EXAMPLE
    C:\PS> Find-PlatformSecretFolder -ParentFolderId 599 -LimitToDirectDescendents
    Recursively finds all child folders under the Secret Server Folder with the Folder Id 599. Limits
    results to just direct child folders. Grandchild folders and beyond are ignored.
	
	.EXAMPLE
    C:\PS> Find-PlatformSecretFolder -OnlyIncludeRootFolders
    Finds all Secret Server Folders visible to the user that are direct descendents of the root folder.
    #>
    [CmdletBinding(DefaultParameterSetName="All")]
    param
    (
        [Parameter(Mandatory = $false, HelpMessage = "The name of the Folder to search.", ParameterSetName = "Name")]
        [System.String]$Name,

        [Parameter(Mandatory = $false, HelpMessage = "The ID of the Folder to search.", ParameterSetName = "ID")]
        [System.Int32]$ID,

        [Parameter(Mandatory = $false, HelpMessage = "Limit to direct descendents of Parent Folder.", ParameterSetName = "ParentFolderId")]
        [Switch]$LimitToDirectDescendents,

        [Parameter(Mandatory = $false, HelpMessage = "Only shows root-level folders.", ParameterSetName = "OnlyRoot")]
        [Parameter(Mandatory = $false, HelpMessage = "Only shows root-level folders.", ParameterSetName = "Name")]
        [Switch]$OnlyIncludeRootFolders,

        [Parameter(Mandatory = $false, HelpMessage = "The ID of the Parent Folder to search.", ParameterSetName = "ParentFolderId")]
        [System.Int32]$ParentFolderId,

        #[Parameter(Mandatory = $false, HelpMessage = "The name of the Account to search.")]
        #[ValidateSet("Owner","Edit","AddSecret","View")]
        #[System.String]$PermissionRequired,

        [Parameter(Mandatory = $false, HelpMessage = "Skip this number of folders.")]
        [System.Int32]$Skip,

        [Parameter(Mandatory = $false, HelpMessage = "Limit results to this many.")]
        [System.Int32]$Limit = 100000
    )

    # verifying an active Platform connection
    Verify-PlatformConnection

    # arraylist for extra options
    $extras = New-Object System.Collections.ArrayList

    # setting up the extra filter conditionals
    if ($PSBoundParameters.ContainsKey("Name"))               { $extras.Add(("filter.searchText={0}" -f [System.Web.HttpUtility]::UrlEncode($Name))) | Out-Null }
    if ($LimitToDirectDescendents.IsPresent)                  { $extras.Add(("filter.limitToDirectDescendents=true")) | Out-Null  }
    if ($OnlyIncludeRootFolders.IsPresent)                    { $extras.Add(("filter.onlyIncludeRootFolders=true")) | Out-Null }
    if ($PSBoundParameters.ContainsKey("ParentFolderId"))     { $extras.Add(("filter.parentFolderId={0}" -f $ParentFolderId)) | Out-Null }
    if ($PSBoundParameters.ContainsKey("PermissionRequired")) { $extras.Add(("filter.permissionRequired={0}" -f $PermissionRequired)) | Out-Null }
    if ($PSBoundParameters.ContainsKey("Skip"))               { $extras.Add(("skip={0}" -f $Skip)) | Out-Null }
    if ($PSBoundParameters.ContainsKey("Limit"))              { $extras.Add(("take={0}" -f $Limit)) | Out-Null }

    # building the base url endpoint
    $baseurlendpoint = ("{0}.secretservercloud.com/api/v1/folders" -f $PlatformConnection.TenantHostName)

    # if the ID parameter set is used, add the folder ID to the base url
    if ($PSBoundParameters.ContainsKey("ID"))
    {
        $baseurlendpoint = $baseurlendpoint + ("/{0}" -f $ID)
    }

    # if extras were used, format them and add it to our base url
    if (($extras | Measure-Object | Select-Object -ExpandProperty Count) -gt 0)
    {
        $baseurlendpoint = $baseurlendpoint + "?" + ($extras -join "&")
    }

    Write-Verbose ("baseurlendpoint is {0}" -f $baseurlendpoint)

    # making the query
    $basequery = Invoke-PlatformAPI -OverrideUriAPI $baseurlendpoint -Method Get

    # if there was no results found
    if ($basequery.total -eq 0)
    {
        return $false
    }
    else # otherwise process the results
    {
        return $basequery
    }
}# function global:Find-PlatformSecretFolder
#endregion
###########