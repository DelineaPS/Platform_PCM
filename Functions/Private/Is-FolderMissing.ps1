###########
#region ### global:Is-FolderMissing # CMDLETDESCRIPTION : Determines if a Secret Server Folder exists or not :
###########
function global:Is-FolderMissing
{
    <#
    .SYNOPSIS
    Determines if a Secret Server Folder is missing or not.

    .DESCRIPTION
    This cmdlet will return true if the provided ID or Name does not exist for the user. If it does exist, 
    this cmdlet will return false.

    Note: it may be possible that the folder does exist, but this user does not have any permissions to see
    it.

    .PARAMETER Name
    Specify the name of the folder to check if it is missing. Only exact name matches will work.

    .PARAMETER FolderId
    Specify the id of the folder to check if it is missing.

    .INPUTS
    None. You can't pipe input to this function.

    .OUTPUTS
    This function outputs either $true or $false.

    .EXAMPLE
    C:\PS> Is-FolderMissing -Name "Infrastructure Team"
    This cmdlet will check if the Secret Server Folder "Infrastructure Team" exists for this user. 
    - if it does not exist, return true. Otherwise return false.

    .EXAMPLE
    C:\PS> Is-FolderMissing -FolderId 44
    This cmdlet will check if the Secret Server Folder Id 44 exists for this user. 
    - if it does not exist, return true. Otherwise return false.
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

    # building base url based on parameter set used.
    if ($PSBoundParameters.ContainsKey("Name"))
    {
        $baseurlendpoint = ("{0}.secretservercloud.com/api/v1/folders/lookup?filter.searchText={1}" -f $PlatformConnection.TenantHostName, [System.Web.HttpUtility]::UrlEncode($Name))
    }
    else
    {
        $baseurlendpoint = ("{0}.secretservercloud.com/api/v1/folder-details/{1}?returnEmptyInsteadOfNoAccessException=true" -f $PlatformConnection.TenantHostName, $FolderID)
    }
    
    Write-Verbose ("baseurlendpoint is {0}" -f $baseurlendpoint)

    # making the query
    $basequery = Invoke-PlatformAPI -OverrideUriAPI $baseurlendpoint -Method Get

    # if the Name parameter was used
    if ($PSBoundParameters.ContainsKey("Name"))
    {
        # if we can't find an exact name match for our folder
        if ($basequery | Where-Object -Property value -ne $Name)
        {
            return $true
        }
        else
        {
            return $false
        }
    }
    else # otherwise
    {
        # if we can't find an exact id match for our folder
        if ($basequery | Where-Object -Property id -ne $FolderID)
        {
            return $true
        }
        else
        {
            return $false
        }
    }
}# function global:Is-FolderMissing
#endregion
###########