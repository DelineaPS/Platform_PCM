###########
#region ### global:Get-PlatformSecretFolderId # CMDLETDESCRIPTION : Gets the Folder ID of a Secret Server Folder :
###########
function global:Get-PlatformSecretFolderId
{
    
    <#
    .SYNOPSIS
    Gets the Folder ID of a Secret Server Folder.

    .DESCRIPTION
    This function gets the Folder ID of a Secret Server Folder by specifying the name. If multiple matches are found
    for the specified name, a selection will be presented to enter in the correct option.

    .PARAMETER Name
    Gets only Accounts of this type. Currently only "Local","Domain","Database", or "Cloud" is supported.

    .INPUTS
    None. You can't pipe input to this function.

    .OUTPUTS
    This function outputs a System.Int32 class object.

    .EXAMPLE
    C:\PS> Get-PlatformSecretFolderId -Name "BlueCrab"
    Gets the Folder ID of the BlueCrab Folder in Secret Server. If there are multiple folders with BlueCrab in the name,
    this function will present a selection to choose from the found folders.
    #>
    [CmdletBinding(DefaultParameterSetName="All")]
    param
    (
        [Parameter(Mandatory = $true, HelpMessage = "The name of the Folder to search.", ParameterSetName = "Name")]
        [System.String]$Name
    )

    # verifying an active Platform connection
    Verify-PlatformConnection

    # verifying the folder exists
    Verify-PlatformSecretFolder -Name $Name

    # building the base url endpoint
    $baseurlendpoint = ("{0}.secretservercloud.com/api/v1/folders/lookup?filter.searchText={1}" -f $PlatformConnection.TenantHostName, [System.Web.HttpUtility]::UrlEncode($Name))

    Write-Verbose ("baseurlendpoint is {0}" -f $baseurlendpoint)

    # making the query
    $basequery = Invoke-PlatformAPI -OverrideUriAPI $baseurlendpoint -Method Get

    # if there was no results found
    if ($basequery.total -eq 0)
    {
        return $false
    }
    # if more than 1 folder was found
    elseif (($basequery | Measure-Object | Select-Object -ExpandProperty Count) -gt 1)
    {
        Write-Warning "Multiple folders found." 

        # get those folders
        $multiplefolders = Get-PlatformSecretFolder -Name $Name

        # print them to the console window
        foreach ($folder in $multiplefolders)
        {
            Write-Host ("[{0}] ID: {1} Path: {2}" -f ++$x, $folder.id, $folder.folderpath)
        }

        # Prompt for Folder selection
        [System.Int32]$Selection = Read-Host -Prompt "Please select a folder [1]"

        # Default selection
        if ([System.String]::IsNullOrEmpty($Selection))
        {
            # Default selection is 1
            $Selection = 1
        }
        # Validate selection
        if ($Selection -gt $x -or $Selection -lt 1)
        {
            # Selection must be in range
            Write-Host "Invalid selection. Folder selection aborted." 
            return $false
        }
        else
        {
            # return the select with the exact name match
            return $basequery[--$Selection] | Where-Object -Property value -eq $Name | Select-Object -ExpandProperty id
        }
        #return $multiplefolders
    }#  elseif (($basequery | Measure-Object | Select-Object -ExpandProperty Count) -gt 1)
    else  
    {
        return $basequery | Where-Object -Property value -eq $Name | Select-Object -ExpandProperty id
    }
}# function global:Get-PlatformSecretFolderId
#endregion
###########