###########
#region ### global:Is-TemplateMissing # CMDLETDESCRIPTION : Determines if a Secret Server Secret Template exists or not :
###########
function global:Is-TemplateMissing
{
    <#
    .SYNOPSIS
    Determines if a Secret Server Secret Template exists or not.

    .DESCRIPTION
    This cmdlet will return true if the provided Name for a Secret Template does not exist for the user. If it does exist, 
    this cmdlet will return false.

    Note: it may be possible that the template does exist, but this user does not have any permissions to see
    it.

    .PARAMETER Name
    Specify the name of the template to check if it is missing. Only exact name matches will work.

    .INPUTS
    None. You can't pipe input to this function.

    .OUTPUTS
    This function outputs either $true or $false.

    .EXAMPLE
    C:\PS> Is-TemplateMissing -Name "PAS Imported Text Secrets"
    This cmdlet will check if the Secret Server Secret Template "PAS Imported Text Secrets" exists for this user. 
    - if it does not exist, return true. Otherwise return false.

    #>
    [CmdletBinding(DefaultParameterSetName="All")]
    param
    (
        [Parameter(Mandatory = $true, HelpMessage = "The name of the Secret Template to search.", ParameterSetName = "Name")]
        [System.String]$Name
    )

    # verifying an active Platform connection
    Verify-PlatformConnection

    $baseurlendpoint = ("{0}.secretservercloud.com/api/v1/secret-templates?filter.searchText={1}&take=10000" -f $PlatformConnection.TenantHostName, [System.Web.HttpUtility]::UrlEncode($Name))
    
    Write-Verbose ("baseurlendpoint is {0}" -f $baseurlendpoint)

    # making the query
    $basequery = Invoke-PlatformAPI -OverrideUriAPI $baseurlendpoint -Method Get

    # if we can't find an exact name match for our template
    if ($basequery | Where-Object -Property name -eq $Name)
    {
        return $false
    }
    else
    {
        return $true
    }

}# function global:Is-TemplateMissing
#endregion
###########