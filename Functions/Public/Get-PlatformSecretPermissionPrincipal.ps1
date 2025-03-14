###########
#region ### global:Get-PlatformSecretPermissionPrincipal # CMDLETDESCRIPTION : Gets a PlatformSecretPermissionPrincipal object :
###########
function global:Get-PlatformSecretPermissionPrincipal
{
    <#
    .SYNOPSIS
    Gets a PlatformSecretPermissionPrincipal object, often used for assigning permissions to Secrets and Folders.

    .DESCRIPTION
    This function gets IDs relevant to a principal for use with assigning them permissions to Secrets or Folders.
    The Name search is a like operator that will search users and groups to find a match in the name or displayName
    properties. If -ExactMatch is used, then only an exact match will be returned.

    If no matches are found, returns $false.

    .PARAMETER Name
    Specify the name to search in users and groups. This is like operator match.

    .PARAMETER ExactMatch
    Only return results that have an exact match with the Name parameter.

    .INPUTS
    None. You can't pipe input to this function.

    .OUTPUTS
    This function outputs a PlatformSecretPermissionPrincipal class object if matches are found,
    otherwise this function returns $false.

    .EXAMPLE
    C:\PS> Get-PlatformSecretPermissionPrincipal
    Gets all users and groups from the Platform and reutrns their groupId and userId.

    .EXAMPLE
    C:\PS> Get-PlatformSecretPermissionPrincipal -Name "BlueCrab"
    Gets all users and groups with "BlueCrab" in the name or displayName attributes.
	
	.EXAMPLE
    C:\PS> Get-PlatformSecretPermissionPrincipal -Name "BlueCrab Admins" -ExactMatch
    Gets all users and groups that have an exact match of "BlueCrab Admins" in their
    name or displayName attributes.

    #>
    [CmdletBinding(DefaultParameterSetName="All")]
    param
    (
        [Parameter(Mandatory = $false, HelpMessage = "The name to search.")]
        [System.String]$Name,

        [Parameter(Mandatory = $false, HelpMessage = "Specify to search for an exact name match.")]
        [Switch]$ExactMatch
    )

    # verifying an active Platform connection
    Verify-PlatformConnection

    # arraylist for extra options
    $extras = New-Object System.Collections.ArrayList

    # building a body payload
    $payload = @{}
    $payload.includeGroups = $true
    $payload.includeUsers  = $true

    # setting up the extra filter conditionals
    if ($PSBoundParameters.ContainsKey("Name")) { $payload.searchTerm = $Name }

    # building the base url endpoint
    $baseurlendpoint = ("{0}.secretservercloud.com/internals/user-detail/search?isExporting=false&paging.take=10000&paging.skip=0" -f $PlatformConnection.TenantHostName)

    Write-Verbose ("baseurlendpoint is {0}" -f $baseurlendpoint)

    # making the query
    $basequery = Invoke-PlatformAPI -OverrideUriAPI $baseurlendpoint -Method Post -Body ($payload | ConvertTo-Json)

    # if there was no results found
    if ($basequery.total -eq 0)
    {
        return $false
    }
    else # otherwise process the results
    {
        $AllData = $basequery  | Foreach-Object -Parallel {
			$query = $_
			$PlatformConnection  = $using:PlatformConnection
            $PlatformSessionInformation = $using:PlatformSessionInformation

			# for each script in our Platform_PCMScriptBlocks
            foreach ($script in $using:Platform_PCMScriptBlocks)
            {
                # add it to this thread as a script, this makes all classes and functions available to this thread
                . $script.ScriptBlock
            }

			$obj = New-Object PSObject

			Try
			{
				# create a new Platform Secret Permission Principals object
				$principal = New-Object PlatformSecretPermissionPrincipal -ArgumentList ($query)
				# add it to our temporary returner object
				$obj | Add-Member -MemberType NoteProperty -Name Principals -Value $principal
			}
			Catch
			{
				# if an error occurred during New-Object, create a new PlatformPCMException and return that with the relevant data
				$e = New-Object PlatformPCMException -ArgumentList ("Error during New PlatformSecretPermissionPrincipal object.")
				$e.AddExceptionData($_)
				$e.AddData("query",$query)
				$obj | Add-Member -MemberType NoteProperty -Name Exceptions -Value $e
			}# Catch
			Finally
			{
				# nulling values to free memory
				$principal = $null
				$query = $null
			}

			# return the returner object
			$obj
		} | # $AllData = $basequery | Foreach-Object -Parallel {
		ForEach-Object -Begin { $i = 0 } -Process { 
			
			$Completed = $($i/($basequery | Measure-Object | Select-Object -ExpandProperty Count)*100)
			# incrementing result count
			$i++
			# update progress bar
			Write-Progress -Activity "Getting Principals" -Status ("{0} out of {1} Complete" -f $i,$basequery.Count) -PercentComplete $Completed -CurrentOperation ("Current: [{0}]" -f $_.folderName)
			# returning the result
			$_
		} #>
	}# if ($basequery -ne $null)

    # if errors were encountered, add them to our global PlatformErrorStack
	if ($AllData.Exceptions.Count -gt 0)
	{
		$global:PlatformErrorStack = $AllData.Exceptions
	}#>

	# clean up some memory
	[System.GC]::GetTotalMemory($true) | Out-Null
	[System.GC]::Collect()

    # if -ExactMatch was used
    if ($ExactMatch.IsPresent)
    {
        # find the match that is an exact match of the name or displayName property
        $thismatch = ($AllData.Principals | Where-Object {$_.Name -eq $Name -or $_.displayName -eq $Name})

        # if thismatch is empty
        if ($thismatch -eq $null)
        {
            return $false
        }
        else # otherwise
        {
            return $thismatch
        }
    }
    else # otherwise
    {   
        # return all our matches
        return $AllData.Principals
    }
}# function global:Get-PlatformSecretPermissionPrincipal
#endregion
###########