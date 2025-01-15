###########
#region ### global:Find-PlatformUser # CMDLETDESCRIPTION : Finds a Platform User :
###########
function global:Find-PlatformUser
{
    <#
    .SYNOPSIS
    Finds a Platform-enabled user.

    .DESCRIPTION
    This cmdlet will retrieve user information about a Platform-enabled user. This search will
    add wildcards '%' to both sides of the text to search. So searching for 'jsmith' is really
    searching for '%jsmith%' in the query. This means that results like 'jsmith-adm' and 
    'xjsmith' will be returned.

    .PARAMETER User
    The user to search, this will append wildcards to either side of the string.

    .INPUTS
    None. You can't redirect or pipe input to this function.

    .OUTPUTS
    This function outputs an ArrayList of PlatformUser objects.

    .EXAMPLE
    C:\PS> Find-PlatformUser -User 'jsmith'
    This will find any users with 'jsmith' in their user information. This will add
    wildcards before and after 'jsmith'.
    #>
    [CmdletBinding(DefaultParameterSetName="Default")]
    param
    (
        [Parameter(Position = 0, Mandatory = $true, HelpMessage = "The user to find.")]
		[System.String]$User
    )

    # verifying an active Platform connection
    Verify-PlatformConnection

    # building the payload
    $ArgsObject = @{}
    $ArgsObject.Ascending = $true 
    $ArgsObject.Caching = 0
    $ArgsObject.FilterQuery = $null
    $ArgsObject.Limit = 100000
    $ArgsObject.PageNumber = 1
    $ArgsObject.PageSize = 60

    $Parameters = New-Object System.Collections.ArrayList

    $obj1 = @{}
    $obj1.ColumnType = 12
    $obj1.Label = "searchString"
    $obj1.Name = "searchString"
    $obj1.Type = "string"
    $obj1.Value = "%$User%"

    $obj2 = @{}
    $obj2.ColumnType = 12
    $obj2.Label = "orderby"
    $obj2.Name = "orderby"
    $obj2.Type = "string"
    $obj2.Value = "Username"

    $Parameters.Add($obj1) | Out-Null
    $Parameters.Add($obj2) | Out-Null

    $ArgsObject.Parameters = $Parameters

    $ArgsObject.SortBy = "Username"

    $Payload = @{}
    $Payload.Args = $ArgsObject
    $Payload.ID = "user_searchbyname"

    # attempting the query
    $query = Invoke-PlatformAPI -APICall identity/api/Report/RunReport -Method POST -Body ($Payload | ConvertTo-Json -Depth 3)

    # ArrayList for returned users
    $Users = New-Object System.Collections.ArrayList

    # for each user found
    foreach ($founduser in $query.Results.Row)
    {
        # build a PlatformUser object
        $obj = New-Object PlatformUser -ArgumentList $founduser

        # and add it to our returning users
        $Users.Add($obj) | Out-Null
    }

    # if no users were added, set $Users to $false
    if ($Users.Count -eq 0) { $Users = $false }

    return $Users
}# function global:Find-PlatformUser 
#endregion
###########