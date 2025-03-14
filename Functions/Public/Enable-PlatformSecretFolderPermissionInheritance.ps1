###########
#region ### global:Enable-PlatformSecretFolderPermissionInheritance # CMDLETDESCRIPTION : Enables folder permission inheritance for a PlatfomrSecretFolder object :
###########
function global:Enable-PlatformSecretFolderPermissionInheritance
{
    <#
    .SYNOPSIS
    Enables folder permission inheritance for a PlatfomrSecretFolder object.

    .DESCRIPTION
    This function enables folder permission inheritance for a PlatformSecretFolder object.

    .PARAMETER PlatformSecretFolders
    Specify the PlatformSecretFolder objects to enable folder permission inheritance. This can be an array and 
    all folders will have folder permission inheritance enabled.

    .INPUTS
    None. You can't pipe input to this function.

    .OUTPUTS
    This function outputs to the console window only.

    .EXAMPLE
    C:\PS> Enable-PlatformSecretFolderPermissionInheritance -PlatformSecretFolders (Get-PlatformSecretFolder -Name "BlueCrab")
    Gets the PlatformSecretFolder for the "BlueCrab" Secret Server Folder, then enables permission folder inheritance on it.

    .EXAMPLE
    C:\PS> Enable-PlatformSecretFolderPermissionInheritance -PlatformSecretFolders (Get-PlatformSecretFolder -ParentFolderId 47)
    Gets all the PlatformSecretFolders that have a ParentFolderId of 47, then enables permission folder inheritance on it.

    #>
    [CmdletBinding(DefaultParameterSetName="All")]
    param
    (
        [Parameter(Mandatory = $false, HelpMessage = "The PlatformSecretFolders to enable inheritance.")]
        [PlatformSecretFolder[]]$PlatformSecretFolders
    )

    # verifying an active Platform connection
    Verify-PlatformConnection

    # preparing the payload data line
    $payload = '{"data":{ "inheritPermissions":{"dirty":true,"value":true}}}'

    # for each platformfolder provided to the cmdlet
    foreach ($PlatformFolder in $PlatformSecretFolders)
    {
        # if the folder doesn't exist, ignore it
        if ($PlatformFolder -eq $false)
        {
            continue
        }

        Try
        {
            # enabling folder inheritance
            Write-Host ("Enabling folder inheritance on [{0}] ... " -f $PlatformFolder.FolderPath) -NoNewline
            $a = Invoke-PlatformAPI -OverrideUriAPI "$($PlatformConnection.TenantHostName).secretservercloud.com/api/v1/folder/$($PlatformFolder.ID)/permissions" -Body $payload -Method PATCH

            if ($a.success)
            {
                Write-Host ("Done!") -ForegroundColor Green
            }
        }
        Catch
        {
            Write-Host ("Error!") -ForegroundColor Red
            # if an error occurred during enabling folder inheritence with the relevant data
            $e = New-Object PlatformPCMException -ArgumentList ("Error during Enable Folder inheritance object.")
            $e.AddExceptionData($_)
            $e.AddData("PlatformFolder",$PlatformFolder)
            return $e
        }# Try
    }# foreach ($PlatformFolder in $PlatformSecretFolders)

}# function global:Enable-PlatformSecretFolderPermissionInheritance
#endregion
###########