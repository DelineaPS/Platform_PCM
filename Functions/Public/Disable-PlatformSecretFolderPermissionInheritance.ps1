###########
#region ### global:Disable-PlatformSecretFolderPermissionInheritance # CMDLETDESCRIPTION : Disables folder permission inheritance for a PlatfomrSecretFolder object :
###########
function global:Disable-PlatformSecretFolderPermissionInheritance
{
    <#
    .SYNOPSIS
    Disables folder permission inheritance for a PlatfomrSecretFolder object.

    .DESCRIPTION
    This function disables folder permission inheritance for a PlatformSecretFolder object.

    .PARAMETER PlatformSecretFolders
    Specify the PlatformSecretFolder objects to disable folder permission inheritance. This can be an array and 
    all folders will have folder permission inheritance disabled.

    .INPUTS
    None. You can't pipe input to this function.

    .OUTPUTS
    This function outputs to the console window only.

    .EXAMPLE
    C:\PS> Disable-PlatformSecretFolderPermissionInheritance -PlatformSecretFolders (Get-PlatformSecretFolder -Name "BlueCrab")
    Gets the PlatformSecretFolder for the "BlueCrab" Secret Server Folder, then disables permission folder inheritance on it.

    .EXAMPLE
    C:\PS> Disable-PlatformSecretFolderPermissionInheritance -PlatformSecretFolders (Get-PlatformSecretFolder -ParentFolderId 47)
    Gets all the PlatformSecretFolders that have a ParentFolderId of 47, then disables permission folder inheritance on it.

    #>
    [CmdletBinding(DefaultParameterSetName="All")]
    param
    (
        [Parameter(Mandatory = $false, HelpMessage = "The PlatformSecretFolders to disable inheritance.")]
        [PlatformSecretFolder[]]$PlatformSecretFolders
    )

    # verifying an active Platform connection
    Verify-PlatformConnection

    # preparing the payload data line
    $payload = '{"data":{ "inheritPermissions":{"dirty":true,"value":false}}}'

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
            # disabling folder inheritance
            Write-Host ("Disabling folder inheritance on [{0}] ... " -f $PlatformFolder.FolderPath) -NoNewline
            $a = Invoke-PlatformAPI -OverrideUriAPI "$($PlatformConnection.TenantHostName).secretservercloud.com/api/v1/folder/$($PlatformFolder.ID)/permissions" -Body $payload -Method PATCH

            if ($a.success)
            {
                Write-Host ("Done!") -ForegroundColor Green
            }
        }# Try
        Catch
        {
            Write-Host ("Error!") -ForegroundColor Red
            # if an error occurred during disabling folder inheritence with the relevant data
            $e = New-Object PlatformPCMException -ArgumentList ("Error during Disable Folder inheritance object.")
            $e.AddExceptionData($_)
            $e.AddData("PlatformFolder",$PlatformFolder)
            return $e
        }# Catch
    }# foreach ($PlatformFolder in $PlatformSecretFolders)

}# function global:Disable-PlatformSecretFolderPermissionInheritance
#endregion
###########