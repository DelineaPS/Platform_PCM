###########
#region ### global:Import-PlatformSecretsFromCsv # CMDLETDESCRIPTION : Imports prepared CSV data using the CSV Import Feature :
###########
function global:Import-PlatformSecretsFromCsv
{
    <#
    .SYNOPSIS
    Import Secrets from prepared CSV Data using the CSV Import Feature.

    .DESCRIPTION
    This function will create new Secrets using the CSV Import feature by providing it prepared
    CSV data.

    The Secret Template Id to use with this import will also need to be specified. This function
    will post progress of the import to the console window.

    .PARAMETER TemplateId
    Specify the Secret Template Id to use for this import.

    .PARAMETER CSV 
    Specify the CSV data to use.

    .PARAMETER ImportType
    Specify the Type of Import Type to use, only CSV is currently supported.

    .PARAMETER ImportWithFolder
    Add in the column to import the data into a specific folder.

    .PARAMETER ImportWithTotp
    Specify the option to use Totp. 
    
    .PARAMETER InheritFolderPermissions
    Specify the option to have the imported secrets immediately inherit the folder's permissions.

    .PARAMETER ChangeRemotePasswords
    Specify the option to have the newly created secrets immediately rotate.

    .INPUTS
    None. You can't redirect or pipe input to this function.

    .OUTPUTS
    This function returns nothing.

    .EXAMPLE
    C:\PS> Import-PlatformSecretsFromCsv -TemplateId 6001 -Csv $Csv
    This will take the CSV data in $Csv and create secrets using the Secret Template 6001 (default Active Directory Account).
    #>
    [CmdletBinding(DefaultParameterSetName="Default")]
    param
    (
        [Parameter(Mandatory = $true, HelpMessage = "The Secret Template ID to use.")]
        [System.Int32]$TemplateId,

        [Parameter(Mandatory = $true, HelpMessage = "The specially prepared CSV data string.")]
        [PSObject]$CSV,

        [Parameter(Mandatory = $false, HelpMessage = "The type of Import to use. Only CSV is currently supported.")]
        [ValidateSet("CSV")]
        [System.String]$ImportType = "CSV",

        [Parameter(Mandatory = $false, HelpMessage = "Add in the option to specify which folder the secrets will be created in.")]
        [System.Boolean]$ImportWithFolder = $true,

        [Parameter(Mandatory = $false, HelpMessage = "Import with Totp option.")]
        [System.Boolean]$ImportWithTotp = $false,

        [Parameter(Mandatory = $false, HelpMessage = "Specify to allow newly created secrets to inherit the folder's permissions.")]
        [System.Boolean]$inheritFolderPermissions = $true,

        [Parameter(Mandatory = $false, HelpMessage = "Change the new secrets' passwords immediately after creation.")]
        [System.Boolean]$ChangeRemotePasswords = $false
    )

    # verifying an active Platform connection
    Verify-PlatformConnection

    # preparing the CSV data line
    $csvdataline = Prepare-PlatformImportCsvData -CsvData $CSV

    # preparing the payload line
    $payloadline = Prepare-PlatformImportCSVPayload -TemplateId $TemplateId -CSV $csvdataline -ImportType $ImportType -ImportWithFolder $ImportWithFolder `
        -ImportwithTotp $ImportWithTotp -inheritFolderPermissions $inheritFolderPermissions -ChangeRemotePasswords $ChangeRemotePasswords
    
    # submitting the csv import data
    $results = Invoke-PlatformAPI -OverrideUriAPI "$($PlatformConnection.TenantHostName).secretservercloud.com/api/v1/secrets/import-csv-process" -Body $payloadline

    # getting the task identifier for this import job
    $taskidentifier = $results.taskidentifier

    # initial getting the progress of the import job
    $get = Invoke-PlatformAPI -OverrideUriAPI "$($PlatformConnection.TenantHostName).secretservercloud.com/api/v1/bulk-operations/$($taskidentifier)/progress" -Method Get

    # while the job is not complete
    while ($get.isComplete -ne $true)
    {
        # print the precent complete, wait 750 milliseconds then get the progress again
        Write-Host "$((Get-Date).ToString()) : $($get.statusMessage), Percent Complete: $(("{0:P2}" -f ($get.percentageComplete/100)))"
        Start-Sleep -Milliseconds 750

        $get = Invoke-PlatformAPI -OverrideUriAPI "$($PlatformConnection.Shortname).secretservercloud.com/api/v1/bulk-operations/$($taskidentifier)/progress" -Method Get
    }

    Write-Host "Done"

    return 
}# function global:Import-PlatformSecretsFromCsv 
#endregion
###########