###########
#region ### global:Prepare-PlatformImportCSVPayload # CMDLETDESCRIPTION : Prepares a json payload for use with the CSV Import Feature :
###########
function global:Prepare-PlatformImportCSVPayload
{
    <#
    .SYNOPSIS
    Prepares a json body payload for use with the CSV Import Feature.

    .DESCRIPTION
    Prepares a json body payload for use with the CSV Import Feature.

    .PARAMETER TemplateId
    Specify the Secret Template Id to use for this import.

    .PARAMETER CSV 
    Specify the specially prepared CSV string data to use for this import. This must come from
    Prepare-PlatformImportCsvData.

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
    None. You can't pipe input to this function.

    .OUTPUTS
    This function outputs a special payload string.

    .EXAMPLE
    C:\PS> Prepare-PlatformImportCSVPayload -TemplateId 6001 -CSV $CsvString
    This will take the provided CSV string data for use with the Secret Template Id of 6001 (default Active Directory Account template)
    #>
    [CmdletBinding(DefaultParameterSetName="Default")]
    param
    (
        [Parameter(Mandatory = $true, HelpMessage = ".")]
        [System.Int32]$TemplateId,

        [Parameter(Mandatory = $true, HelpMessage = ".")]
        [System.String]$CSV,

        [Parameter(Mandatory = $false, HelpMessage = ".")]
        [ValidateSet("CSV")]
        [System.String]$ImportType = "CSV",

        [Parameter(Mandatory = $false, HelpMessage = ".")]
        [System.Boolean]$ImportWithFolder = $true,

        [Parameter(Mandatory = $false, HelpMessage = ".")]
        [System.Boolean]$ImportWithTotp = $false,

        [Parameter(Mandatory = $false, HelpMessage = ".")]
        [System.Boolean]$inheritFolderPermissions = $true,

        [Parameter(Mandatory = $false, HelpMessage = ".")]
        [System.Boolean]$ChangeRemotePasswords = $false
    )

    # ternary operators for settings
    $ImportWithTotp           ? ($payloadtotp    = "true") : ($payloadtotp    = "false") | Out-Null
    $ImportWithFolder         ? ($payloadfolder  = "true") : ($payloadfolder  = "false") | Out-Null
    $inheritFolderPermissions ? ($payloadinherit = "true") : ($payloadinherit = "false") | Out-Null
    $ChangeRemotePasswords    ? ($payloadchange  = "true") : ($payloadchange  = "false") | Out-Null

    # prepares the payload string
    $PayloadString = '{"data":{"importType":"' + $ImportType + '","csv":"' + $CSV + '","templateId":' + $TemplateId + ',"importWithTotp":' `
        + $payloadtotp + ',"importWithFolder":' + $payloadfolder + ',"changeRemotePasswords":' + $payloadchange + ',"inheritFolderPermissions":' + $payloadinherit + '}}'

    return $PayloadString
}# function global:Prepare-PlatformImportCSVPayload 
#endregion
###########