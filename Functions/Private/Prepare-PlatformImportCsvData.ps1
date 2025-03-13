###########
#region ### global:Prepare-PlatformImportCSVData # CMDLETDESCRIPTION : Prepares passed csv data as part of the CSV Import Feature :
###########
function global:Prepare-PlatformImportCSVData
{
    <#
    .SYNOPSIS
    Prepares csv data as part of a json body payload for use with the CSV Import feature. For use with
    the Prepare-PlatformImportPayload cmdlet.

    .DESCRIPTION
    Prepares csv data as part of a json body payload for use with the CSV Import feature. For use with
    the Prepare-PlatformImportPayload cmdlet.

    .PARAMETER CsvData
    Specify the CSV data to format.

    .INPUTS
    None. You can't pipe input to this function.

    .OUTPUTS
    This function outputs a specially prepared csv data line for use with a json body payload.

    .EXAMPLE
    C:\PS> Prepare-PlatformImportCSVData -CsvData $CsvData
    This will take the provided csv data, convert it onto something useable for json and skips the first line (headers).
    #>
    [CmdletBinding(DefaultParameterSetName="Default")]
    param
    (
        [PSObject]$CsvData
    )

    $ModifiedCsvBody = ((($CsvData | ConvertTo-Csv | Select-Object -Skip 1) -replace '\\','\\')-replace '"','\"') -join "\n"

    return $ModifiedCsvBody
}# function global:Prepare-PlatformImportCSVData 
#endregion
###########