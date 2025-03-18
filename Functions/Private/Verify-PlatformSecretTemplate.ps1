###########
#region ### global:Verify-PlatformSecretTemplate # CMDLETDESCRIPTION : Verifies if a Secret Server Secret Template exists or not :
###########
function global:Verify-PlatformSecretTemplate
{
    <#
    .SYNOPSIS
    Verifies if a Secret Server Secret Template exists or not.

    .DESCRIPTION
    This cmdlet will throw an exception if the provided Name for a Secret Template does not exist for the user.

    Note: it may be possible that the template does exist, but this user does not have any permissions to see
    it.

    .PARAMETER Name
    Specify the name of the template to check if it is missing. Only exact name matches will work.

    .INPUTS
    None. You can't pipe input to this function.

    .OUTPUTS
    This function throws an error if the template is not found.

    .EXAMPLE
    C:\PS> Verify-PlatformSecretTemplate -Name "PAS Imported Text Secrets"
    This cmdlet will check if the Secret Template "PAS Imported Text Secrets" exists for this user. 
    - if it does not exist, throw an exception.
    #>
    [CmdletBinding(DefaultParameterSetName="All")]
    param
    (
        [Parameter(Mandatory = $true, HelpMessage = "The name of the Secret Template to search.", ParameterSetName = "Name")]
        [System.String]$Name
    )

    # verifying an active Platform connection
    Verify-PlatformConnection

    if (Is-TemplateMissing -Name $Name)
    {
        throw ("Secret Template [{0}] not found." -f $Name)
    }
}# function global:Verify-PlatformSecretTemplate
#endregion
###########