# obtained from https://github.com/allynl93/getSAMLResponse-Interactive/blob/main/PowerShell%20New-SAMLInteractive%20Module/PS-SAML-Interactive.psm1
# modified for our use case
function New-SAMLInteractive{

    [CmdletBinding()]
	param(
		[Parameter(Mandatory=$true)]
		[string] $LoginIDP
	)

    Begin{

        $SamlMatch     = '(?i)name="SAMLResponse"(?: type="hidden")? value=\"(.*?)\"(?:.*)?\/>'
        $RelayMatch    = '(?i)name="RelayState"(?: type="hidden")? value=\"(.*?)\"(?:.*)?\/>'
        $CallBackMatch = '(?i)<form .*?action="(https.*?)".*>'

        Add-Type -AssemblyName System.Windows.Forms 
        Add-Type -AssemblyName System.Web

    }

    Process{

        # create window for embedded browser
        $form = New-Object Windows.Forms.Form
        $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen;
        $form.Width = 640
        $form.Height = 700
        $form.showIcon = $false
        $form.TopMost = $true
    
        $web = New-Object Windows.Forms.WebBrowser
        $web.Size = $form.ClientSize
        $web.Anchor = "Left,Top,Right,Bottom"
        $web.ScriptErrorsSuppressed = $true

        $form.Controls.Add($web)

        $web.Navigate($LoginIDP)
        
        $web.add_Navigating({
    
            if ($web.DocumentText -match "SAMLResponse"){

                $_.cancel = $true

                # probably a better way to do this but this will work for now
                if ($web.DocumentText -match $SamlMatch){

                    $Script:SAMLResponse = $(($Matches[1] -replace '&#x2b;', '+') -replace '&#x3d;', '=')

                    if ($web.DocumentText -match $RelayMatch){

                        $Script:RelayState = $(($Matches[1] -replace '&#x2b;', '+') -replace '&#x3d;', '=')

                        if ($web.DocumentText -match $CallBackMatch){

                            # replacing bad characters in the callback url
                            $Script:CallBackUrl = $(((($Matches[1]  -replace '&#x2b;', '+') -replace '&#x3d;', '=') -replace '&#x3a;', ':') -replace '&#x2f;', '/')

                        }
                    }

                    $form.Close()
                }# if ($web.DocumentText -match $SamlMatch){
            }# if ($web.DocumentText -match "SAMLResponse"){
        })# $web.add_Navigating({
    
        # show browser window, waits for window to close
        if([system.windows.forms.application]::run($form) -ne "OK") {
            
            if ($null -ne $Script:SAMLResponse){

                $obj = New-Object psobject

                $obj | Add-Member -MemberType NoteProperty -Name CallBackUrl  -Value $Script:CallBackUrl
                $obj | Add-Member -MemberType NoteProperty -Name SamlResponse -Value $Script:SAMLResponse
                $obj | Add-Member -MemberType NoteProperty -Name RelayState   -Value $Script:RelayState
                
                $obj
                $form.Close()
                Remove-Variable -Name CallBackUrl  -Scope Script -ErrorAction SilentlyContinue
                Remove-Variable -Name SAMLResponse -Scope Script -ErrorAction SilentlyContinue
                Remove-Variable -Name RelayState   -Scope Script -ErrorAction SilentlyContinue

            }# if ($null -ne $Script:SAMLResponse){
            Else{
            
                throw "SAMLResponse not matched"
            
            }
    
        }
    }# Process{

    End{
        
        $form.Dispose()
        
    }
}# function New-SAMLInteractive{