###########
#region ### global:Connect-PlatformInstance # CMDLETDESCRIPTION : Connects the user to a Platform Instance :
###########
function global:Connect-PlatformInstance
{
	<#
	.SYNOPSIS
    This cmdlet connects you to a Platform Instance.

    .DESCRIPTION
    This cmdlet will connect you to a Platform Instance. Information about your connection information will
    be stored in global variables that will only exist for this PowerShell session.

    .PARAMETER Url
    Enter the url to connect to, for example myurl.delinea.app.

    .PARAMETER User
    Enter the user to connect as, for example cloudadmin@mydomain.com.

    .INPUTS
    None.

    .OUTPUTS
    This cmdlet only outputs some information to the console window once connected. The cmdlet will store
    all relevant connection information in global variables that exist for this session only.

    .EXAMPLE
    C:\PS> Connect-PlatformInstance -Url myurl.delinea.app -User myuser@domain.com
    This cmdlet will attempt to connect to myurl.delinea.app with the user myuser@domain.com. You
    will be prompted for password and MFA challenges relevant for the user myuser@domain.com.
	#>
    [CmdletBinding(DefaultParameterSetName="All")]
	param
	(
		[Parameter(Mandatory = $true, Position = 0, HelpMessage = "Specify the URL to use for the connection (e.g. oceanlab.my.centrify.net).")]
		[System.String]$Url,
		
		[Parameter(Mandatory = $true, ParameterSetName = "Interactive", HelpMessage = "Specify the User login to use for the connection (e.g. CloudAdmin@oceanlab.my.centrify.net).")]
		[System.String]$User,
        
        [Parameter(Mandatory = $true, ParameterSetName = "OAuth2", HelpMessage = "Specify the OAuth2 Client ID to use to obtain a Bearer Token.")]
        [System.String]$Client,

		[Parameter(Mandatory = $true, ParameterSetName = "OAuth2", HelpMessage = "Specify the OAuth2 Scope Name to claim a Bearer Token for.")]
        [System.String]$Scope,

		[Parameter(Mandatory = $true, ParameterSetName = "OAuth2", HelpMessage = "Specify the OAuth2 Secret to use for the ClientID.")]
        [System.String]$Secret,

        [Parameter(Mandatory = $false, ParameterSetName = "Base64", HelpMessage = "Encode Base64 Secret to use for OAuth2.")]
        [Switch]$EncodeSecret
	)
	
	# Debug preference
	if ($PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent)
	{
		# Debug continue without waiting for confirmation
		$DebugPreference = "Continue"
	}
	else 
	{
		# Debug message are turned off
		$DebugPreference = "SilentlyContinue"
	}

	# if EncodeSecret was used
	if ($EncodeSecret.IsPresent)
	{
		Try
		{
			# Get Confidential Client name and password
			$Client = Read-Host "Confidential Client name"
			$SecureString = Read-Host "Password" -AsSecureString
			$Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString))
			# Return Base64 encoded secret
			$AuthenticationString = ("{0}:{1}" -f $Client, $Password)
			return ("Secret: {0}" -f [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($AuthenticationString)))
	
		}
		Catch
		{
			$e = New-Object PlatfromPCPException -ArgumentList ("Error during Connect-PlatformInstance -EncodeSecret.")
			$e.AddExceptionData($_)
		}
	}# if ($EncodeSecret.IsPresent)

	# Set Security Protocol for RestAPI (must use TLS 1.2)
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

	# Check if URL provided has "https://" in front, if so, remove it.
	if ($Url.ToLower().Substring(0,8) -eq "https://")
	{
		$Url = $Url.Substring(8)
	}

	Write-Verbose ("Url is [{0}]" -f $Url)
	
	# if the OAuth2 version was used
	if ($PSCmdlet.ParameterSetName -eq "OAuth2")
	{
		 # Delete any existing connection cache
		 $Global:PlatformConnection = [Void]$null

		 # Get Bearer Token from OAuth2 Client App
		 $BearerToken = Get-PASBearerToken -Url $Url -Client $Client -Secret $Secret -Scope $Scope

		 # Validate Bearer Token and obtain Session details
		 $Uri = ("https://{0}/Security/Whoami" -f $Url)
		 $ContentType = "application/json" 
		 $Header = @{ "X-CENTRIFY-NATIVE-CLIENT" = "1"; "Authorization" = ("Bearer {0}" -f $BearerToken) }
		 Write-Debug ("Connecting to Delinea Platform (https://{0}) using Bearer Token" -f $Url)

		# Format Json query
		$Json = @{} | ConvertTo-Json
		
		Try
		{
			# Connect using Bearer Token
			$WebResponse = Invoke-WebRequest -UseBasicParsing -Method Post -SessionVariable PlatformSession -Uri $Uri -Body $Json -ContentType $ContentType -Headers $Header
		}
		Catch
		{
			$e = New-Object PlatfromPCPException -ArgumentList ("Error during Connect-PlatformInstance via bearer token.")
			$e.AddExceptionData($_)
			$e.AddData("WebResponse",$WebResponse)
			$e.AddData("Uri",$Uri)
			$e.AddData("Json",$Json)
			$global:LastPAS_PCMError = $e
		}

		# assuming we were successful
		$WebResponseResult = $WebResponse.Content | ConvertFrom-Json
		if ($WebResponseResult.Success)
		{
			# Get Connection details
			$Connection = $WebResponseResult.Result
			
			# Force URL into PodFqdn to retain URL when performing MachineCertificate authentication
			$Connection | Add-Member -MemberType NoteProperty -Name CustomerId -Value $Connection.TenantId
			$Connection | Add-Member -MemberType NoteProperty -Name PodFqdn -Value $Url
			
			# Add session to the Connection
			$Connection | Add-Member -MemberType NoteProperty -Name Session -Value $PlatformSession

			# Set Connection as global
			$Global:PlatformConnection = $Connection

			# setting the splat
			$global:PlatformSessionInformation = @{ Headers = $PlatformConnection.Session.Headers }

			# if the $PlatformConnections variable does not contain this Connection, add it
			if (-Not ($PlatformConnections | Where-Object {$_.PodFqdn -eq $Connection.PodFqdn}))
			{
				# add a new PlatformConnection object and add it to our $PlatformConnectionsList
				$obj = New-Object PlatformConnection -ArgumentList ($Connection.PodFqdn, $Connection, $global:PlatformSessionInformation)
				$global:PlatformConnections.Add($obj) | Out-Null
			}
			
			# Return information values to confirm connection success
			return ($Connection | Select-Object -Property CustomerId, User, PodFqdn | Format-List)
		}
		else
		{
			Write-Error "Invalid Bearer Token"
			Exit 1
		}
	}# if ($PSCmdlet.ParameterSetName -eq "OAuth2")

	# if the Interactive version was used
	elseif ($PSCmdlet.ParameterSetName -eq "Interactive")
	{
		Write-Verbose ("Interactive login used.")

		# Setup variable for interactive connection using MFA
		$Uri = ("https://{0}/identity/Security/StartAuthentication" -f $Url)
		$BaseUrl = $Url.split(".")[1..$Url.Length] -join '.'
		$ContentType = "application/json" 
		$Header = @{ "X-CENTRIFY-NATIVE-CLIENT" = "true" }
		Write-Host ("Connecting to Delinea Platform (https://{0}) as {1}`n" -f $Url, $User)

        # Debug informations
        Write-Debug ("Uri= {0}" -f $Uri)
        Write-Debug ("Login= {0}" -f $UserName)

		# Format Json query
		$Auth = @{}
		$Auth.TenantId = $Url.Split('.')[0]
		$Auth.User = $User
		$Auth.Version = "1.0"
		$Json = $Auth | ConvertTo-Json

		Try # StartAuthentication
		{
			# Initiate connection
			$InitialResponse = Invoke-WebRequest -UseBasicParsing -Method Post -SessionVariable PlatformSession -Uri $Uri -Body $Json -ContentType $ContentType -Headers $Header

		}
		Catch
		{
			$e = New-Object PlatfromPCPException -ArgumentList ("Error during StartAuthentication on Interactive Connect-PlatformInstance.")
			$e.AddExceptionData($_)
			$e.AddData("InitialResponse",$InitialResponse)
			$e.AddData("Uri",$Uri)
			$e.AddData("Json",$Json)
			$global:LastPAS_PCMError = $e
		}

		# Getting Authentication challenges from initial Response
		$InitialResponseResult = $InitialResponse.Content | ConvertFrom-Json

		Write-Verbose ("Initial Response Success is [{0}]" -f $InitialResponseResult.Success)
		
		# if the initial response was a success
		if ($InitialResponseResult.Success)
		{
			# testing for Federation Redirect
			# if the IdpRedirectUrl property is not null or empty
			if (-Not ([System.String]::IsNullOrEmpty($InitialResponseResult.Result.IdpRedirectUrl)))
			{
				Write-Verbose ("Federation detected.")
				
				# get the relay state
				$relaystate = $InitialResponseResult.Result.IdpRedirectUrl -replace '^.*?&RelayState=(.*?)&SigAlg=.*$','$1'

				# getting the SamlResponse, derived from https://github.com/allynl93/getSAMLResponse-Interactive/blob/main/PowerShell%20New-SAMLInteractive%20Module/PS-SAML-Interactive.psm1
				$SamlResponse = New-SAMLInteractive -LoginIDP $InitialResponseResult.Result.IdpRedirectUrl

				# preparing the body response back to PAS/PAS
				$bodyresponse = ("SAMLResponse={0}&RelayState={1}" -f [System.Web.HttpUtility]::UrlEncode($samlresponse), $relaystate)

				# get the TenantID from the URL
				$TenantID = (Resolve-DnsName -Name $Url).NameHost[0].Split(".")[0]

				# this is now getting me the ASPXAUTH
				$aftersaml = Invoke-WebRequest -Method Post -Uri ('https://{0}.{1}/home' -f $TenantID, $BaseUrl) -Body ("{0}" -f $bodyresponse) -WebSession $PlatformSession

				# setting up the regex to grab the AuthData
				$regex = '\s*var AuthData = ({.*?}});'

				# grabbing the AuthData line from the raw html content, this is to parse out Connection details
				$authdataline = [regex]::Match($aftersaml.RawContent,$regex,[System.Text.RegularExpressions.RegexOptions]::Singleline).Groups[0].Value

				# getting the JSON form of the AuthData property
				$authdatajson = ($authdataline -replace '.*var AuthData = (.*}});.*','$1') | ConvertFrom-Json

				# building the custom PlatformConnection object
				$PlatformConnection = New-Object PSCustomObject

				# setting addition properties manually
				$PlatformConnection | Add-Member -MemberType NoteProperty -Name AuthLevel -Value $authdatajson.AmIAuthenticated.AuthLevel
				$PlatformConnection | Add-Member -MemberType NoteProperty -Name DisplayName -Value $authdatajson.AmIAuthenticated.DisplayName
				$PlatformConnection | Add-Member -MemberType NoteProperty -Name UserId -Value $authdatajson.AmIAuthenticated.UserId
				$PlatformConnection | Add-Member -MemberType NoteProperty -Name PodFqdn -Value ("{0}.{1}" -f $TenantID, $BaseUrl)
				$PlatformConnection | Add-Member -MemberType NoteProperty -Name TenantID -Value $TenantID
				$PlatformConnection | Add-Member -MemberType NoteProperty -Name SourceDsType -Value $authdatajson.AmIAuthenticated.SourceDsType
				$PlatformConnection | Add-Member -MemberType NoteProperty -Name Session -Value $PlatformSession

				# Set Connection as global
				$global:PlatformConnection = $PlatformConnection

				# setting the splat for variable connection 
				$global:PlatformSessionInformation = @{ WebSession = $PlatformConnection.Session ; ContentType = "application/json"}

				# Return information values to confirm connection success
				return ($PlatformConnection | Select-Object -Property TenantID, UserId, PodFqdn | Format-List)

			}# if (-Not ([System.String]::IsNullOrEmpty($InitialResponseResult.Result.IdpRedirectUrl)))

			Write-Verbose ("Going through each challenge")

			# Go through all challenges
			foreach ($Challenge in $InitialResponseResult.Result.Challenges)
			{
				# Go through all available mechanisms
				if ($Challenge.Mechanisms.Count -gt 1)
				{
					Write-Host "`n[Available mechanisms]"
					# More than one mechanism available
					$MechanismIndex = 1
					foreach ($Mechanism in $Challenge.Mechanisms)
					{
						# Show Mechanism
						Write-Host ("{0} - {1}" -f $MechanismIndex++, $Mechanism.PromptSelectMech)
					}
					
					# Prompt for Mechanism selection
					$Selection = Read-Host -Prompt "Please select a mechanism [1]"
					# Default selection
					if ([System.String]::IsNullOrEmpty($Selection))
					{
						# Default selection is 1
						$Selection = 1
					}
					# Validate selection
					if ($Selection -gt $Challenge.Mechanisms.Count)
					{
						# Selection must be in range
						Throw "Invalid selection. Authentication challenge aborted." 
					}
				}# if ($Challenge.Mechanisms.Count -gt 1)
				elseif($Challenge.Mechanisms.Count -eq 1)
				{
					# Force selection to unique mechanism
					$Selection = 1
				}
				else
				{
					# Unknown error
					Throw "Invalid number of mechanisms received. Authentication challenge aborted."
				}

				# Select chosen Mechanism and prepare answer
				$ChosenMechanism = $Challenge.Mechanisms[$Selection - 1]

				# Format Json query
				$Auth = @{}
				$Auth.TenantId = $InitialResponseResult.Result.TenantId
				$Auth.SessionId = $InitialResponseResult.Result.SessionId
				$Auth.MechanismId = $ChosenMechanism.MechanismId
				
				# Decide for Prompt or Out-of-bounds Auth
				switch($ChosenMechanism.AnswerType)
				{
					"Text" # Prompt User for answer
					{
						$Auth.Action = "Answer"
						# Prompt for User answer using SecureString to mask typing
						$SecureString = Read-Host $ChosenMechanism.PromptMechChosen -AsSecureString

						if([System.Environment]::OSVersion.Platform -like "Win32*"){
							$Auth.Answer = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString))
						# Made this so it could kinda work on CentOS 9; This is the way it has be for Linux to decrypt priv string
						}elseif([System.Environment]::OSVersion.Platform -eq "Unix"){
							$Auth.Answer = $(ConvertFrom-SecureString -SecureString $secureString -AsPlainText)
						}else{
							throw [System.SystemException]::new("Somehow OS was missed. Need to stop NOW.")}
					}
					
					"StartTextOob" # Out-of-bounds Authentication (User need to take action other than through typed answer)
					{
						$Auth.Action = "StartOOB"
						# Notify User for further actions
						Write-Host $ChosenMechanism.PromptMechChosen
					}
				}
				$Json = $Auth | ConvertTo-Json
				
				# Send Challenge answer
				$Uri = ("https://{0}/identity/Security/AdvanceAuthentication" -f $Url)
				$ContentType = "application/json" 
				$Header = @{ "X-CENTRIFY-NATIVE-CLIENT" = "1" }

				Write-Verbose ("Attempting AdvancedAuthentication")

				Try
				{
					# Send answer
					$WebResponse = Invoke-WebRequest -UseBasicParsing -Method Post -SessionVariable PlatformSession -Uri $Uri -Body $Json -ContentType $ContentType -Headers $Header
				}
				Catch
				{
					$e = New-Object PlatfromPCPException -ArgumentList ("Error during 1st AdvanceAuthentication on Interactive Connect-PlatformInstance.")
					$e.AddExceptionData($_)
					$e.AddData("WebResponse",$WebResponse)
					$e.AddData("Uri",$Uri)
					$e.AddData("Json",$Json)
					$global:LastPAS_PCMError = $e
				}

				# Get Response
				$WebResponseResult = $WebResponse.Content | ConvertFrom-Json

				Write-Verbose ("Initial Response Success is [{0}]" -f $WebResponseResult.Success)
				
				# if the first AdvancedAuthentication was a success
				if ($WebResponseResult.Success)
				{
					# Evaluate Summary response
					if ($WebResponseResult.Result.Summary -eq "OobPending")
					{
						$Answer = Read-Host "Enter code then press <enter> to finish authentication"
						# Send Poll message to Delinea Identity Platform after pressing enter key
						$Uri = ("https://{0}/identity/Security/AdvanceAuthentication" -f $Url)
						$ContentType = "application/json" 
						$Header = @{ "X-CENTRIFY-NATIVE-CLIENT" = "1" }

						# Format Json query
						$Auth = @{}
						$Auth.TenantId = $InitialResponseResult.Result.TenantId
						$Auth.SessionId = $InitialResponseResult.Result.SessionId
						$Auth.MechanismId = $ChosenMechanism.MechanismId
						
						# Either send entered code or poll service for answer
						if ([System.String]::IsNullOrEmpty($Answer))
						{
							$Auth.Action = "Poll"
						}
						else
						{
							$Auth.Action = "Answer"
							$Auth.Answer = $Answer
						}
						$Json = $Auth | ConvertTo-Json
						
						Try
						{
							# Send Poll message or Answer
							$WebResponse = Invoke-WebRequest -UseBasicParsing -Method Post -SessionVariable PlatformSession -Uri $Uri -Body $Json -ContentType $ContentType -Headers $Header
						}
						Catch
						{
							$e = New-Object PlatformPCMException -ArgumentList ("Error during 2nd AdvanceAuthentication on Interactive Connect-PlatformInstance.")
							$e.AddExceptionData($_)
							$e.AddData("WebResponse",$WebResponse)
							$e.AddData("Uri",$Uri)
							$e.AddData("Json",$Json)
							$global:LastPAS_PCMError = $e
						}

						# Get Response
						$WebResponseResult = $WebResponse.Content | ConvertFrom-Json

						if ($WebResponseResult.Result.Summary -ne "LoginSuccess")
						{
							Write-Error "Failed to receive challenge answer or answer is incorrect. Authentication challenge aborted."
                            $global:Auth = $Auth
						}
					}# if ($WebResponseResult.Result.Summary -eq "OobPending")

					# If summary return LoginSuccess at any step, we can proceed with session
					if ($WebResponseResult.Result.Summary -eq "LoginSuccess")
					{
						# Get Session Token from successfull login
						Write-Debug ("WebResponse=`n{0}" -f $WebResponseResult)

                        # Get Connection details
                        $Connection = $WebResponseResult.Result
        
                        # Add session to the Connection
                        $Connection | Add-Member -MemberType NoteProperty -Name Session -Value $PlatformSession

                        # removing the identity part of the pod FQDN
                        $Connection.PodFqdn = $Connection.PodFqdn -replace '/identity',''

                        # Set Connection as global
                        $Global:PlatformConnection = $Connection


                        # setting the bearer token header
                        $accesstoken = $Connection.OAuthTokens.access_token
                        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
                        $headers.Add("Authorization","Bearer $accesstoken")

                        # setting the splat
                        $global:PlatformSessionInformation = @{ Headers = $headers; ContentType = "application/json" }

                        <# leaving this out for now, but this will be added later to support multiple Platform connections
                        # if the $PlatformConnections variable does not contain this Connection, add it
                        if (-Not ($PlatformConnections | Where-Object {$_.PodFqdn -eq $Connection.PodFqdn}))
                        {
                            # add a new PlatformConnection object and add it to our $PlatformConnectionsList
                            $obj = New-Object PlatformConnection -ArgumentList ($Connection.PodFqdn,$Connection,$global:PlatformSessionInformation)
                            $global:PlatformConnections.Add($obj) | Out-Null
                        } #>
        
                        # Return information values to confirm connection success
                        return ($Connection | Select-Object -Property CustomerId, User, PodFqdn | Format-List)
						
					}# if ($WebResponseResult.Result.Summary -eq "LoginSuccess")
				}# if ($WebResponseResult.Success)
				else
				{
					Throw $WebResponseResult.Message
				}
			}# foreach ($Challenge in $InitialResponseResult.Result.Challenges)
		}# if ($InitialResponseResult.Success)
		else
		{
			# Unsuccesful connection
			Throw $InitialResponseResult.Message
		}
	}# elseif ($PSCmdlet.ParameterSetName -eq "Interactive")
}# function global:Connect-PlatformInstance
#endregion
###########