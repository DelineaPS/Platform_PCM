# class to hold a custom PlatformSecretUser
[NoRunspaceAffinity()]
class PlatformSecretUser
{
    [System.Int32]$id
    [System.String]$userName
    [System.String]$emailAddress
    [System.String]$externalUserSource


    # empty constructor
	PlatformSecretUser () {}

    # primary constructor
    PlatformSecretUser($u) 
	{
        $this.id                 = $u.id
        $this.userName           = $u.userName
        $this.emailAddress       = $u.emailAddress
        $this.externalUserSource = $u.externalUserSource
	}# PlatformSecretUser($u) 
    
}# class PlatformSecretUser