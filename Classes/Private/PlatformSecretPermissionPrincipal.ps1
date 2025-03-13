# class to hold a custom PlatformSecretPermissionPrincipal
[NoRunspaceAffinity()]
class PlatformSecretPermissionPrincipal
{
    [System.String]$name
    [System.String]$displayName
    [System.Int32]$groupId
    [System.Int32]$userId
    [System.String]$domainName


    # empty constructor
	PlatformSecretPermissionPrincipal () {}

    # primary constructor
    PlatformSecretPermissionPrincipal($p) 
	{
        $this.name        = $p.name
        $this.displayName = $p.displayName
        $this.groupId     = $p.groupId
        $this.userId      = $p.userId
        $this.domainName  = $p.domainName
	}# PlatformSecretPermissionPrincipal($u) 
    
}# class PlatformSecretPermissionPrincipal