# class to hold a custom PlatformSecretPermissionSecretRole
[NoRunspaceAffinity()]
class PlatformSecretPermissionSecretRole
{
    [System.Int32]$id
    [System.String]$name
    [System.Boolean]$enabled
    [System.DateTime]$created
    [System.Boolean]$isSystem

    # empty constructor
	PlatformSecretPermissionSecretRole () {}

    # primary constructor
    PlatformSecretPermissionSecretRole($r) 
	{
        $this.id = $r.id
        $this.name = $r.name
        $this.enabled = $r.enabled
        $this.created = $r.created
        $this.isSystem = $r.isSystem
	}# PlatformSecretPermissionSecretRole($u) 
    
}# class PlatformSecretPermissionSecretRole