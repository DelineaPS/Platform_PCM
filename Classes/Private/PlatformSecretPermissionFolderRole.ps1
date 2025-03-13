# class to hold a custom PlatformSecretPermissionFolderRole
[NoRunspaceAffinity()]
class PlatformSecretPermissionFolderRole
{
    [System.Int32]$id
    [System.String]$name
    [System.Boolean]$enabled
    [System.DateTime]$created
    [System.Boolean]$isSystem

    # empty constructor
	PlatformSecretPermissionFolderRole () {}

    # primary constructor
    PlatformSecretPermissionFolderRole($r) 
	{
        $this.id = $r.id
        $this.name = $r.name
        $this.enabled = $r.enabled
        $this.created = $r.created
        $this.isSystem = $r.isSystem
	}# PlatformSecretPermissionFolderRole($u) 
    
}# class PlatformSecretPermissionFolderRole