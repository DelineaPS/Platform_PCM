# class to hold a custom PlatformSecretFolder
[NoRunspaceAffinity()]
class PlatformSecretFolder
{
    [System.Int32]$id
    [System.String]$folderName
    [System.String]$folderPath
    [System.Int32]$parentFolderId
    [System.Int32]$folderTypeId
    [System.Int32]$secretPolicyId
    [System.Boolean]$inheritSecretPolicy
    [System.Boolean]$inheritPermissions

    # empty constructor
	PlatformSecretFolder () {}

    # primary constructor
    PlatformSecretFolder($f) 
	{
        $this.id                  = $f.id
        $this.folderName          = $f.folderName
        $this.folderPath          = $f.folderPath
        $this.parentFolderId      = $f.parentFolderId
        $this.folderTypeId        = $f.folderTypeId
        $this.secretPolicyId      = $f.secretPolicyId
        $this.inheritSecretPolicy = $f.inheritSecretPolicy
        $this.inheritPermissions  = $f.inheritPermissions
	}# PlatformSecretFolder($f) 
    
}# class PlatformSecretFolder