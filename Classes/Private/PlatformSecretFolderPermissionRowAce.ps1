# class to hold a custom PlatformSecretFolderPermissionRowAce
[NoRunspaceAffinity()]
class PlatformSecretFolderPermissionRowAce
{
    [System.Int32]$folderAccessRoleId
    [System.Int32]$groupId
    [System.Int32]$secretAccessRoleId
    [System.Int32]$userId

    # empty constructor
	PlatformSecretFolderPermissionRowAce () {}

    # primary constructor
    PlatformSecretFolderPermissionRowAce([System.Int32]$farid, [System.Int32]$gid, `
                                         [System.Int32]$sarid, [System.Int32]$uid)
	{
        $this.folderAccessRoleId = $farid
        $this.groupId            = $gid
        $this.secretAccessRoleId = $sarid
        $this.userId             = $uid
	}# PlatformSecretFolderPermissionRowAce($u) 
    
}# class PlatformSecretFolderPermissionRowAce