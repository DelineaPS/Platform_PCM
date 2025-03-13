# class to hold PlatformSecretServerVaults
[NoRunspaceAffinity()]
class PlatformSecretServerVault
{
    [System.String]$VaultId
    [System.String]$Name
    [System.String]$Type
    [System.Boolean]$isDefault
    [System.Boolean]$isGlobalDefault
    [System.Boolean]$isActive
    [System.String]$Url
    [System.String]$oAuthProfileId

    # empty constructor
	PlatformSecretServerVault () {}

    # primary constructor
    PlatformSecretServerVault($v)
    {
        $this.VaultId = $v.VaultId
        $this.Name = $v.name
        $this.Type = $v.type
        $this.isDefault = $v.isDefault
        $this.isGlobalDefault = $v.isGlobalDefault
        $this.isActive = $v.isActive
        $this.Url = $v.connection.url
        $this.oAuthProfileId = $v.connection.oAuthProfileId
    }
}# class PlatformSecretServerVault