# class to hold a custom PlatformUser
[NoRunspaceAffinity()]
class PlatformUser
{
    [System.String]$sourceds
    [System.String]$cloudstate
    [System.String]$email
    [System.String]$directorysericeuuid
    [System.String]$displayname
    [System.String]$platformusermembershiptype
    [System.Boolean]$securityquestionset
    [System.String]$riskscore
    [System.String]$visibility
    [System.String]$forest
    [System.DateTime]$lastlogin
    [System.DateTime]$lastinvite
    [System.String]$status
    [System.String]$username
    [System.String]$statusenum
    [System.String]$usertype
    [System.String]$searchemail
    [System.String]$statusdescription
    [System.Boolean]$serviceuser
    [System.String]$sourcedslocalized
    [System.String]$sourcedsinstance
    [System.String]$sourcedstype
    [System.String]$ID
    [System.int32]$securityquestioncount
    [System.DateTime]$phonepinlastchangedate

    # empty constructor
	PlatformUser () {}

    # primary constructor
    PlatformUser($u) 
	{
		$this.sourceds                   = $u.sourceds
        $this.cloudstate                 = $u.cloudstate
        $this.email                      = $u.email
        $this.directorysericeuuid        = $u.directorysericeuuid
        $this.displayname                = $u.displayname
        $this.platformusermembershiptype = $u.platformusermembershiptype
        $this.securityquestionset        = $u.securityquestionset
        $this.riskscore                  = $u.riskscore
        $this.visibility                 = $u.visibility
        $this.forest                     = $u.forest
        $this.status                     = $u.status
        $this.username                   = $u.username
        $this.statusenum                 = $u.statusenum
        $this.usertype                   = $u.usertype
        $this.searchemail                = $u.searchemail
        $this.statusdescription          = $u.statusdescription
        $this.serviceuser                = $u.serviceuser
        $this.sourcedslocalized          = $u.sourcedslocalized
        $this.sourcedsinstance           = $u.sourcedsinstance
        $this.sourcedstype               = $u.sourcedstype
        $this.ID                         = $u.ID
        $this.securityquestioncount      = $u.securityquestioncount

        if ($u.lastlogin          -eq $null) { $this.lastlogin              = 0 }
        if ($u.lastinvite         -eq $null) { $this.lastinvite             = 0 }
        if ($u.phonepinlastchange -eq $null) { $this.phonepinlastchangedate = 0 }
	}# PlatformUser($u) 
    
}# class PlatformUser