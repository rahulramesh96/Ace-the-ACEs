# Enumerate objects with GenericAll on user accounts (Red Team)
param(
    [Alias('d')]
    [Parameter(Mandatory=$true)]
    [string]$Domain,

    [Alias('a')]
    [switch]$IncludeAll
)

Import-Module ActiveDirectory

function Invoke-RandomCalculation {
    $a = Get-Random -Minimum 1 -Maximum 100
    $b = Get-Random -Minimum 1 -Maximum 100
    return $a + $b
}

function Invoke-JunkStringManipulation {
    $junkString = "abcdefghijklmnopqrstuvwxyz"
    $shuffledString = -join ($junkString.ToCharArray() | Sort-Object {Get-Random})
    return $shuffledString.Substring(0, 5)
}

# Junk function invocation (for obfuscation)
$null = Invoke-RandomCalculation
$null = Invoke-JunkStringManipulation

# Fetch all user objects from specified domain
$users = Get-ADUser -Filter * -Server $Domain -Properties DistinguishedName

foreach ($user in $users) {
    # Check ACL for each user
    $acl = Get-Acl -Path ("AD:\" + $user.DistinguishedName)
    foreach ($ace in $acl.Access) {
        if ($ace.ActiveDirectoryRights -match "GenericAll" -and ($IncludeAll -or $ace.IdentityReference -notmatch "^(NT AUTHORITY|BUILTIN|CREATOR|SYSTEM|Administrators)")) {
            [PSCustomObject]@{
                UserObject          = $user.SamAccountName
                IdentityWithControl = $ace.IdentityReference
                AccessControlType   = $ace.AccessControlType
            }
        }
    }
}
