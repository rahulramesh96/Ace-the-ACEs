# Enumerate objects with GenericAll on group accounts (Red Team)
param(
    [Alias('d')]
    [Parameter(Mandatory=$true)]
    [string]$Domain,

    [Alias('a')]
    [switch]$IncludeAll
)

Import-Module ActiveDirectory

function Invoke-RandomCalculation {
    $x = Get-Random -Minimum 10 -Maximum 200
    $y = Get-Random -Minimum 10 -Maximum 200
    return $x * $y
}

function Invoke-JunkHashGeneration {
    $randomString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return -join (1..10 | ForEach-Object { $randomString[(Get-Random -Maximum $randomString.Length)] })
}

# Junk function invocation (for obfuscation)
$null = Invoke-RandomCalculation
$null = Invoke-JunkHashGeneration

# Fetch all group objects from specified domain
$groups = Get-ADGroup -Filter * -Server $Domain -Properties DistinguishedName

foreach ($group in $groups) {
    # Check ACL for each group
    $acl = Get-Acl -Path ("AD:\" + $group.DistinguishedName)
    foreach ($ace in $acl.Access) {
        if ($ace.ActiveDirectoryRights -match "GenericAll" -and ($IncludeAll -or $ace.IdentityReference -notmatch "^(NT AUTHORITY|BUILTIN|CREATOR|SYSTEM|Administrators)")) {
            [PSCustomObject]@{
                GroupObject         = $group.SamAccountName
                IdentityWithControl = $ace.IdentityReference
                AccessControlType   = $ace.AccessControlType
            }
        }
    }
}
