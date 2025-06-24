# GenericAllUser.ps1

## Purpose:
Enumerates all Active Directory objects that have GenericAll permissions on user accounts. Useful for Red Teaming to identify potential privilege escalation paths.

Enumerates all the accounts
`.\GenericAllUser.ps1 -d <DomainName> -a`

Enumerates non-admin accounts.
`.\GenericAllUser.ps1 -d <DomainName>`

# GenericAllGroup.ps1

## Purpose:
Enumerates all Active Directory groups where another user/object has GenericAll permissions. Useful in Red Teaming to find privilege escalation paths through group control.

Enumerates all the accounts
`.\GenericAllGroup.ps1 -d <DomainName> -a`

Enumerates non-admin accounts.
`.\GenericAllGroup.ps1 -d <DomainName>`

