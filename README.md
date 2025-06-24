# GenericAllUser.ps1

## Purpose:
Enumerates all Active Directory objects that have GenericAll permissions on user accounts. Useful for Red Teaming to identify potential privilege escalation paths.

Enumerates all the accounts
`.\GenericAllUser.ps1 -d <DomainName> -a` 

Enumerates non-admin accounts.
`.\GenericAllUser.ps1 -d <DomainName>`
