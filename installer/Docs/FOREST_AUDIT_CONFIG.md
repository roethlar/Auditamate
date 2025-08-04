# Forest Audit Configuration Guide

## Overview

The forest audit tool supports domain-specific group configuration, allowing you to specify different privileged groups to audit in each domain.

## Configuration File Location

`[Installation Directory]\Config\forest-audit-config.json`

## Configuration Structure

```json
{
    "DomainGroups": {
        "_default": [
            // Groups to audit in all domains unless overridden
            "Domain Admins",
            "Administrators",
            "Account Operators"
        ],
        "domain1.company.com": [
            // Specific groups for this domain
            "Domain Admins",
            "Custom-Privileged-Group"
        ],
        "domain2.company.com": [
            // Different groups for this domain
            "Domain Admins",
            "Special-Admin-Group"
        ]
    },
    "ExcludeGroups": [
        // Groups to never audit even if discovered
        "Domain Computers",
        "Domain Users"
    ]
}
```

## Key Features

### Domain-Specific Configuration
- Define different privileged groups for each domain
- Use `_default` for common groups across all domains
- Domain-specific settings override defaults

### Exclude Groups
- Prevent auditing of large non-privileged groups
- Useful for excluding Domain Computers, Domain Users, etc.

### Forest Root Groups
- Enterprise Admins and Schema Admins are automatically included for root domain
- Can be configured in the root domain section

## Example Configuration

For a forest with root domain `corp.company.com` and child domain `users.company.com`:

```json
{
    "DomainGroups": {
        "_default": [
            "Domain Admins",
            "Administrators",
            "Server Operators",
            "Backup Operators"
        ],
        "corp.company.com": [
            "Enterprise Admins",
            "Schema Admins",
            "Domain Admins",
            "Administrators"
        ],
        "users.company.com": [
            "Domain Admins",
            "Administrators",
            "IT-SecurityAdmins",
            "IT-HelpDeskAdmins"
        ]
    }
}
```

## Fallback Behavior

If no configuration file exists or DomainGroups is not defined:
1. The tool will discover standard privileged groups automatically
2. It will audit Domain Admins, Enterprise Admins, etc.
3. A warning will indicate that default discovery is being used

## Best Practices

1. **Review Regularly**: Update the configuration as new privileged groups are created
2. **Include Custom Groups**: Add any domain-specific admin groups
3. **Exclude Large Groups**: Always exclude Domain Computers, Domain Users
4. **Test First**: Run with a small set of groups to verify access before full audit