<!-- region Generated -->
# Az.Purview
This directory contains the PowerShell module for the Purview service.

---
## Status
[![Az.Purview](https://img.shields.io/powershellgallery/v/Az.Purview.svg?style=flat-square&label=Az.Purview "Az.Purview")](https://www.powershellgallery.com/packages/Az.Purview/)

## Info
- Modifiable: yes
- Generated: all
- Committed: yes
- Packaged: yes

---
## Detail
This module was primarily generated via [AutoRest](https://github.com/Azure/autorest) using the [PowerShell](https://github.com/Azure/autorest.powershell) extension.

## Module Requirements
- [Az.Accounts module](https://www.powershellgallery.com/packages/Az.Accounts/), version 2.2.3 or greater

## Authentication
AutoRest does not generate authentication code for the module. Authentication is handled via Az.Accounts by altering the HTTP payload before it is sent.

## Development
For information on how to develop for `Az.Purview`, see [how-to.md](how-to.md).
<!-- endregion -->

### AutoRest Configuration
> see https://aka.ms/autorest

``` yaml
branch: 0dd6671cd8e404b1c7fab25f93607fbca0afaedf
require:
  - $(this-folder)/../readme.azure.noprofile.md
# lock the commit
input-file:
  - $(repo)/specification/purview/resource-manager/Microsoft.Purview/preview/2020-12-01-preview/purview.json

module-version: 0.1.0
title: Purview
subject-prefix: $(service-name)
identity-correction-for-post: true 
nested-object-to-string: true

directive:
  # Following is two common directive which are normally required in all the RPs
  # 1. Remove the unexpanded parameter set
  # 2. For New-* cmdlets, ViaIdentity is not required, so CreateViaIdentityExpanded is removed as well
  - where:
      variant: ^Create$|^CreateViaIdentity$|^CreateViaIdentityExpanded$|^Update$|^UpdateViaIdentity$|^Check$|^CheckViaIdentity$|^CheckViaIdentityExpanded$|^Set$
    remove: true
  # Remove the set-* cmdlet
  - where:
      verb: Set
      subject: Account
    remove: true
  - where:
      verb: Set
      subject: DefaultAccount
    hide: true
  - where:
      subject: PrivateEndpointConnection|PrivateLinkResource
    hide: true
  - where:
      verb: New
      subject: Account
    hide: true
  - where:
      verb: Get|Remove
      subject: DefaultAccount
    hide: true
```
