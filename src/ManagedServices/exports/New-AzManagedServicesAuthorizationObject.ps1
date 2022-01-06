
# ----------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# Code generated by Microsoft (R) AutoRest Code Generator.Changes may cause incorrect behavior and will be lost if the code
# is regenerated.
# ----------------------------------------------------------------------------------

<#
.Synopsis
Create an in-memory object for Authorization.
.Description
Create an in-memory object for Authorization.
.Example
PS C:\> New-AzManagedServicesAuthorizationObject -PrincipalId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -RoleDefinitionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -PrincipalIdDisplayName "Test user"

DelegatedRoleDefinitionId PrincipalId                          PrincipalIdDisplayName RoleDefinitionId
------------------------- -----------                          ---------------------- ----------------
                          xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx Test user              xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
.Example
PS C:\> New-AzManagedServicesAuthorizationObject -PrincipalId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -RoleDefinitionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -PrincipalIdDisplayName "Test user" -DelegatedRoleDefinitionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

DelegatedRoleDefinitionId                                                    PrincipalId                          PrincipalIdDisplayName RoleDefinitionId
-------------------------                                                    -----------                          ---------------------- ----------------
{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx, xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx Test user              xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

.Outputs
Microsoft.Azure.PowerShell.Cmdlets.ManagedServices.Models.Api20200201Preview.Authorization
.Link
https://docs.microsoft.com/powershell/module/az.ManagedServices/new-AzManagedServicesAuthorizationObject
#>
function New-AzManagedServicesAuthorizationObject {
[OutputType([Microsoft.Azure.PowerShell.Cmdlets.ManagedServices.Models.Api20200201Preview.Authorization])]
[CmdletBinding(PositionalBinding=$false)]
param(
    [Parameter(Mandatory)]
    [Microsoft.Azure.PowerShell.Cmdlets.ManagedServices.Category('Body')]
    [System.String]
    # The identifier of the Azure Active Directory principal.
    ${PrincipalId},

    [Parameter(Mandatory)]
    [Microsoft.Azure.PowerShell.Cmdlets.ManagedServices.Category('Body')]
    [System.String]
    # The identifier of the Azure built-in role that defines the permissions that the Azure Active Directory principal will have on the projected scope.
    ${RoleDefinitionId},

    [Parameter()]
    [Microsoft.Azure.PowerShell.Cmdlets.ManagedServices.Category('Body')]
    [System.String[]]
    # The delegatedRoleDefinitionIds field is required when the roleDefinitionId refers to the User Access Administrator Role.
    # It is the list of role definition ids which define all the permissions that the user in the authorization can assign to other principals.
    ${DelegatedRoleDefinitionId},

    [Parameter()]
    [Microsoft.Azure.PowerShell.Cmdlets.ManagedServices.Category('Body')]
    [System.String]
    # The display name of the Azure Active Directory principal.
    ${PrincipalIdDisplayName}
)

begin {
    try {
        $outBuffer = $null
        if ($PSBoundParameters.TryGetValue('OutBuffer', [ref]$outBuffer)) {
            $PSBoundParameters['OutBuffer'] = 1
        }
        $parameterSet = $PSCmdlet.ParameterSetName
        $mapping = @{
            __AllParameterSets = 'Az.ManagedServices.custom\New-AzManagedServicesAuthorizationObject';
        }
        $cmdInfo = Get-Command -Name $mapping[$parameterSet]
        [Microsoft.Azure.PowerShell.Cmdlets.ManagedServices.Runtime.MessageAttributeHelper]::ProcessCustomAttributesAtRuntime($cmdInfo, $MyInvocation, $parameterSet, $PSCmdlet)
        $wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand(($mapping[$parameterSet]), [System.Management.Automation.CommandTypes]::Cmdlet)
        $scriptCmd = {& $wrappedCmd @PSBoundParameters}
        $steppablePipeline = $scriptCmd.GetSteppablePipeline($MyInvocation.CommandOrigin)
        $steppablePipeline.Begin($PSCmdlet)
    } catch {
        throw
    }
}

process {
    try {
        $steppablePipeline.Process($_)
    } catch {
        throw
    }
}

end {
    try {
        $steppablePipeline.End()
    } catch {
        throw
    }
}
}
