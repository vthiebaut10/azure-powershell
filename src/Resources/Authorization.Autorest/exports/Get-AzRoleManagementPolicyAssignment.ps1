
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
Get the specified role management policy assignment for a resource scope
.Description
Get the specified role management policy assignment for a resource scope
.Example
PS C:\> $scope = "/subscriptions/38ab2ccc-3747-4567-b36b-9478f5602f0d/"
PS C:\> Get-AzRoleManagementPolicyAssignment -Scope $scope

Name                                                                      Type                                                   Scope                                               RoleDefinitionId
----                                                                      ----                                                   -----                                               ----------------
588b80cc-f50c-4616-acc9-0003872624db_00493d72-78f6-4148-b6c5-d3ce8e4799dd Microsoft.Authorization/roleManagementPolicyAssignment /subscriptions/38ab2ccc-3747-4567-b36b-9478f5602f0d /subscriptions/38ab2ccc-3747-4567-b36b-9478f5602f… 
8dbbf139-4d46-4ad4-a56b-004156c117d2_056cd41c-7e88-42e1-933e-88ba6a50c9c3 Microsoft.Authorization/roleManagementPolicyAssignment /subscriptions/38ab2ccc-3747-4567-b36b-9478f5602f0d /subscriptions/38ab2ccc-3747-4567-b36b-9478f5602f… 
1c8bc687-402c-4e62-b38b-009d6fc244d3_b97fb8bc-a8b2-4522-a38b-dd33c7e65ead Microsoft.Authorization/roleManagementPolicyAssignment /subscriptions/38ab2ccc-3747-4567-b36b-9478f5602f0d /subscriptions/38ab2ccc-3747-4567-b36b-9478f5602f… 
5d582357-e60a-4322-a299-00ab23713a07_70bbe301-9835-447d-afdd-19eb3167307c Microsoft.Authorization/roleManagementPolicyAssignment /subscriptions/38ab2ccc-3747-4567-b36b-9478f5602f0d /subscriptions/38ab2ccc-3747-4567-b36b-9478f5602f… 
.Example
PS C:\> $scope = "/subscriptions/38ab2ccc-3747-4567-b36b-9478f5602f0d/"
PS C:\> $name = "588b80cc-f50c-4616-acc9-0003872624db_00493d72-78f6-4148-b6c5-d3ce8e4799dd"
PS C:\> Get-AzRoleManagementPolicyAssignment -Scope $scope -Name $name

Name                                                                      Type                                                   Scope                                               RoleDefinitionId
----                                                                      ----                                                   -----                                               ----------------
588b80cc-f50c-4616-acc9-0003872624db_00493d72-78f6-4148-b6c5-d3ce8e4799dd Microsoft.Authorization/roleManagementPolicyAssignment /subscriptions/38ab2ccc-3747-4567-b36b-9478f5602f0d /subscriptions/38ab2ccc-3747-4567-b36b-9478f5602f…

.Inputs
Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.IAuthorizationIdentity
.Outputs
Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IRoleManagementPolicyAssignment
.Notes
COMPLEX PARAMETER PROPERTIES

To create the parameters described below, construct a hash table containing the appropriate properties. For information on hash tables, run Get-Help about_Hash_Tables.

INPUTOBJECT <IAuthorizationIdentity>: Identity Parameter
  [Id <String>]: Resource identity path
  [RoleAssignmentScheduleInstanceName <String>]: The name (hash of schedule name + time) of the role assignment schedule to get.
  [RoleAssignmentScheduleName <String>]: The name (guid) of the role assignment schedule to get.
  [RoleAssignmentScheduleRequestName <String>]: The name of the role assignment to create. It can be any valid GUID.
  [RoleEligibilityScheduleInstanceName <String>]: The name (hash of schedule name + time) of the role eligibility schedule to get.
  [RoleEligibilityScheduleName <String>]: The name (guid) of the role eligibility schedule to get.
  [RoleEligibilityScheduleRequestName <String>]: The name of the role eligibility to create. It can be any valid GUID.
  [RoleManagementPolicyAssignmentName <String>]: The name of format {guid_guid} the role management policy assignment to get.
  [RoleManagementPolicyName <String>]: The name (guid) of the role management policy to get.
  [Scope <String>]: The scope of the role management policy.
.Link
https://docs.microsoft.com/powershell/module/az.resources/get-azrolemanagementpolicyassignment
#>
function Get-AzRoleManagementPolicyAssignment {
[OutputType([Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IRoleManagementPolicyAssignment])]
[CmdletBinding(DefaultParameterSetName='List', PositionalBinding=$false)]
param(
    [Parameter(ParameterSetName='Get', Mandatory)]
    [Alias('RoleManagementPolicyAssignmentName')]
    [Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Category('Path')]
    [System.String]
    # The name of format {guid_guid} the role management policy assignment to get.
    ${Name},

    [Parameter(ParameterSetName='Get', Mandatory)]
    [Parameter(ParameterSetName='List', Mandatory)]
    [Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Category('Path')]
    [System.String]
    # The scope of the role management policy.
    ${Scope},

    [Parameter(ParameterSetName='GetViaIdentity', Mandatory, ValueFromPipeline)]
    [Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Category('Path')]
    [Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.IAuthorizationIdentity]
    # Identity Parameter
    # To construct, see NOTES section for INPUTOBJECT properties and create a hash table.
    ${InputObject},

    [Parameter()]
    [Alias('AzureRMContext', 'AzureCredential')]
    [ValidateNotNull()]
    [Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Category('Azure')]
    [System.Management.Automation.PSObject]
    # The credentials, account, tenant, and subscription used for communication with Azure.
    ${DefaultProfile},

    [Parameter(DontShow)]
    [Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Category('Runtime')]
    [System.Management.Automation.SwitchParameter]
    # Wait for .NET debugger to attach
    ${Break},

    [Parameter(DontShow)]
    [ValidateNotNull()]
    [Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Category('Runtime')]
    [Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Runtime.SendAsyncStep[]]
    # SendAsync Pipeline Steps to be appended to the front of the pipeline
    ${HttpPipelineAppend},

    [Parameter(DontShow)]
    [ValidateNotNull()]
    [Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Category('Runtime')]
    [Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Runtime.SendAsyncStep[]]
    # SendAsync Pipeline Steps to be prepended to the front of the pipeline
    ${HttpPipelinePrepend},

    [Parameter(DontShow)]
    [Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Category('Runtime')]
    [System.Uri]
    # The URI for the proxy server to use
    ${Proxy},

    [Parameter(DontShow)]
    [ValidateNotNull()]
    [Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Category('Runtime')]
    [System.Management.Automation.PSCredential]
    # Credentials for a proxy server to use for the remote call
    ${ProxyCredential},

    [Parameter(DontShow)]
    [Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Category('Runtime')]
    [System.Management.Automation.SwitchParameter]
    # Use the default credentials for the proxy
    ${ProxyUseDefaultCredentials}
)

begin {
    try {
        $outBuffer = $null
        if ($PSBoundParameters.TryGetValue('OutBuffer', [ref]$outBuffer)) {
            $PSBoundParameters['OutBuffer'] = 1
        }
        $parameterSet = $PSCmdlet.ParameterSetName

        if ($null -eq [Microsoft.WindowsAzure.Commands.Utilities.Common.AzurePSCmdlet]::PowerShellVersion) {
            [Microsoft.WindowsAzure.Commands.Utilities.Common.AzurePSCmdlet]::PowerShellVersion = $Host.Runspace.Version.ToString()
        }         
        $preTelemetryId = [Microsoft.WindowsAzure.Commands.Common.MetricHelper]::TelemetryId
        if ($preTelemetryId -eq '') {
            [Microsoft.WindowsAzure.Commands.Common.MetricHelper]::TelemetryId =(New-Guid).ToString()
            [Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.module]::Instance.Telemetry.Invoke('Create', $MyInvocation, $parameterSet, $PSCmdlet)
        } else {
            $internalCalledCmdlets = [Microsoft.WindowsAzure.Commands.Common.MetricHelper]::InternalCalledCmdlets
            if ($internalCalledCmdlets -eq '') {
                [Microsoft.WindowsAzure.Commands.Common.MetricHelper]::InternalCalledCmdlets = $MyInvocation.MyCommand.Name
            } else {
                [Microsoft.WindowsAzure.Commands.Common.MetricHelper]::InternalCalledCmdlets += ',' + $MyInvocation.MyCommand.Name
            }
            [Microsoft.WindowsAzure.Commands.Common.MetricHelper]::TelemetryId = 'internal'
        }

        $mapping = @{
            Get = 'Az.Authorization.private\Get-AzRoleManagementPolicyAssignment_Get';
            GetViaIdentity = 'Az.Authorization.private\Get-AzRoleManagementPolicyAssignment_GetViaIdentity';
            List = 'Az.Authorization.private\Get-AzRoleManagementPolicyAssignment_List';
        }
        $cmdInfo = Get-Command -Name $mapping[$parameterSet]
        [Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Runtime.MessageAttributeHelper]::ProcessCustomAttributesAtRuntime($cmdInfo, $MyInvocation, $parameterSet, $PSCmdlet)
        $wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand(($mapping[$parameterSet]), [System.Management.Automation.CommandTypes]::Cmdlet)
        $scriptCmd = {& $wrappedCmd @PSBoundParameters}
        $steppablePipeline = $scriptCmd.GetSteppablePipeline($MyInvocation.CommandOrigin)
        $steppablePipeline.Begin($PSCmdlet)
    } catch {
        [Microsoft.WindowsAzure.Commands.Common.MetricHelper]::ClearTelemetryContext()
        throw
    }
}

process {
    try {
        $steppablePipeline.Process($_)
    } catch {
        [Microsoft.WindowsAzure.Commands.Common.MetricHelper]::ClearTelemetryContext()
        throw
    }

    finally {
        $backupTelemetryId = [Microsoft.WindowsAzure.Commands.Common.MetricHelper]::TelemetryId
        $backupInternalCalledCmdlets = [Microsoft.WindowsAzure.Commands.Common.MetricHelper]::InternalCalledCmdlets
        [Microsoft.WindowsAzure.Commands.Common.MetricHelper]::ClearTelemetryContext()
    }

}
end {
    try {
        $steppablePipeline.End()

        [Microsoft.WindowsAzure.Commands.Common.MetricHelper]::TelemetryId = $backupTelemetryId
        [Microsoft.WindowsAzure.Commands.Common.MetricHelper]::InternalCalledCmdlets = $backupInternalCalledCmdlets
        if ($preTelemetryId -eq '') {
            [Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.module]::Instance.Telemetry.Invoke('Send', $MyInvocation, $parameterSet, $PSCmdlet)
            [Microsoft.WindowsAzure.Commands.Common.MetricHelper]::ClearTelemetryContext()
        }
        [Microsoft.WindowsAzure.Commands.Common.MetricHelper]::TelemetryId = $preTelemetryId

    } catch {
        [Microsoft.WindowsAzure.Commands.Common.MetricHelper]::ClearTelemetryContext()
        throw
    }
} 
}
