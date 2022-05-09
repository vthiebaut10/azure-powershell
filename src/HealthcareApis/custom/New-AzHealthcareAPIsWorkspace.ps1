
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
Creates or updates a workspace resource with the specified parameters.
.Description
Creates or updates a workspace resource with the specified parameters.
.Example
PS C:\> New-AzHealthcareAPIsWorkspace -Name azpshcws -ResourceGroupName azps_test_group -Location eastus2

Location Name     ResourceGroupName
-------- ----     -----------------
eastus2  azpshcws azps_test_group

.Outputs
Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Models.Api20211101.IWorkspace
.Link
https://docs.microsoft.com/powershell/module/az.healthcareapis/new-azhealthcareapisworkspace
#>
function New-AzHealthcareAPIsWorkspace {
    [OutputType([Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Models.Api20211101.IWorkspace])]
    [CmdletBinding(DefaultParameterSetName='CreateExpanded', PositionalBinding=$false, SupportsShouldProcess, ConfirmImpact='Medium')]
    param(
        [Parameter(Mandatory)]
        [Alias('WorkspaceName')]
        [Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Category('Path')]
        [System.String]
        # The name of workspace resource.
        ${Name},

        [Parameter(Mandatory)]
        [Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Category('Path')]
        [System.String]
        # The name of the resource group that contains the service instance.
        ${ResourceGroupName},

        [Parameter()]
        [Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Category('Path')]
        [Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Runtime.DefaultInfo(Script='(Get-AzContext).Subscription.Id')]
        [System.String]
        # The subscription identifier.
        ${SubscriptionId},

        [Parameter()]
        [Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Category('Body')]
        [System.String]
        # An etag associated with the resource, used for optimistic concurrency when editing it.
        ${Etag},

        [Parameter(Mandatory)]
        [Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Category('Body')]
        [System.String]
        # The resource location.
        ${Location},

        [Parameter()]
        [ArgumentCompleter([Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Support.PublicNetworkAccess])]
        [Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Category('Body')]
        [Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Support.PublicNetworkAccess]
        # Control permission for data plane traffic coming from public networks while private endpoint is enabled.
        ${PublicNetworkAccess},

        [Parameter()]
        [Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Category('Body')]
        [Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Runtime.Info(PossibleTypes=([Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Models.Api20211101.IResourceTags]))]
        [System.Collections.Hashtable]
        # Resource tags.
        ${Tag},

        [Parameter()]
        [Alias('AzureRMContext', 'AzureCredential')]
        [ValidateNotNull()]
        [Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Category('Azure')]
        [System.Management.Automation.PSObject]
        # The credentials, account, tenant, and subscription used for communication with Azure.
        ${DefaultProfile},

        [Parameter()]
        [Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Category('Runtime')]
        [System.Management.Automation.SwitchParameter]
        # Run the command as a job
        ${AsJob},

        [Parameter(DontShow)]
        [Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Category('Runtime')]
        [System.Management.Automation.SwitchParameter]
        # Wait for .NET debugger to attach
        ${Break},

        [Parameter(DontShow)]
        [ValidateNotNull()]
        [Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Category('Runtime')]
        [Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Runtime.SendAsyncStep[]]
        # SendAsync Pipeline Steps to be appended to the front of the pipeline
        ${HttpPipelineAppend},

        [Parameter(DontShow)]
        [ValidateNotNull()]
        [Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Category('Runtime')]
        [Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Runtime.SendAsyncStep[]]
        # SendAsync Pipeline Steps to be prepended to the front of the pipeline
        ${HttpPipelinePrepend},

        [Parameter()]
        [Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Category('Runtime')]
        [System.Management.Automation.SwitchParameter]
        # Run the command asynchronously
        ${NoWait},

        [Parameter(DontShow)]
        [Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Category('Runtime')]
        [System.Uri]
        # The URI for the proxy server to use
        ${Proxy},

        [Parameter(DontShow)]
        [ValidateNotNull()]
        [Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Category('Runtime')]
        [System.Management.Automation.PSCredential]
        # Credentials for a proxy server to use for the remote call
        ${ProxyCredential},

        [Parameter(DontShow)]
        [Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Category('Runtime')]
        [System.Management.Automation.SwitchParameter]
        # Use the default credentials for the proxy
        ${ProxyUseDefaultCredentials}
)

    process {
        try {
            Az.HealthcareApis.internal\New-AzHealthcareAPIsWorkspace @PSBoundParameters
        } catch {
            throw
        }
    }
}
