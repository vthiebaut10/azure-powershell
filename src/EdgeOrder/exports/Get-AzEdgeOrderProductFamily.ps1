
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
This method provides the list of product families for the given subscription.
.Description
This method provides the list of product families for the given subscription.
.Example
PS C:\>  $familyDetails = Get-AzEdgeOrderProductFamily -SubscriptionId SubscriptionId -FilterableProperty  @{"azurestackedge"=@($filterableProperty)} -Expand "configurations"
PS C:\> $familyDetails.ProductLine.Product.Configuration.HierarchyInformation

ConfigurationName ProductFamilyName ProductLineName ProductName
----------------- ----------------- --------------- -----------
edgep_high        azurestackedge    azurestackedge  azurestackedgegpu
edgepr_base       azurestackedge    azurestackedge  azurestackedgepror
edgemr_mini       azurestackedge    azurestackedge  azurestackedgeminir

.Outputs
Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IProductFamily
.Notes
COMPLEX PARAMETER PROPERTIES

To create the parameters described below, construct a hash table containing the appropriate properties. For information on hash tables, run Get-Help about_Hash_Tables.

CUSTOMERSUBSCRIPTIONDETAIL <ICustomerSubscriptionDetails>: Customer subscription properties. Clients can display available products to unregistered customers by explicitly passing subscription details
  QuotaId <String>: Quota ID of a subscription
  [LocationPlacementId <String>]: Location placement Id of a subscription
  [RegisteredFeature <ICustomerSubscriptionRegisteredFeatures[]>]: List of registered feature flags for subscription
    [Name <String>]: Name of subscription registered feature
    [State <String>]: State of subscription registered feature
.Link
https://docs.microsoft.com/powershell/module/az.edgeorder/get-azedgeorderproductfamily
#>
function Get-AzEdgeOrderProductFamily {
[OutputType([Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IProductFamily])]
[CmdletBinding(DefaultParameterSetName='ListExpanded', PositionalBinding=$false, SupportsShouldProcess, ConfirmImpact='Medium')]
param(
    [Parameter()]
    [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Category('Path')]
    [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Runtime.DefaultInfo(Script='(Get-AzContext).Subscription.Id')]
    [System.String[]]
    # The ID of the target subscription.
    ${SubscriptionId},

    [Parameter()]
    [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Category('Query')]
    [System.String]
    # $expand is supported on configurations parameter for product, which provides details on the configurations for the product.
    ${Expand},

    [Parameter(Mandatory)]
    [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Category('Body')]
    [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Runtime.Info(Required, PossibleTypes=([Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IProductFamiliesRequestFilterableProperties]))]
    [System.Collections.Hashtable]
    # Dictionary of filterable properties on product family.
    ${FilterableProperty},

    [Parameter()]
    [Alias('AzureRMContext', 'AzureCredential')]
    [ValidateNotNull()]
    [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Category('Azure')]
    [System.Management.Automation.PSObject]
    # The credentials, account, tenant, and subscription used for communication with Azure.
    ${DefaultProfile},

    [Parameter(DontShow)]
    [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Category('Runtime')]
    [System.Management.Automation.SwitchParameter]
    # Wait for .NET debugger to attach
    ${Break},

    [Parameter(DontShow)]
    [ValidateNotNull()]
    [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Category('Runtime')]
    [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Runtime.SendAsyncStep[]]
    # SendAsync Pipeline Steps to be appended to the front of the pipeline
    ${HttpPipelineAppend},

    [Parameter(DontShow)]
    [ValidateNotNull()]
    [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Category('Runtime')]
    [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Runtime.SendAsyncStep[]]
    # SendAsync Pipeline Steps to be prepended to the front of the pipeline
    ${HttpPipelinePrepend},

    [Parameter(DontShow)]
    [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Category('Runtime')]
    [System.Uri]
    # The URI for the proxy server to use
    ${Proxy},

    [Parameter(DontShow)]
    [ValidateNotNull()]
    [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Category('Runtime')]
    [System.Management.Automation.PSCredential]
    # Credentials for a proxy server to use for the remote call
    ${ProxyCredential},

    [Parameter(DontShow)]
    [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Category('Runtime')]
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
        $mapping = @{
            ListExpanded = 'Az.EdgeOrder.private\Get-AzEdgeOrderProductFamily_ListExpanded';
        }
        if (('ListExpanded') -contains $parameterSet -and -not $PSBoundParameters.ContainsKey('SubscriptionId')) {
            $PSBoundParameters['SubscriptionId'] = (Get-AzContext).Subscription.Id
        }
        $cmdInfo = Get-Command -Name $mapping[$parameterSet]
        [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Runtime.MessageAttributeHelper]::ProcessCustomAttributesAtRuntime($cmdInfo, $MyInvocation, $parameterSet, $PSCmdlet)
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
