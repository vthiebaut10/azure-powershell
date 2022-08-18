
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
Create a new Activity Log Alert rule or update an existing one.
.Description
Create a new Activity Log Alert rule or update an existing one.
.Example
$scope = "subscriptions/"+(Get-AzContext).Subscription.ID
$actiongroup=New-AzActivityLogAlertActionGroupObject -Id $ActionGroupResourceId -WebhookProperty @{"sampleWebhookProperty"="SamplePropertyValue"}
$condition1=New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -Equal Administrative -Field category
$condition2=New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -Equal Error -Field level
$any1=New-AzAlertRuleLeafConditionObject -Field properties.incidentType -Equal Maintenance
$any2=New-AzAlertRuleLeafConditionObject -Field properties.incidentType -Equal Incident
$condition3=New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -AnyOf $any1,$any2
New-AzActivityLogAlert -Name $AlertName -ResourceGroupName $ResourceGroupName -Action $actiongroup -Condition @($condition1,$condition2,$condition3) -Location global -Scope $scope

.Outputs
Microsoft.Azure.PowerShell.Cmdlets.Monitor.ActivityLogAlert.Models.Api20201001.IActivityLogAlertResource
.Notes
COMPLEX PARAMETER PROPERTIES

To create the parameters described below, construct a hash table containing the appropriate properties. For information on hash tables, run Get-Help about_Hash_Tables.

ACTION <IActionGroup[]>: The list of the Action Groups.
  Id <String>: The resource ID of the Action Group. This cannot be null or empty.
  [WebhookProperty <IActionGroupWebhookProperties>]: the dictionary of custom properties to include with the post operation. These data are appended to the webhook payload.
    [(Any) <String>]: This indicates any property can be added to this object.

CONDITION <IAlertRuleAnyOfOrLeafCondition[]>: The list of Activity Log Alert rule conditions.
  [ContainsAny <String[]>]: The value of the event's field will be compared to the values in this array (case-insensitive) to determine if the condition is met.
  [Equal <String>]: The value of the event's field will be compared to this value (case-insensitive) to determine if the condition is met.
  [Field <String>]: The name of the Activity Log event's field that this condition will examine.         The possible values for this field are (case-insensitive): 'resourceId', 'category', 'caller', 'level', 'operationName', 'resourceGroup', 'resourceProvider', 'status', 'subStatus', 'resourceType', or anything beginning with 'properties'.
  [AnyOf <IAlertRuleLeafCondition[]>]: An Activity Log Alert rule condition that is met when at least one of its member leaf conditions are met.
    [ContainsAny <String[]>]: The value of the event's field will be compared to the values in this array (case-insensitive) to determine if the condition is met.
    [Equal <String>]: The value of the event's field will be compared to this value (case-insensitive) to determine if the condition is met.
    [Field <String>]: The name of the Activity Log event's field that this condition will examine.         The possible values for this field are (case-insensitive): 'resourceId', 'category', 'caller', 'level', 'operationName', 'resourceGroup', 'resourceProvider', 'status', 'subStatus', 'resourceType', or anything beginning with 'properties'.
.Link
https://docs.microsoft.com/powershell/module/az.monitor/new-azactivitylogalert
#>
function New-AzActivityLogAlert {
[OutputType([Microsoft.Azure.PowerShell.Cmdlets.Monitor.ActivityLogAlert.Models.Api20201001.IActivityLogAlertResource])]
[CmdletBinding(DefaultParameterSetName='CreateExpanded', PositionalBinding=$false, SupportsShouldProcess, ConfirmImpact='Medium')]
param(
    [Parameter(Mandatory)]
    [Alias('ActivityLogAlertName')]
    [Microsoft.Azure.PowerShell.Cmdlets.Monitor.ActivityLogAlert.Category('Path')]
    [System.String]
    # The name of the Activity Log Alert rule.
    ${Name},

    [Parameter(Mandatory)]
    [Microsoft.Azure.PowerShell.Cmdlets.Monitor.ActivityLogAlert.Category('Path')]
    [System.String]
    # The name of the resource group.
    # The name is case insensitive.
    ${ResourceGroupName},

    [Parameter()]
    [Microsoft.Azure.PowerShell.Cmdlets.Monitor.ActivityLogAlert.Category('Path')]
    [Microsoft.Azure.PowerShell.Cmdlets.Monitor.ActivityLogAlert.Runtime.DefaultInfo(Script='(Get-AzContext).Subscription.Id')]
    [System.String]
    # The ID of the target subscription.
    ${SubscriptionId},

    [Parameter()]
    [AllowEmptyCollection()]
    [Microsoft.Azure.PowerShell.Cmdlets.Monitor.ActivityLogAlert.Category('Body')]
    [Microsoft.Azure.PowerShell.Cmdlets.Monitor.ActivityLogAlert.Models.Api20201001.IActionGroup[]]
    # The list of the Action Groups.
    # To construct, see NOTES section for ACTION properties and create a hash table.
    ${Action},

    [Parameter()]
    [AllowEmptyCollection()]
    [Microsoft.Azure.PowerShell.Cmdlets.Monitor.ActivityLogAlert.Category('Body')]
    [Microsoft.Azure.PowerShell.Cmdlets.Monitor.ActivityLogAlert.Models.Api20201001.IAlertRuleAnyOfOrLeafCondition[]]
    # The list of Activity Log Alert rule conditions.
    # To construct, see NOTES section for CONDITION properties and create a hash table.
    ${Condition},

    [Parameter()]
    [Microsoft.Azure.PowerShell.Cmdlets.Monitor.ActivityLogAlert.Category('Body')]
    [System.String]
    # A description of this Activity Log Alert rule.
    ${Description},

    [Parameter()]
    [Microsoft.Azure.PowerShell.Cmdlets.Monitor.ActivityLogAlert.Category('Body')]
    [System.Management.Automation.SwitchParameter]
    # Indicates whether this Activity Log Alert rule is enabled.
    # If an Activity Log Alert rule is not enabled, then none of its actions will be activated.
    ${Enabled},

    [Parameter()]
    [Microsoft.Azure.PowerShell.Cmdlets.Monitor.ActivityLogAlert.Category('Body')]
    [System.String]
    # The location of the resource.
    # Since Azure Activity Log Alerts is a global service, the location of the rules should always be 'global'.
    ${Location},

    [Parameter()]
    [AllowEmptyCollection()]
    [Microsoft.Azure.PowerShell.Cmdlets.Monitor.ActivityLogAlert.Category('Body')]
    [System.String[]]
    # A list of resource IDs that will be used as prefixes.
    # The alert will only apply to Activity Log events with resource IDs that fall under one of these prefixes.
    # This list must include at least one item.
    ${Scope},

    [Parameter()]
    [Microsoft.Azure.PowerShell.Cmdlets.Monitor.ActivityLogAlert.Category('Body')]
    [Microsoft.Azure.PowerShell.Cmdlets.Monitor.ActivityLogAlert.Runtime.Info(PossibleTypes=([Microsoft.Azure.PowerShell.Cmdlets.Monitor.ActivityLogAlert.Models.Api20201001.IAzureResourceTags]))]
    [System.Collections.Hashtable]
    # The tags of the resource.
    ${Tag},

    [Parameter()]
    [Alias('AzureRMContext', 'AzureCredential')]
    [ValidateNotNull()]
    [Microsoft.Azure.PowerShell.Cmdlets.Monitor.ActivityLogAlert.Category('Azure')]
    [System.Management.Automation.PSObject]
    # The credentials, account, tenant, and subscription used for communication with Azure.
    ${DefaultProfile},

    [Parameter(DontShow)]
    [Microsoft.Azure.PowerShell.Cmdlets.Monitor.ActivityLogAlert.Category('Runtime')]
    [System.Management.Automation.SwitchParameter]
    # Wait for .NET debugger to attach
    ${Break},

    [Parameter(DontShow)]
    [ValidateNotNull()]
    [Microsoft.Azure.PowerShell.Cmdlets.Monitor.ActivityLogAlert.Category('Runtime')]
    [Microsoft.Azure.PowerShell.Cmdlets.Monitor.ActivityLogAlert.Runtime.SendAsyncStep[]]
    # SendAsync Pipeline Steps to be appended to the front of the pipeline
    ${HttpPipelineAppend},

    [Parameter(DontShow)]
    [ValidateNotNull()]
    [Microsoft.Azure.PowerShell.Cmdlets.Monitor.ActivityLogAlert.Category('Runtime')]
    [Microsoft.Azure.PowerShell.Cmdlets.Monitor.ActivityLogAlert.Runtime.SendAsyncStep[]]
    # SendAsync Pipeline Steps to be prepended to the front of the pipeline
    ${HttpPipelinePrepend},

    [Parameter(DontShow)]
    [Microsoft.Azure.PowerShell.Cmdlets.Monitor.ActivityLogAlert.Category('Runtime')]
    [System.Uri]
    # The URI for the proxy server to use
    ${Proxy},

    [Parameter(DontShow)]
    [ValidateNotNull()]
    [Microsoft.Azure.PowerShell.Cmdlets.Monitor.ActivityLogAlert.Category('Runtime')]
    [System.Management.Automation.PSCredential]
    # Credentials for a proxy server to use for the remote call
    ${ProxyCredential},

    [Parameter(DontShow)]
    [Microsoft.Azure.PowerShell.Cmdlets.Monitor.ActivityLogAlert.Category('Runtime')]
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
            CreateExpanded = 'Az.ActivityLogAlert.private\New-AzActivityLogAlert_CreateExpanded';
        }
        if (('CreateExpanded') -contains $parameterSet -and -not $PSBoundParameters.ContainsKey('SubscriptionId')) {
            $PSBoundParameters['SubscriptionId'] = (Get-AzContext).Subscription.Id
        }

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
