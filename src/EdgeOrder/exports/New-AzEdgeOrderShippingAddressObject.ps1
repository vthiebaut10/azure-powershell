
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
Create an in-memory object for ShippingAddress.
.Description
Create an in-memory object for ShippingAddress.
.Example
PS C:\> $ShippingDetails = New-AzEdgeOrderShippingAddressObject -StreetAddress1 "101 TOWNSEND ST" -StateOrProvince "CA" -Country "US" -City "San Francisco" -PostalCode "94107" -AddressType "Commercial"

$ShippingDetails | fl

AddressType     : Commercial
City            : San Francisco
CompanyName     :
Country         : US
PostalCode      : 94107
StateOrProvince : CA
StreetAddress1  : 101 TOWNSEND ST
StreetAddress2  :
StreetAddress3  :
ZipExtendedCode :

.Outputs
Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.ShippingAddress
.Link
https://docs.microsoft.com/powershell/module/az.EdgeOrder/new-AzEdgeOrderShippingAddressObject
#>
function New-AzEdgeOrderShippingAddressObject {
[OutputType([Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.ShippingAddress])]
[CmdletBinding(PositionalBinding=$false)]
param(
    [Parameter(Mandatory)]
    [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Category('Body')]
    [System.String]
    # Name of the Country.
    ${Country},

    [Parameter(Mandatory)]
    [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Category('Body')]
    [System.String]
    # Street Address line 1.
    ${StreetAddress1},

    [Parameter()]
    [ArgumentCompleter([Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Support.AddressType])]
    [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Category('Body')]
    [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Support.AddressType]
    # Type of address.
    ${AddressType},

    [Parameter()]
    [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Category('Body')]
    [System.String]
    # Name of the City.
    ${City},

    [Parameter()]
    [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Category('Body')]
    [System.String]
    # Name of the company.
    ${CompanyName},

    [Parameter()]
    [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Category('Body')]
    [System.String]
    # Postal code.
    ${PostalCode},

    [Parameter()]
    [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Category('Body')]
    [System.String]
    # Name of the State or Province.
    ${StateOrProvince},

    [Parameter()]
    [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Category('Body')]
    [System.String]
    # Street Address line 2.
    ${StreetAddress2},

    [Parameter()]
    [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Category('Body')]
    [System.String]
    # Street Address line 3.
    ${StreetAddress3},

    [Parameter()]
    [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Category('Body')]
    [System.String]
    # Extended Zip Code.
    ${ZipExtendedCode}
)

begin {
    try {
        $outBuffer = $null
        if ($PSBoundParameters.TryGetValue('OutBuffer', [ref]$outBuffer)) {
            $PSBoundParameters['OutBuffer'] = 1
        }
        $parameterSet = $PSCmdlet.ParameterSetName
        $mapping = @{
            __AllParameterSets = 'Az.EdgeOrder.custom\New-AzEdgeOrderShippingAddressObject';
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
