// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Models.Api20211101
{
    using static Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Runtime.Extensions;

    /// <summary>Common IoT Connector destination properties.</summary>
    public partial class IotDestinationProperties :
        Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Models.Api20211101.IIotDestinationProperties,
        Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Models.Api20211101.IIotDestinationPropertiesInternal
    {

        /// <summary>Internal Acessors for ProvisioningState</summary>
        Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Support.ProvisioningState? Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Models.Api20211101.IIotDestinationPropertiesInternal.ProvisioningState { get => this._provisioningState; set { {_provisioningState = value;} } }

        /// <summary>Backing field for <see cref="ProvisioningState" /> property.</summary>
        private Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Support.ProvisioningState? _provisioningState;

        /// <summary>The provisioning state.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Origin(Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.PropertyOrigin.Owned)]
        public Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Support.ProvisioningState? ProvisioningState { get => this._provisioningState; }

        /// <summary>Creates an new <see cref="IotDestinationProperties" /> instance.</summary>
        public IotDestinationProperties()
        {

        }
    }
    /// Common IoT Connector destination properties.
    public partial interface IIotDestinationProperties :
        Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Runtime.IJsonSerializable
    {
        /// <summary>The provisioning state.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"The provisioning state.",
        SerializedName = @"provisioningState",
        PossibleTypes = new [] { typeof(Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Support.ProvisioningState) })]
        Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Support.ProvisioningState? ProvisioningState { get;  }

    }
    /// Common IoT Connector destination properties.
    internal partial interface IIotDestinationPropertiesInternal

    {
        /// <summary>The provisioning state.</summary>
        Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Support.ProvisioningState? ProvisioningState { get; set; }

    }
}