// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801
{
    using Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Runtime.PowerShell;

    /// <summary>Properties specific to the grafana resource.</summary>
    [System.ComponentModel.TypeConverter(typeof(ManagedGrafanaPropertiesTypeConverter))]
    public partial class ManagedGrafanaProperties
    {

        /// <summary>
        /// <c>AfterDeserializeDictionary</c> will be called after the deserialization has finished, allowing customization of the
        /// object before it is returned. Implement this method in a partial class to enable this behavior
        /// </summary>
        /// <param name="content">The global::System.Collections.IDictionary content that should be used.</param>

        partial void AfterDeserializeDictionary(global::System.Collections.IDictionary content);

        /// <summary>
        /// <c>AfterDeserializePSObject</c> will be called after the deserialization has finished, allowing customization of the object
        /// before it is returned. Implement this method in a partial class to enable this behavior
        /// </summary>
        /// <param name="content">The global::System.Management.Automation.PSObject content that should be used.</param>

        partial void AfterDeserializePSObject(global::System.Management.Automation.PSObject content);

        /// <summary>
        /// <c>BeforeDeserializeDictionary</c> will be called before the deserialization has commenced, allowing complete customization
        /// of the object before it is deserialized.
        /// If you wish to disable the default deserialization entirely, return <c>true</c> in the <paramref name="returnNow" /> output
        /// parameter.
        /// Implement this method in a partial class to enable this behavior.
        /// </summary>
        /// <param name="content">The global::System.Collections.IDictionary content that should be used.</param>
        /// <param name="returnNow">Determines if the rest of the serialization should be processed, or if the method should return
        /// instantly.</param>

        partial void BeforeDeserializeDictionary(global::System.Collections.IDictionary content, ref bool returnNow);

        /// <summary>
        /// <c>BeforeDeserializePSObject</c> will be called before the deserialization has commenced, allowing complete customization
        /// of the object before it is deserialized.
        /// If you wish to disable the default deserialization entirely, return <c>true</c> in the <paramref name="returnNow" /> output
        /// parameter.
        /// Implement this method in a partial class to enable this behavior.
        /// </summary>
        /// <param name="content">The global::System.Management.Automation.PSObject content that should be used.</param>
        /// <param name="returnNow">Determines if the rest of the serialization should be processed, or if the method should return
        /// instantly.</param>

        partial void BeforeDeserializePSObject(global::System.Management.Automation.PSObject content, ref bool returnNow);

        /// <summary>
        /// <c>OverrideToString</c> will be called if it is implemented. Implement this method in a partial class to enable this behavior
        /// </summary>
        /// <param name="stringResult">/// instance serialized to a string, normally it is a Json</param>
        /// <param name="returnNow">/// set returnNow to true if you provide a customized OverrideToString function</param>

        partial void OverrideToString(ref string stringResult, ref bool returnNow);

        /// <summary>
        /// Deserializes a <see cref="global::System.Collections.IDictionary" /> into an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.ManagedGrafanaProperties"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Collections.IDictionary content that should be used.</param>
        /// <returns>
        /// an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaProperties" />.
        /// </returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaProperties DeserializeFromDictionary(global::System.Collections.IDictionary content)
        {
            return new ManagedGrafanaProperties(content);
        }

        /// <summary>
        /// Deserializes a <see cref="global::System.Management.Automation.PSObject" /> into an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.ManagedGrafanaProperties"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Management.Automation.PSObject content that should be used.</param>
        /// <returns>
        /// an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaProperties" />.
        /// </returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaProperties DeserializeFromPSObject(global::System.Management.Automation.PSObject content)
        {
            return new ManagedGrafanaProperties(content);
        }

        /// <summary>
        /// Creates a new instance of <see cref="ManagedGrafanaProperties" />, deserializing the content from a json string.
        /// </summary>
        /// <param name="jsonText">a string containing a JSON serialized instance of this model.</param>
        /// <returns>an instance of the <see cref="ManagedGrafanaProperties" /> model class.</returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaProperties FromJsonString(string jsonText) => FromJson(Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Runtime.Json.JsonNode.Parse(jsonText));

        /// <summary>
        /// Deserializes a <see cref="global::System.Collections.IDictionary" /> into a new instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.ManagedGrafanaProperties"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Collections.IDictionary content that should be used.</param>
        internal ManagedGrafanaProperties(global::System.Collections.IDictionary content)
        {
            bool returnNow = false;
            BeforeDeserializeDictionary(content, ref returnNow);
            if (returnNow)
            {
                return;
            }
            // actually deserialize
            if (content.Contains("GrafanaIntegration"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).GrafanaIntegration = (Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IGrafanaIntegrations) content.GetValueForProperty("GrafanaIntegration",((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).GrafanaIntegration, Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.GrafanaIntegrationsTypeConverter.ConvertFrom);
            }
            if (content.Contains("ProvisioningState"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).ProvisioningState = (Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Support.ProvisioningState?) content.GetValueForProperty("ProvisioningState",((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).ProvisioningState, Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Support.ProvisioningState.CreateFrom);
            }
            if (content.Contains("GrafanaVersion"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).GrafanaVersion = (string) content.GetValueForProperty("GrafanaVersion",((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).GrafanaVersion, global::System.Convert.ToString);
            }
            if (content.Contains("Endpoint"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).Endpoint = (string) content.GetValueForProperty("Endpoint",((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).Endpoint, global::System.Convert.ToString);
            }
            if (content.Contains("PublicNetworkAccess"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).PublicNetworkAccess = (Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Support.PublicNetworkAccess?) content.GetValueForProperty("PublicNetworkAccess",((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).PublicNetworkAccess, Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Support.PublicNetworkAccess.CreateFrom);
            }
            if (content.Contains("ZoneRedundancy"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).ZoneRedundancy = (Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Support.ZoneRedundancy?) content.GetValueForProperty("ZoneRedundancy",((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).ZoneRedundancy, Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Support.ZoneRedundancy.CreateFrom);
            }
            if (content.Contains("ApiKey"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).ApiKey = (Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Support.ApiKey?) content.GetValueForProperty("ApiKey",((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).ApiKey, Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Support.ApiKey.CreateFrom);
            }
            if (content.Contains("DeterministicOutboundIP"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).DeterministicOutboundIP = (Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Support.DeterministicOutboundIP?) content.GetValueForProperty("DeterministicOutboundIP",((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).DeterministicOutboundIP, Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Support.DeterministicOutboundIP.CreateFrom);
            }
            if (content.Contains("OutboundIP"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).OutboundIP = (string[]) content.GetValueForProperty("OutboundIP",((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).OutboundIP, __y => TypeConverterExtensions.SelectToArray<string>(__y, global::System.Convert.ToString));
            }
            if (content.Contains("PrivateEndpointConnection"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).PrivateEndpointConnection = (Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IPrivateEndpointConnection[]) content.GetValueForProperty("PrivateEndpointConnection",((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).PrivateEndpointConnection, __y => TypeConverterExtensions.SelectToArray<Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IPrivateEndpointConnection>(__y, Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.PrivateEndpointConnectionTypeConverter.ConvertFrom));
            }
            if (content.Contains("AutoGeneratedDomainNameLabelScope"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).AutoGeneratedDomainNameLabelScope = (Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Support.AutoGeneratedDomainNameLabelScope?) content.GetValueForProperty("AutoGeneratedDomainNameLabelScope",((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).AutoGeneratedDomainNameLabelScope, Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Support.AutoGeneratedDomainNameLabelScope.CreateFrom);
            }
            if (content.Contains("GrafanaIntegrationAzureMonitorWorkspaceIntegration"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).GrafanaIntegrationAzureMonitorWorkspaceIntegration = (Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IAzureMonitorWorkspaceIntegration[]) content.GetValueForProperty("GrafanaIntegrationAzureMonitorWorkspaceIntegration",((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).GrafanaIntegrationAzureMonitorWorkspaceIntegration, __y => TypeConverterExtensions.SelectToArray<Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IAzureMonitorWorkspaceIntegration>(__y, Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.AzureMonitorWorkspaceIntegrationTypeConverter.ConvertFrom));
            }
            AfterDeserializeDictionary(content);
        }

        /// <summary>
        /// Deserializes a <see cref="global::System.Management.Automation.PSObject" /> into a new instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.ManagedGrafanaProperties"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Management.Automation.PSObject content that should be used.</param>
        internal ManagedGrafanaProperties(global::System.Management.Automation.PSObject content)
        {
            bool returnNow = false;
            BeforeDeserializePSObject(content, ref returnNow);
            if (returnNow)
            {
                return;
            }
            // actually deserialize
            if (content.Contains("GrafanaIntegration"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).GrafanaIntegration = (Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IGrafanaIntegrations) content.GetValueForProperty("GrafanaIntegration",((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).GrafanaIntegration, Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.GrafanaIntegrationsTypeConverter.ConvertFrom);
            }
            if (content.Contains("ProvisioningState"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).ProvisioningState = (Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Support.ProvisioningState?) content.GetValueForProperty("ProvisioningState",((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).ProvisioningState, Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Support.ProvisioningState.CreateFrom);
            }
            if (content.Contains("GrafanaVersion"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).GrafanaVersion = (string) content.GetValueForProperty("GrafanaVersion",((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).GrafanaVersion, global::System.Convert.ToString);
            }
            if (content.Contains("Endpoint"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).Endpoint = (string) content.GetValueForProperty("Endpoint",((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).Endpoint, global::System.Convert.ToString);
            }
            if (content.Contains("PublicNetworkAccess"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).PublicNetworkAccess = (Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Support.PublicNetworkAccess?) content.GetValueForProperty("PublicNetworkAccess",((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).PublicNetworkAccess, Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Support.PublicNetworkAccess.CreateFrom);
            }
            if (content.Contains("ZoneRedundancy"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).ZoneRedundancy = (Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Support.ZoneRedundancy?) content.GetValueForProperty("ZoneRedundancy",((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).ZoneRedundancy, Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Support.ZoneRedundancy.CreateFrom);
            }
            if (content.Contains("ApiKey"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).ApiKey = (Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Support.ApiKey?) content.GetValueForProperty("ApiKey",((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).ApiKey, Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Support.ApiKey.CreateFrom);
            }
            if (content.Contains("DeterministicOutboundIP"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).DeterministicOutboundIP = (Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Support.DeterministicOutboundIP?) content.GetValueForProperty("DeterministicOutboundIP",((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).DeterministicOutboundIP, Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Support.DeterministicOutboundIP.CreateFrom);
            }
            if (content.Contains("OutboundIP"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).OutboundIP = (string[]) content.GetValueForProperty("OutboundIP",((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).OutboundIP, __y => TypeConverterExtensions.SelectToArray<string>(__y, global::System.Convert.ToString));
            }
            if (content.Contains("PrivateEndpointConnection"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).PrivateEndpointConnection = (Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IPrivateEndpointConnection[]) content.GetValueForProperty("PrivateEndpointConnection",((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).PrivateEndpointConnection, __y => TypeConverterExtensions.SelectToArray<Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IPrivateEndpointConnection>(__y, Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.PrivateEndpointConnectionTypeConverter.ConvertFrom));
            }
            if (content.Contains("AutoGeneratedDomainNameLabelScope"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).AutoGeneratedDomainNameLabelScope = (Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Support.AutoGeneratedDomainNameLabelScope?) content.GetValueForProperty("AutoGeneratedDomainNameLabelScope",((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).AutoGeneratedDomainNameLabelScope, Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Support.AutoGeneratedDomainNameLabelScope.CreateFrom);
            }
            if (content.Contains("GrafanaIntegrationAzureMonitorWorkspaceIntegration"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).GrafanaIntegrationAzureMonitorWorkspaceIntegration = (Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IAzureMonitorWorkspaceIntegration[]) content.GetValueForProperty("GrafanaIntegrationAzureMonitorWorkspaceIntegration",((Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IManagedGrafanaPropertiesInternal)this).GrafanaIntegrationAzureMonitorWorkspaceIntegration, __y => TypeConverterExtensions.SelectToArray<Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.IAzureMonitorWorkspaceIntegration>(__y, Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Models.Api20220801.AzureMonitorWorkspaceIntegrationTypeConverter.ConvertFrom));
            }
            AfterDeserializePSObject(content);
        }

        /// <summary>Serializes this instance to a json string.</summary>

        /// <returns>a <see cref="System.String" /> containing this model serialized to JSON text.</returns>
        public string ToJsonString() => ToJson(null, Microsoft.Azure.PowerShell.Cmdlets.Dashboard.Runtime.SerializationMode.IncludeAll)?.ToString();

        public override string ToString()
        {
            var returnNow = false;
            var result = global::System.String.Empty;
            OverrideToString(ref result, ref returnNow);
            if (returnNow)
            {
                return result;
            }
            return ToJsonString();
        }
    }
    /// Properties specific to the grafana resource.
    [System.ComponentModel.TypeConverter(typeof(ManagedGrafanaPropertiesTypeConverter))]
    public partial interface IManagedGrafanaProperties

    {

    }
}