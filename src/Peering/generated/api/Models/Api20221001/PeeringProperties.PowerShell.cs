// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001
{
    using Microsoft.Azure.PowerShell.Cmdlets.Peering.Runtime.PowerShell;

    /// <summary>The properties that define connectivity to the Microsoft Cloud Edge.</summary>
    [System.ComponentModel.TypeConverter(typeof(PeeringPropertiesTypeConverter))]
    public partial class PeeringProperties
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
        /// Deserializes a <see cref="global::System.Collections.IDictionary" /> into an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.PeeringProperties"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Collections.IDictionary content that should be used.</param>
        /// <returns>
        /// an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringProperties" />.
        /// </returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringProperties DeserializeFromDictionary(global::System.Collections.IDictionary content)
        {
            return new PeeringProperties(content);
        }

        /// <summary>
        /// Deserializes a <see cref="global::System.Management.Automation.PSObject" /> into an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.PeeringProperties"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Management.Automation.PSObject content that should be used.</param>
        /// <returns>
        /// an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringProperties" />.
        /// </returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringProperties DeserializeFromPSObject(global::System.Management.Automation.PSObject content)
        {
            return new PeeringProperties(content);
        }

        /// <summary>
        /// Creates a new instance of <see cref="PeeringProperties" />, deserializing the content from a json string.
        /// </summary>
        /// <param name="jsonText">a string containing a JSON serialized instance of this model.</param>
        /// <returns>an instance of the <see cref="PeeringProperties" /> model class.</returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringProperties FromJsonString(string jsonText) => FromJson(Microsoft.Azure.PowerShell.Cmdlets.Peering.Runtime.Json.JsonNode.Parse(jsonText));

        /// <summary>
        /// Deserializes a <see cref="global::System.Collections.IDictionary" /> into a new instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.PeeringProperties"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Collections.IDictionary content that should be used.</param>
        internal PeeringProperties(global::System.Collections.IDictionary content)
        {
            bool returnNow = false;
            BeforeDeserializeDictionary(content, ref returnNow);
            if (returnNow)
            {
                return;
            }
            // actually deserialize
            if (content.Contains("Direct"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).Direct = (Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesDirect) content.GetValueForProperty("Direct",((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).Direct, Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.PeeringPropertiesDirectTypeConverter.ConvertFrom);
            }
            if (content.Contains("Exchange"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).Exchange = (Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesExchange) content.GetValueForProperty("Exchange",((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).Exchange, Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.PeeringPropertiesExchangeTypeConverter.ConvertFrom);
            }
            if (content.Contains("PeeringLocation"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).PeeringLocation = (string) content.GetValueForProperty("PeeringLocation",((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).PeeringLocation, global::System.Convert.ToString);
            }
            if (content.Contains("ProvisioningState"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).ProvisioningState = (Microsoft.Azure.PowerShell.Cmdlets.Peering.Support.ProvisioningState?) content.GetValueForProperty("ProvisioningState",((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).ProvisioningState, Microsoft.Azure.PowerShell.Cmdlets.Peering.Support.ProvisioningState.CreateFrom);
            }
            if (content.Contains("DirectPeerAsn"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).DirectPeerAsn = (Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.ISubResource) content.GetValueForProperty("DirectPeerAsn",((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).DirectPeerAsn, Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.SubResourceTypeConverter.ConvertFrom);
            }
            if (content.Contains("DirectConnection"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).DirectConnection = (Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IDirectConnection[]) content.GetValueForProperty("DirectConnection",((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).DirectConnection, __y => TypeConverterExtensions.SelectToArray<Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IDirectConnection>(__y, Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.DirectConnectionTypeConverter.ConvertFrom));
            }
            if (content.Contains("DirectUseForPeeringService"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).DirectUseForPeeringService = (bool?) content.GetValueForProperty("DirectUseForPeeringService",((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).DirectUseForPeeringService, (__y)=> (bool) global::System.Convert.ChangeType(__y, typeof(bool)));
            }
            if (content.Contains("DirectPeeringType"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).DirectPeeringType = (Microsoft.Azure.PowerShell.Cmdlets.Peering.Support.DirectPeeringType?) content.GetValueForProperty("DirectPeeringType",((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).DirectPeeringType, Microsoft.Azure.PowerShell.Cmdlets.Peering.Support.DirectPeeringType.CreateFrom);
            }
            if (content.Contains("ExchangePeerAsn"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).ExchangePeerAsn = (Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.ISubResource) content.GetValueForProperty("ExchangePeerAsn",((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).ExchangePeerAsn, Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.SubResourceTypeConverter.ConvertFrom);
            }
            if (content.Contains("ExchangeConnection"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).ExchangeConnection = (Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IExchangeConnection[]) content.GetValueForProperty("ExchangeConnection",((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).ExchangeConnection, __y => TypeConverterExtensions.SelectToArray<Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IExchangeConnection>(__y, Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.ExchangeConnectionTypeConverter.ConvertFrom));
            }
            if (content.Contains("DirectPeerAsnId"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).DirectPeerAsnId = (string) content.GetValueForProperty("DirectPeerAsnId",((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).DirectPeerAsnId, global::System.Convert.ToString);
            }
            if (content.Contains("ExchangePeerAsnId"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).ExchangePeerAsnId = (string) content.GetValueForProperty("ExchangePeerAsnId",((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).ExchangePeerAsnId, global::System.Convert.ToString);
            }
            AfterDeserializeDictionary(content);
        }

        /// <summary>
        /// Deserializes a <see cref="global::System.Management.Automation.PSObject" /> into a new instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.PeeringProperties"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Management.Automation.PSObject content that should be used.</param>
        internal PeeringProperties(global::System.Management.Automation.PSObject content)
        {
            bool returnNow = false;
            BeforeDeserializePSObject(content, ref returnNow);
            if (returnNow)
            {
                return;
            }
            // actually deserialize
            if (content.Contains("Direct"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).Direct = (Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesDirect) content.GetValueForProperty("Direct",((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).Direct, Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.PeeringPropertiesDirectTypeConverter.ConvertFrom);
            }
            if (content.Contains("Exchange"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).Exchange = (Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesExchange) content.GetValueForProperty("Exchange",((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).Exchange, Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.PeeringPropertiesExchangeTypeConverter.ConvertFrom);
            }
            if (content.Contains("PeeringLocation"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).PeeringLocation = (string) content.GetValueForProperty("PeeringLocation",((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).PeeringLocation, global::System.Convert.ToString);
            }
            if (content.Contains("ProvisioningState"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).ProvisioningState = (Microsoft.Azure.PowerShell.Cmdlets.Peering.Support.ProvisioningState?) content.GetValueForProperty("ProvisioningState",((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).ProvisioningState, Microsoft.Azure.PowerShell.Cmdlets.Peering.Support.ProvisioningState.CreateFrom);
            }
            if (content.Contains("DirectPeerAsn"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).DirectPeerAsn = (Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.ISubResource) content.GetValueForProperty("DirectPeerAsn",((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).DirectPeerAsn, Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.SubResourceTypeConverter.ConvertFrom);
            }
            if (content.Contains("DirectConnection"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).DirectConnection = (Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IDirectConnection[]) content.GetValueForProperty("DirectConnection",((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).DirectConnection, __y => TypeConverterExtensions.SelectToArray<Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IDirectConnection>(__y, Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.DirectConnectionTypeConverter.ConvertFrom));
            }
            if (content.Contains("DirectUseForPeeringService"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).DirectUseForPeeringService = (bool?) content.GetValueForProperty("DirectUseForPeeringService",((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).DirectUseForPeeringService, (__y)=> (bool) global::System.Convert.ChangeType(__y, typeof(bool)));
            }
            if (content.Contains("DirectPeeringType"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).DirectPeeringType = (Microsoft.Azure.PowerShell.Cmdlets.Peering.Support.DirectPeeringType?) content.GetValueForProperty("DirectPeeringType",((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).DirectPeeringType, Microsoft.Azure.PowerShell.Cmdlets.Peering.Support.DirectPeeringType.CreateFrom);
            }
            if (content.Contains("ExchangePeerAsn"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).ExchangePeerAsn = (Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.ISubResource) content.GetValueForProperty("ExchangePeerAsn",((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).ExchangePeerAsn, Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.SubResourceTypeConverter.ConvertFrom);
            }
            if (content.Contains("ExchangeConnection"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).ExchangeConnection = (Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IExchangeConnection[]) content.GetValueForProperty("ExchangeConnection",((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).ExchangeConnection, __y => TypeConverterExtensions.SelectToArray<Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IExchangeConnection>(__y, Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.ExchangeConnectionTypeConverter.ConvertFrom));
            }
            if (content.Contains("DirectPeerAsnId"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).DirectPeerAsnId = (string) content.GetValueForProperty("DirectPeerAsnId",((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).DirectPeerAsnId, global::System.Convert.ToString);
            }
            if (content.Contains("ExchangePeerAsnId"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).ExchangePeerAsnId = (string) content.GetValueForProperty("ExchangePeerAsnId",((Microsoft.Azure.PowerShell.Cmdlets.Peering.Models.Api20221001.IPeeringPropertiesInternal)this).ExchangePeerAsnId, global::System.Convert.ToString);
            }
            AfterDeserializePSObject(content);
        }

        /// <summary>Serializes this instance to a json string.</summary>

        /// <returns>a <see cref="System.String" /> containing this model serialized to JSON text.</returns>
        public string ToJsonString() => ToJson(null, Microsoft.Azure.PowerShell.Cmdlets.Peering.Runtime.SerializationMode.IncludeAll)?.ToString();

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
    /// The properties that define connectivity to the Microsoft Cloud Edge.
    [System.ComponentModel.TypeConverter(typeof(PeeringPropertiesTypeConverter))]
    public partial interface IPeeringProperties

    {

    }
}