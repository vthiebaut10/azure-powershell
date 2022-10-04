// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801
{
    using Microsoft.Azure.PowerShell.Cmdlets.Functions.Runtime.PowerShell;

    /// <summary>Metadata for the metrics.</summary>
    [System.ComponentModel.TypeConverter(typeof(ResourceMetricDefinitionTypeConverter))]
    public partial class ResourceMetricDefinition
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
        /// Deserializes a <see cref="global::System.Collections.IDictionary" /> into an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.ResourceMetricDefinition"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Collections.IDictionary content that should be used.</param>
        /// <returns>
        /// an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinition" />.
        /// </returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinition DeserializeFromDictionary(global::System.Collections.IDictionary content)
        {
            return new ResourceMetricDefinition(content);
        }

        /// <summary>
        /// Deserializes a <see cref="global::System.Management.Automation.PSObject" /> into an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.ResourceMetricDefinition"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Management.Automation.PSObject content that should be used.</param>
        /// <returns>
        /// an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinition" />.
        /// </returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinition DeserializeFromPSObject(global::System.Management.Automation.PSObject content)
        {
            return new ResourceMetricDefinition(content);
        }

        /// <summary>
        /// Creates a new instance of <see cref="ResourceMetricDefinition" />, deserializing the content from a json string.
        /// </summary>
        /// <param name="jsonText">a string containing a JSON serialized instance of this model.</param>
        /// <returns>an instance of the <see cref="ResourceMetricDefinition" /> model class.</returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinition FromJsonString(string jsonText) => FromJson(Microsoft.Azure.PowerShell.Cmdlets.Functions.Runtime.Json.JsonNode.Parse(jsonText));

        /// <summary>
        /// Deserializes a <see cref="global::System.Collections.IDictionary" /> into a new instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.ResourceMetricDefinition"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Collections.IDictionary content that should be used.</param>
        internal ResourceMetricDefinition(global::System.Collections.IDictionary content)
        {
            bool returnNow = false;
            BeforeDeserializeDictionary(content, ref returnNow);
            if (returnNow)
            {
                return;
            }
            // actually deserialize
            if (content.Contains("Property"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinitionInternal)this).Property = (Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinitionProperties1) content.GetValueForProperty("Property",((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinitionInternal)this).Property, Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.ResourceMetricDefinitionProperties1TypeConverter.ConvertFrom);
            }
            if (content.Contains("Id"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IProxyOnlyResourceInternal)this).Id = (string) content.GetValueForProperty("Id",((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IProxyOnlyResourceInternal)this).Id, global::System.Convert.ToString);
            }
            if (content.Contains("Name"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IProxyOnlyResourceInternal)this).Name = (string) content.GetValueForProperty("Name",((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IProxyOnlyResourceInternal)this).Name, global::System.Convert.ToString);
            }
            if (content.Contains("Kind"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IProxyOnlyResourceInternal)this).Kind = (string) content.GetValueForProperty("Kind",((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IProxyOnlyResourceInternal)this).Kind, global::System.Convert.ToString);
            }
            if (content.Contains("Type"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IProxyOnlyResourceInternal)this).Type = (string) content.GetValueForProperty("Type",((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IProxyOnlyResourceInternal)this).Type, global::System.Convert.ToString);
            }
            if (content.Contains("ResourceMetricDefinitionProperty"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinitionInternal)this).ResourceMetricDefinitionProperty = (Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinitionProperties) content.GetValueForProperty("ResourceMetricDefinitionProperty",((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinitionInternal)this).ResourceMetricDefinitionProperty, Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.ResourceMetricDefinitionPropertiesTypeConverter.ConvertFrom);
            }
            if (content.Contains("Unit"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinitionInternal)this).Unit = (string) content.GetValueForProperty("Unit",((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinitionInternal)this).Unit, global::System.Convert.ToString);
            }
            if (content.Contains("PrimaryAggregationType"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinitionInternal)this).PrimaryAggregationType = (string) content.GetValueForProperty("PrimaryAggregationType",((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinitionInternal)this).PrimaryAggregationType, global::System.Convert.ToString);
            }
            if (content.Contains("MetricAvailability"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinitionInternal)this).MetricAvailability = (Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricAvailability[]) content.GetValueForProperty("MetricAvailability",((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinitionInternal)this).MetricAvailability, __y => TypeConverterExtensions.SelectToArray<Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricAvailability>(__y, Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.ResourceMetricAvailabilityTypeConverter.ConvertFrom));
            }
            if (content.Contains("ResourceUri"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinitionInternal)this).ResourceUri = (string) content.GetValueForProperty("ResourceUri",((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinitionInternal)this).ResourceUri, global::System.Convert.ToString);
            }
            AfterDeserializeDictionary(content);
        }

        /// <summary>
        /// Deserializes a <see cref="global::System.Management.Automation.PSObject" /> into a new instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.ResourceMetricDefinition"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Management.Automation.PSObject content that should be used.</param>
        internal ResourceMetricDefinition(global::System.Management.Automation.PSObject content)
        {
            bool returnNow = false;
            BeforeDeserializePSObject(content, ref returnNow);
            if (returnNow)
            {
                return;
            }
            // actually deserialize
            if (content.Contains("Property"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinitionInternal)this).Property = (Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinitionProperties1) content.GetValueForProperty("Property",((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinitionInternal)this).Property, Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.ResourceMetricDefinitionProperties1TypeConverter.ConvertFrom);
            }
            if (content.Contains("Id"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IProxyOnlyResourceInternal)this).Id = (string) content.GetValueForProperty("Id",((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IProxyOnlyResourceInternal)this).Id, global::System.Convert.ToString);
            }
            if (content.Contains("Name"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IProxyOnlyResourceInternal)this).Name = (string) content.GetValueForProperty("Name",((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IProxyOnlyResourceInternal)this).Name, global::System.Convert.ToString);
            }
            if (content.Contains("Kind"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IProxyOnlyResourceInternal)this).Kind = (string) content.GetValueForProperty("Kind",((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IProxyOnlyResourceInternal)this).Kind, global::System.Convert.ToString);
            }
            if (content.Contains("Type"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IProxyOnlyResourceInternal)this).Type = (string) content.GetValueForProperty("Type",((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IProxyOnlyResourceInternal)this).Type, global::System.Convert.ToString);
            }
            if (content.Contains("ResourceMetricDefinitionProperty"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinitionInternal)this).ResourceMetricDefinitionProperty = (Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinitionProperties) content.GetValueForProperty("ResourceMetricDefinitionProperty",((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinitionInternal)this).ResourceMetricDefinitionProperty, Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.ResourceMetricDefinitionPropertiesTypeConverter.ConvertFrom);
            }
            if (content.Contains("Unit"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinitionInternal)this).Unit = (string) content.GetValueForProperty("Unit",((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinitionInternal)this).Unit, global::System.Convert.ToString);
            }
            if (content.Contains("PrimaryAggregationType"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinitionInternal)this).PrimaryAggregationType = (string) content.GetValueForProperty("PrimaryAggregationType",((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinitionInternal)this).PrimaryAggregationType, global::System.Convert.ToString);
            }
            if (content.Contains("MetricAvailability"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinitionInternal)this).MetricAvailability = (Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricAvailability[]) content.GetValueForProperty("MetricAvailability",((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinitionInternal)this).MetricAvailability, __y => TypeConverterExtensions.SelectToArray<Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricAvailability>(__y, Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.ResourceMetricAvailabilityTypeConverter.ConvertFrom));
            }
            if (content.Contains("ResourceUri"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinitionInternal)this).ResourceUri = (string) content.GetValueForProperty("ResourceUri",((Microsoft.Azure.PowerShell.Cmdlets.Functions.Models.Api20190801.IResourceMetricDefinitionInternal)this).ResourceUri, global::System.Convert.ToString);
            }
            AfterDeserializePSObject(content);
        }

        /// <summary>Serializes this instance to a json string.</summary>

        /// <returns>a <see cref="System.String" /> containing this model serialized to JSON text.</returns>
        public string ToJsonString() => ToJson(null, Microsoft.Azure.PowerShell.Cmdlets.Functions.Runtime.SerializationMode.IncludeAll)?.ToString();
    }
    /// Metadata for the metrics.
    [System.ComponentModel.TypeConverter(typeof(ResourceMetricDefinitionTypeConverter))]
    public partial interface IResourceMetricDefinition

    {

    }
}