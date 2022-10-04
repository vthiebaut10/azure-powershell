// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview
{
    using Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.PowerShell;

    /// <summary>Incident Configuration property bag.</summary>
    [System.ComponentModel.TypeConverter(typeof(IncidentConfigurationTypeConverter))]
    public partial class IncidentConfiguration
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
        /// Deserializes a <see cref="global::System.Collections.IDictionary" /> into an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IncidentConfiguration"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Collections.IDictionary content that should be used.</param>
        /// <returns>
        /// an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfiguration"
        /// />.
        /// </returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfiguration DeserializeFromDictionary(global::System.Collections.IDictionary content)
        {
            return new IncidentConfiguration(content);
        }

        /// <summary>
        /// Deserializes a <see cref="global::System.Management.Automation.PSObject" /> into an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IncidentConfiguration"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Management.Automation.PSObject content that should be used.</param>
        /// <returns>
        /// an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfiguration"
        /// />.
        /// </returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfiguration DeserializeFromPSObject(global::System.Management.Automation.PSObject content)
        {
            return new IncidentConfiguration(content);
        }

        /// <summary>
        /// Creates a new instance of <see cref="IncidentConfiguration" />, deserializing the content from a json string.
        /// </summary>
        /// <param name="jsonText">a string containing a JSON serialized instance of this model.</param>
        /// <returns>an instance of the <see cref="IncidentConfiguration" /> model class.</returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfiguration FromJsonString(string jsonText) => FromJson(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonNode.Parse(jsonText));

        /// <summary>
        /// Deserializes a <see cref="global::System.Collections.IDictionary" /> into a new instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IncidentConfiguration"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Collections.IDictionary content that should be used.</param>
        internal IncidentConfiguration(global::System.Collections.IDictionary content)
        {
            bool returnNow = false;
            BeforeDeserializeDictionary(content, ref returnNow);
            if (returnNow)
            {
                return;
            }
            // actually deserialize
            if (content.Contains("GroupingConfiguration"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfiguration = (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IGroupingConfiguration) content.GetValueForProperty("GroupingConfiguration",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfiguration, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.GroupingConfigurationTypeConverter.ConvertFrom);
            }
            if (content.Contains("CreateIncident"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).CreateIncident = (bool) content.GetValueForProperty("CreateIncident",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).CreateIncident, (__y)=> (bool) global::System.Convert.ChangeType(__y, typeof(bool)));
            }
            if (content.Contains("GroupingConfigurationLookbackDuration"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfigurationLookbackDuration = (global::System.TimeSpan) content.GetValueForProperty("GroupingConfigurationLookbackDuration",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfigurationLookbackDuration, (v) => v is global::System.TimeSpan _v ? _v : global::System.Xml.XmlConvert.ToTimeSpan( v.ToString() ));
            }
            if (content.Contains("GroupingConfigurationMatchingMethod"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfigurationMatchingMethod = (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.MatchingMethod) content.GetValueForProperty("GroupingConfigurationMatchingMethod",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfigurationMatchingMethod, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.MatchingMethod.CreateFrom);
            }
            if (content.Contains("GroupingConfigurationEnabled"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfigurationEnabled = (bool) content.GetValueForProperty("GroupingConfigurationEnabled",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfigurationEnabled, (__y)=> (bool) global::System.Convert.ChangeType(__y, typeof(bool)));
            }
            if (content.Contains("GroupingConfigurationReopenClosedIncident"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfigurationReopenClosedIncident = (bool) content.GetValueForProperty("GroupingConfigurationReopenClosedIncident",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfigurationReopenClosedIncident, (__y)=> (bool) global::System.Convert.ChangeType(__y, typeof(bool)));
            }
            if (content.Contains("GroupingConfigurationGroupByEntity"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfigurationGroupByEntity = (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.EntityMappingType[]) content.GetValueForProperty("GroupingConfigurationGroupByEntity",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfigurationGroupByEntity, __y => TypeConverterExtensions.SelectToArray<Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.EntityMappingType>(__y, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.EntityMappingType.CreateFrom));
            }
            if (content.Contains("GroupingConfigurationGroupByAlertDetail"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfigurationGroupByAlertDetail = (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.AlertDetail[]) content.GetValueForProperty("GroupingConfigurationGroupByAlertDetail",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfigurationGroupByAlertDetail, __y => TypeConverterExtensions.SelectToArray<Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.AlertDetail>(__y, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.AlertDetail.CreateFrom));
            }
            if (content.Contains("GroupingConfigurationGroupByCustomDetail"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfigurationGroupByCustomDetail = (string[]) content.GetValueForProperty("GroupingConfigurationGroupByCustomDetail",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfigurationGroupByCustomDetail, __y => TypeConverterExtensions.SelectToArray<string>(__y, global::System.Convert.ToString));
            }
            AfterDeserializeDictionary(content);
        }

        /// <summary>
        /// Deserializes a <see cref="global::System.Management.Automation.PSObject" /> into a new instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IncidentConfiguration"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Management.Automation.PSObject content that should be used.</param>
        internal IncidentConfiguration(global::System.Management.Automation.PSObject content)
        {
            bool returnNow = false;
            BeforeDeserializePSObject(content, ref returnNow);
            if (returnNow)
            {
                return;
            }
            // actually deserialize
            if (content.Contains("GroupingConfiguration"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfiguration = (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IGroupingConfiguration) content.GetValueForProperty("GroupingConfiguration",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfiguration, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.GroupingConfigurationTypeConverter.ConvertFrom);
            }
            if (content.Contains("CreateIncident"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).CreateIncident = (bool) content.GetValueForProperty("CreateIncident",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).CreateIncident, (__y)=> (bool) global::System.Convert.ChangeType(__y, typeof(bool)));
            }
            if (content.Contains("GroupingConfigurationLookbackDuration"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfigurationLookbackDuration = (global::System.TimeSpan) content.GetValueForProperty("GroupingConfigurationLookbackDuration",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfigurationLookbackDuration, (v) => v is global::System.TimeSpan _v ? _v : global::System.Xml.XmlConvert.ToTimeSpan( v.ToString() ));
            }
            if (content.Contains("GroupingConfigurationMatchingMethod"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfigurationMatchingMethod = (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.MatchingMethod) content.GetValueForProperty("GroupingConfigurationMatchingMethod",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfigurationMatchingMethod, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.MatchingMethod.CreateFrom);
            }
            if (content.Contains("GroupingConfigurationEnabled"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfigurationEnabled = (bool) content.GetValueForProperty("GroupingConfigurationEnabled",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfigurationEnabled, (__y)=> (bool) global::System.Convert.ChangeType(__y, typeof(bool)));
            }
            if (content.Contains("GroupingConfigurationReopenClosedIncident"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfigurationReopenClosedIncident = (bool) content.GetValueForProperty("GroupingConfigurationReopenClosedIncident",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfigurationReopenClosedIncident, (__y)=> (bool) global::System.Convert.ChangeType(__y, typeof(bool)));
            }
            if (content.Contains("GroupingConfigurationGroupByEntity"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfigurationGroupByEntity = (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.EntityMappingType[]) content.GetValueForProperty("GroupingConfigurationGroupByEntity",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfigurationGroupByEntity, __y => TypeConverterExtensions.SelectToArray<Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.EntityMappingType>(__y, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.EntityMappingType.CreateFrom));
            }
            if (content.Contains("GroupingConfigurationGroupByAlertDetail"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfigurationGroupByAlertDetail = (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.AlertDetail[]) content.GetValueForProperty("GroupingConfigurationGroupByAlertDetail",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfigurationGroupByAlertDetail, __y => TypeConverterExtensions.SelectToArray<Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.AlertDetail>(__y, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.AlertDetail.CreateFrom));
            }
            if (content.Contains("GroupingConfigurationGroupByCustomDetail"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfigurationGroupByCustomDetail = (string[]) content.GetValueForProperty("GroupingConfigurationGroupByCustomDetail",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IIncidentConfigurationInternal)this).GroupingConfigurationGroupByCustomDetail, __y => TypeConverterExtensions.SelectToArray<string>(__y, global::System.Convert.ToString));
            }
            AfterDeserializePSObject(content);
        }

        /// <summary>Serializes this instance to a json string.</summary>

        /// <returns>a <see cref="System.String" /> containing this model serialized to JSON text.</returns>
        public string ToJsonString() => ToJson(null, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.SerializationMode.IncludeAll)?.ToString();
    }
    /// Incident Configuration property bag.
    [System.ComponentModel.TypeConverter(typeof(IncidentConfigurationTypeConverter))]
    public partial interface IIncidentConfiguration

    {

    }
}