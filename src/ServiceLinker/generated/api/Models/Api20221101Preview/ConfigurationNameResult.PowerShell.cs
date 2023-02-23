// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20221101Preview
{
    using Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Runtime.PowerShell;

    /// <summary>
    /// Configuration Name list which will be set based on different target resource, client type, auth type.
    /// </summary>
    [System.ComponentModel.TypeConverter(typeof(ConfigurationNameResultTypeConverter))]
    public partial class ConfigurationNameResult
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
        /// Deserializes a <see cref="global::System.Collections.IDictionary" /> into a new instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20221101Preview.ConfigurationNameResult"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Collections.IDictionary content that should be used.</param>
        internal ConfigurationNameResult(global::System.Collections.IDictionary content)
        {
            bool returnNow = false;
            BeforeDeserializeDictionary(content, ref returnNow);
            if (returnNow)
            {
                return;
            }
            // actually deserialize
            if (content.Contains("Value"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20221101Preview.IConfigurationNameResultInternal)this).Value = (Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20221101Preview.IConfigurationNameItem[]) content.GetValueForProperty("Value",((Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20221101Preview.IConfigurationNameResultInternal)this).Value, __y => TypeConverterExtensions.SelectToArray<Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20221101Preview.IConfigurationNameItem>(__y, Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20221101Preview.ConfigurationNameItemTypeConverter.ConvertFrom));
            }
            if (content.Contains("NextLink"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20221101Preview.IConfigurationNameResultInternal)this).NextLink = (string) content.GetValueForProperty("NextLink",((Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20221101Preview.IConfigurationNameResultInternal)this).NextLink, global::System.Convert.ToString);
            }
            AfterDeserializeDictionary(content);
        }

        /// <summary>
        /// Deserializes a <see cref="global::System.Management.Automation.PSObject" /> into a new instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20221101Preview.ConfigurationNameResult"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Management.Automation.PSObject content that should be used.</param>
        internal ConfigurationNameResult(global::System.Management.Automation.PSObject content)
        {
            bool returnNow = false;
            BeforeDeserializePSObject(content, ref returnNow);
            if (returnNow)
            {
                return;
            }
            // actually deserialize
            if (content.Contains("Value"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20221101Preview.IConfigurationNameResultInternal)this).Value = (Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20221101Preview.IConfigurationNameItem[]) content.GetValueForProperty("Value",((Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20221101Preview.IConfigurationNameResultInternal)this).Value, __y => TypeConverterExtensions.SelectToArray<Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20221101Preview.IConfigurationNameItem>(__y, Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20221101Preview.ConfigurationNameItemTypeConverter.ConvertFrom));
            }
            if (content.Contains("NextLink"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20221101Preview.IConfigurationNameResultInternal)this).NextLink = (string) content.GetValueForProperty("NextLink",((Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20221101Preview.IConfigurationNameResultInternal)this).NextLink, global::System.Convert.ToString);
            }
            AfterDeserializePSObject(content);
        }

        /// <summary>
        /// Deserializes a <see cref="global::System.Collections.IDictionary" /> into an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20221101Preview.ConfigurationNameResult"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Collections.IDictionary content that should be used.</param>
        /// <returns>
        /// an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20221101Preview.IConfigurationNameResult"
        /// />.
        /// </returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20221101Preview.IConfigurationNameResult DeserializeFromDictionary(global::System.Collections.IDictionary content)
        {
            return new ConfigurationNameResult(content);
        }

        /// <summary>
        /// Deserializes a <see cref="global::System.Management.Automation.PSObject" /> into an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20221101Preview.ConfigurationNameResult"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Management.Automation.PSObject content that should be used.</param>
        /// <returns>
        /// an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20221101Preview.IConfigurationNameResult"
        /// />.
        /// </returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20221101Preview.IConfigurationNameResult DeserializeFromPSObject(global::System.Management.Automation.PSObject content)
        {
            return new ConfigurationNameResult(content);
        }

        /// <summary>
        /// Creates a new instance of <see cref="ConfigurationNameResult" />, deserializing the content from a json string.
        /// </summary>
        /// <param name="jsonText">a string containing a JSON serialized instance of this model.</param>
        /// <returns>an instance of the <see cref="ConfigurationNameResult" /> model class.</returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20221101Preview.IConfigurationNameResult FromJsonString(string jsonText) => FromJson(Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Runtime.Json.JsonNode.Parse(jsonText));

        /// <summary>Serializes this instance to a json string.</summary>

        /// <returns>a <see cref="System.String" /> containing this model serialized to JSON text.</returns>
        public string ToJsonString() => ToJson(null, Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Runtime.SerializationMode.IncludeAll)?.ToString();
    }
    /// Configuration Name list which will be set based on different target resource, client type, auth type.
    [System.ComponentModel.TypeConverter(typeof(ConfigurationNameResultTypeConverter))]
    public partial interface IConfigurationNameResult

    {

    }
}