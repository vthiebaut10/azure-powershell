// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview
{
    using Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Runtime.PowerShell;

    [System.ComponentModel.TypeConverter(typeof(ExpandedPropertiesTypeConverter))]
    public partial class ExpandedProperties
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
        /// If you wish to disable the default deserialization entirely, return <c>true</c> in the <see "returnNow" /> output parameter.
        /// Implement this method in a partial class to enable this behavior.
        /// </summary>
        /// <param name="content">The global::System.Collections.IDictionary content that should be used.</param>
        /// <param name="returnNow">Determines if the rest of the serialization should be processed, or if the method should return
        /// instantly.</param>

        partial void BeforeDeserializeDictionary(global::System.Collections.IDictionary content, ref bool returnNow);

        /// <summary>
        /// <c>BeforeDeserializePSObject</c> will be called before the deserialization has commenced, allowing complete customization
        /// of the object before it is deserialized.
        /// If you wish to disable the default deserialization entirely, return <c>true</c> in the <see "returnNow" /> output parameter.
        /// Implement this method in a partial class to enable this behavior.
        /// </summary>
        /// <param name="content">The global::System.Management.Automation.PSObject content that should be used.</param>
        /// <param name="returnNow">Determines if the rest of the serialization should be processed, or if the method should return
        /// instantly.</param>

        partial void BeforeDeserializePSObject(global::System.Management.Automation.PSObject content, ref bool returnNow);

        /// <summary>
        /// Deserializes a <see cref="global::System.Collections.IDictionary" /> into an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.ExpandedProperties"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Collections.IDictionary content that should be used.</param>
        /// <returns>
        /// an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedProperties"
        /// />.
        /// </returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedProperties DeserializeFromDictionary(global::System.Collections.IDictionary content)
        {
            return new ExpandedProperties(content);
        }

        /// <summary>
        /// Deserializes a <see cref="global::System.Management.Automation.PSObject" /> into an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.ExpandedProperties"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Management.Automation.PSObject content that should be used.</param>
        /// <returns>
        /// an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedProperties"
        /// />.
        /// </returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedProperties DeserializeFromPSObject(global::System.Management.Automation.PSObject content)
        {
            return new ExpandedProperties(content);
        }

        /// <summary>
        /// Deserializes a <see cref="global::System.Collections.IDictionary" /> into a new instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.ExpandedProperties"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Collections.IDictionary content that should be used.</param>
        internal ExpandedProperties(global::System.Collections.IDictionary content)
        {
            bool returnNow = false;
            BeforeDeserializeDictionary(content, ref returnNow);
            if (returnNow)
            {
                return;
            }
            // actually deserialize
            if (content.Contains("Scope"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).Scope = (Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesScope) content.GetValueForProperty("Scope",((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).Scope, Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.ExpandedPropertiesScopeTypeConverter.ConvertFrom);
            }
            if (content.Contains("RoleDefinition"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).RoleDefinition = (Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesRoleDefinition) content.GetValueForProperty("RoleDefinition",((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).RoleDefinition, Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.ExpandedPropertiesRoleDefinitionTypeConverter.ConvertFrom);
            }
            if (content.Contains("Principal"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).Principal = (Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesPrincipal) content.GetValueForProperty("Principal",((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).Principal, Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.ExpandedPropertiesPrincipalTypeConverter.ConvertFrom);
            }
            if (content.Contains("ScopeId"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).ScopeId = (string) content.GetValueForProperty("ScopeId",((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).ScopeId, global::System.Convert.ToString);
            }
            if (content.Contains("ScopeDisplayName"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).ScopeDisplayName = (string) content.GetValueForProperty("ScopeDisplayName",((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).ScopeDisplayName, global::System.Convert.ToString);
            }
            if (content.Contains("ScopeType"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).ScopeType = (string) content.GetValueForProperty("ScopeType",((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).ScopeType, global::System.Convert.ToString);
            }
            if (content.Contains("RoleDefinitionId"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).RoleDefinitionId = (string) content.GetValueForProperty("RoleDefinitionId",((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).RoleDefinitionId, global::System.Convert.ToString);
            }
            if (content.Contains("RoleDefinitionDisplayName"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).RoleDefinitionDisplayName = (string) content.GetValueForProperty("RoleDefinitionDisplayName",((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).RoleDefinitionDisplayName, global::System.Convert.ToString);
            }
            if (content.Contains("RoleDefinitionType"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).RoleDefinitionType = (string) content.GetValueForProperty("RoleDefinitionType",((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).RoleDefinitionType, global::System.Convert.ToString);
            }
            if (content.Contains("PrincipalId"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).PrincipalId = (string) content.GetValueForProperty("PrincipalId",((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).PrincipalId, global::System.Convert.ToString);
            }
            if (content.Contains("PrincipalDisplayName"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).PrincipalDisplayName = (string) content.GetValueForProperty("PrincipalDisplayName",((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).PrincipalDisplayName, global::System.Convert.ToString);
            }
            if (content.Contains("PrincipalEmail"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).PrincipalEmail = (string) content.GetValueForProperty("PrincipalEmail",((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).PrincipalEmail, global::System.Convert.ToString);
            }
            if (content.Contains("PrincipalType"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).PrincipalType = (string) content.GetValueForProperty("PrincipalType",((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).PrincipalType, global::System.Convert.ToString);
            }
            AfterDeserializeDictionary(content);
        }

        /// <summary>
        /// Deserializes a <see cref="global::System.Management.Automation.PSObject" /> into a new instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.ExpandedProperties"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Management.Automation.PSObject content that should be used.</param>
        internal ExpandedProperties(global::System.Management.Automation.PSObject content)
        {
            bool returnNow = false;
            BeforeDeserializePSObject(content, ref returnNow);
            if (returnNow)
            {
                return;
            }
            // actually deserialize
            if (content.Contains("Scope"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).Scope = (Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesScope) content.GetValueForProperty("Scope",((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).Scope, Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.ExpandedPropertiesScopeTypeConverter.ConvertFrom);
            }
            if (content.Contains("RoleDefinition"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).RoleDefinition = (Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesRoleDefinition) content.GetValueForProperty("RoleDefinition",((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).RoleDefinition, Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.ExpandedPropertiesRoleDefinitionTypeConverter.ConvertFrom);
            }
            if (content.Contains("Principal"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).Principal = (Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesPrincipal) content.GetValueForProperty("Principal",((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).Principal, Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.ExpandedPropertiesPrincipalTypeConverter.ConvertFrom);
            }
            if (content.Contains("ScopeId"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).ScopeId = (string) content.GetValueForProperty("ScopeId",((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).ScopeId, global::System.Convert.ToString);
            }
            if (content.Contains("ScopeDisplayName"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).ScopeDisplayName = (string) content.GetValueForProperty("ScopeDisplayName",((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).ScopeDisplayName, global::System.Convert.ToString);
            }
            if (content.Contains("ScopeType"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).ScopeType = (string) content.GetValueForProperty("ScopeType",((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).ScopeType, global::System.Convert.ToString);
            }
            if (content.Contains("RoleDefinitionId"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).RoleDefinitionId = (string) content.GetValueForProperty("RoleDefinitionId",((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).RoleDefinitionId, global::System.Convert.ToString);
            }
            if (content.Contains("RoleDefinitionDisplayName"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).RoleDefinitionDisplayName = (string) content.GetValueForProperty("RoleDefinitionDisplayName",((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).RoleDefinitionDisplayName, global::System.Convert.ToString);
            }
            if (content.Contains("RoleDefinitionType"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).RoleDefinitionType = (string) content.GetValueForProperty("RoleDefinitionType",((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).RoleDefinitionType, global::System.Convert.ToString);
            }
            if (content.Contains("PrincipalId"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).PrincipalId = (string) content.GetValueForProperty("PrincipalId",((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).PrincipalId, global::System.Convert.ToString);
            }
            if (content.Contains("PrincipalDisplayName"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).PrincipalDisplayName = (string) content.GetValueForProperty("PrincipalDisplayName",((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).PrincipalDisplayName, global::System.Convert.ToString);
            }
            if (content.Contains("PrincipalEmail"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).PrincipalEmail = (string) content.GetValueForProperty("PrincipalEmail",((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).PrincipalEmail, global::System.Convert.ToString);
            }
            if (content.Contains("PrincipalType"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).PrincipalType = (string) content.GetValueForProperty("PrincipalType",((Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedPropertiesInternal)this).PrincipalType, global::System.Convert.ToString);
            }
            AfterDeserializePSObject(content);
        }

        /// <summary>
        /// Creates a new instance of <see cref="ExpandedProperties" />, deserializing the content from a json string.
        /// </summary>
        /// <param name="jsonText">a string containing a JSON serialized instance of this model.</param>
        /// <returns>an instance of the <see cref="className" /> model class.</returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Models.Api20201001Preview.IExpandedProperties FromJsonString(string jsonText) => FromJson(Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Runtime.Json.JsonNode.Parse(jsonText));

        /// <summary>Serializes this instance to a json string.</summary>

        /// <returns>a <see cref="System.String" /> containing this model serialized to JSON text.</returns>
        public string ToJsonString() => ToJson(null, Microsoft.Azure.PowerShell.Cmdlets.Resources.Authorization.Runtime.SerializationMode.IncludeAll)?.ToString();
    }
    [System.ComponentModel.TypeConverter(typeof(ExpandedPropertiesTypeConverter))]
    public partial interface IExpandedProperties

    {

    }
}