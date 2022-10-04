// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview
{
    using Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.PowerShell;

    /// <summary>
    /// Metadata property bag for patch requests. This is the same as the MetadataProperties, but with nothing required
    /// </summary>
    [System.ComponentModel.TypeConverter(typeof(MetadataPropertiesPatchTypeConverter))]
    public partial class MetadataPropertiesPatch
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
        /// Deserializes a <see cref="global::System.Collections.IDictionary" /> into an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.MetadataPropertiesPatch"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Collections.IDictionary content that should be used.</param>
        /// <returns>
        /// an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatch"
        /// />.
        /// </returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatch DeserializeFromDictionary(global::System.Collections.IDictionary content)
        {
            return new MetadataPropertiesPatch(content);
        }

        /// <summary>
        /// Deserializes a <see cref="global::System.Management.Automation.PSObject" /> into an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.MetadataPropertiesPatch"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Management.Automation.PSObject content that should be used.</param>
        /// <returns>
        /// an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatch"
        /// />.
        /// </returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatch DeserializeFromPSObject(global::System.Management.Automation.PSObject content)
        {
            return new MetadataPropertiesPatch(content);
        }

        /// <summary>
        /// Creates a new instance of <see cref="MetadataPropertiesPatch" />, deserializing the content from a json string.
        /// </summary>
        /// <param name="jsonText">a string containing a JSON serialized instance of this model.</param>
        /// <returns>an instance of the <see cref="MetadataPropertiesPatch" /> model class.</returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatch FromJsonString(string jsonText) => FromJson(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonNode.Parse(jsonText));

        /// <summary>
        /// Deserializes a <see cref="global::System.Collections.IDictionary" /> into a new instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.MetadataPropertiesPatch"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Collections.IDictionary content that should be used.</param>
        internal MetadataPropertiesPatch(global::System.Collections.IDictionary content)
        {
            bool returnNow = false;
            BeforeDeserializeDictionary(content, ref returnNow);
            if (returnNow)
            {
                return;
            }
            // actually deserialize
            if (content.Contains("Source"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Source = (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataSource) content.GetValueForProperty("Source",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Source, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.MetadataSourceTypeConverter.ConvertFrom);
            }
            if (content.Contains("Author"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Author = (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataAuthor) content.GetValueForProperty("Author",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Author, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.MetadataAuthorTypeConverter.ConvertFrom);
            }
            if (content.Contains("Support"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Support = (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataSupport) content.GetValueForProperty("Support",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Support, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.MetadataSupportTypeConverter.ConvertFrom);
            }
            if (content.Contains("Dependency"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Dependency = (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataDependencies) content.GetValueForProperty("Dependency",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Dependency, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.MetadataDependenciesTypeConverter.ConvertFrom);
            }
            if (content.Contains("Category"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Category = (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataCategories) content.GetValueForProperty("Category",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Category, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.MetadataCategoriesTypeConverter.ConvertFrom);
            }
            if (content.Contains("ContentId"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).ContentId = (string) content.GetValueForProperty("ContentId",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).ContentId, global::System.Convert.ToString);
            }
            if (content.Contains("ParentId"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).ParentId = (string) content.GetValueForProperty("ParentId",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).ParentId, global::System.Convert.ToString);
            }
            if (content.Contains("Version"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Version = (string) content.GetValueForProperty("Version",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Version, global::System.Convert.ToString);
            }
            if (content.Contains("Kind"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Kind = (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.Kind?) content.GetValueForProperty("Kind",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Kind, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.Kind.CreateFrom);
            }
            if (content.Contains("Provider"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Provider = (string[]) content.GetValueForProperty("Provider",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Provider, __y => TypeConverterExtensions.SelectToArray<string>(__y, global::System.Convert.ToString));
            }
            if (content.Contains("FirstPublishDate"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).FirstPublishDate = (global::System.DateTime?) content.GetValueForProperty("FirstPublishDate",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).FirstPublishDate, (v) => v is global::System.DateTime _v ? _v : global::System.Xml.XmlConvert.ToDateTime( v.ToString() , global::System.Xml.XmlDateTimeSerializationMode.Unspecified));
            }
            if (content.Contains("LastPublishDate"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).LastPublishDate = (global::System.DateTime?) content.GetValueForProperty("LastPublishDate",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).LastPublishDate, (v) => v is global::System.DateTime _v ? _v : global::System.Xml.XmlConvert.ToDateTime( v.ToString() , global::System.Xml.XmlDateTimeSerializationMode.Unspecified));
            }
            if (content.Contains("SourceKind"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).SourceKind = (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.SourceKind) content.GetValueForProperty("SourceKind",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).SourceKind, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.SourceKind.CreateFrom);
            }
            if (content.Contains("SupportTier"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).SupportTier = (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.SupportTier) content.GetValueForProperty("SupportTier",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).SupportTier, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.SupportTier.CreateFrom);
            }
            if (content.Contains("DependencyKind"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).DependencyKind = (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.Kind?) content.GetValueForProperty("DependencyKind",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).DependencyKind, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.Kind.CreateFrom);
            }
            if (content.Contains("DependencyOperator"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).DependencyOperator = (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.Operator?) content.GetValueForProperty("DependencyOperator",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).DependencyOperator, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.Operator.CreateFrom);
            }
            if (content.Contains("SourceName"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).SourceName = (string) content.GetValueForProperty("SourceName",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).SourceName, global::System.Convert.ToString);
            }
            if (content.Contains("SourceId"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).SourceId = (string) content.GetValueForProperty("SourceId",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).SourceId, global::System.Convert.ToString);
            }
            if (content.Contains("AuthorName"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).AuthorName = (string) content.GetValueForProperty("AuthorName",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).AuthorName, global::System.Convert.ToString);
            }
            if (content.Contains("AuthorEmail"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).AuthorEmail = (string) content.GetValueForProperty("AuthorEmail",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).AuthorEmail, global::System.Convert.ToString);
            }
            if (content.Contains("AuthorLink"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).AuthorLink = (string) content.GetValueForProperty("AuthorLink",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).AuthorLink, global::System.Convert.ToString);
            }
            if (content.Contains("SupportName"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).SupportName = (string) content.GetValueForProperty("SupportName",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).SupportName, global::System.Convert.ToString);
            }
            if (content.Contains("SupportEmail"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).SupportEmail = (string) content.GetValueForProperty("SupportEmail",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).SupportEmail, global::System.Convert.ToString);
            }
            if (content.Contains("SupportLink"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).SupportLink = (string) content.GetValueForProperty("SupportLink",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).SupportLink, global::System.Convert.ToString);
            }
            if (content.Contains("DependencyContentId"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).DependencyContentId = (string) content.GetValueForProperty("DependencyContentId",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).DependencyContentId, global::System.Convert.ToString);
            }
            if (content.Contains("DependencyVersion"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).DependencyVersion = (string) content.GetValueForProperty("DependencyVersion",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).DependencyVersion, global::System.Convert.ToString);
            }
            if (content.Contains("DependencyName"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).DependencyName = (string) content.GetValueForProperty("DependencyName",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).DependencyName, global::System.Convert.ToString);
            }
            if (content.Contains("DependencyCriterion"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).DependencyCriterion = (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataDependencies[]) content.GetValueForProperty("DependencyCriterion",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).DependencyCriterion, __y => TypeConverterExtensions.SelectToArray<Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataDependencies>(__y, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.MetadataDependenciesTypeConverter.ConvertFrom));
            }
            if (content.Contains("CategoryDomain"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).CategoryDomain = (string[]) content.GetValueForProperty("CategoryDomain",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).CategoryDomain, __y => TypeConverterExtensions.SelectToArray<string>(__y, global::System.Convert.ToString));
            }
            if (content.Contains("CategoryVertical"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).CategoryVertical = (string[]) content.GetValueForProperty("CategoryVertical",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).CategoryVertical, __y => TypeConverterExtensions.SelectToArray<string>(__y, global::System.Convert.ToString));
            }
            AfterDeserializeDictionary(content);
        }

        /// <summary>
        /// Deserializes a <see cref="global::System.Management.Automation.PSObject" /> into a new instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.MetadataPropertiesPatch"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Management.Automation.PSObject content that should be used.</param>
        internal MetadataPropertiesPatch(global::System.Management.Automation.PSObject content)
        {
            bool returnNow = false;
            BeforeDeserializePSObject(content, ref returnNow);
            if (returnNow)
            {
                return;
            }
            // actually deserialize
            if (content.Contains("Source"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Source = (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataSource) content.GetValueForProperty("Source",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Source, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.MetadataSourceTypeConverter.ConvertFrom);
            }
            if (content.Contains("Author"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Author = (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataAuthor) content.GetValueForProperty("Author",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Author, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.MetadataAuthorTypeConverter.ConvertFrom);
            }
            if (content.Contains("Support"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Support = (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataSupport) content.GetValueForProperty("Support",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Support, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.MetadataSupportTypeConverter.ConvertFrom);
            }
            if (content.Contains("Dependency"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Dependency = (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataDependencies) content.GetValueForProperty("Dependency",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Dependency, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.MetadataDependenciesTypeConverter.ConvertFrom);
            }
            if (content.Contains("Category"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Category = (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataCategories) content.GetValueForProperty("Category",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Category, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.MetadataCategoriesTypeConverter.ConvertFrom);
            }
            if (content.Contains("ContentId"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).ContentId = (string) content.GetValueForProperty("ContentId",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).ContentId, global::System.Convert.ToString);
            }
            if (content.Contains("ParentId"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).ParentId = (string) content.GetValueForProperty("ParentId",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).ParentId, global::System.Convert.ToString);
            }
            if (content.Contains("Version"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Version = (string) content.GetValueForProperty("Version",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Version, global::System.Convert.ToString);
            }
            if (content.Contains("Kind"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Kind = (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.Kind?) content.GetValueForProperty("Kind",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Kind, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.Kind.CreateFrom);
            }
            if (content.Contains("Provider"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Provider = (string[]) content.GetValueForProperty("Provider",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).Provider, __y => TypeConverterExtensions.SelectToArray<string>(__y, global::System.Convert.ToString));
            }
            if (content.Contains("FirstPublishDate"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).FirstPublishDate = (global::System.DateTime?) content.GetValueForProperty("FirstPublishDate",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).FirstPublishDate, (v) => v is global::System.DateTime _v ? _v : global::System.Xml.XmlConvert.ToDateTime( v.ToString() , global::System.Xml.XmlDateTimeSerializationMode.Unspecified));
            }
            if (content.Contains("LastPublishDate"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).LastPublishDate = (global::System.DateTime?) content.GetValueForProperty("LastPublishDate",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).LastPublishDate, (v) => v is global::System.DateTime _v ? _v : global::System.Xml.XmlConvert.ToDateTime( v.ToString() , global::System.Xml.XmlDateTimeSerializationMode.Unspecified));
            }
            if (content.Contains("SourceKind"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).SourceKind = (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.SourceKind) content.GetValueForProperty("SourceKind",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).SourceKind, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.SourceKind.CreateFrom);
            }
            if (content.Contains("SupportTier"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).SupportTier = (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.SupportTier) content.GetValueForProperty("SupportTier",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).SupportTier, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.SupportTier.CreateFrom);
            }
            if (content.Contains("DependencyKind"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).DependencyKind = (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.Kind?) content.GetValueForProperty("DependencyKind",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).DependencyKind, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.Kind.CreateFrom);
            }
            if (content.Contains("DependencyOperator"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).DependencyOperator = (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.Operator?) content.GetValueForProperty("DependencyOperator",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).DependencyOperator, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Support.Operator.CreateFrom);
            }
            if (content.Contains("SourceName"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).SourceName = (string) content.GetValueForProperty("SourceName",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).SourceName, global::System.Convert.ToString);
            }
            if (content.Contains("SourceId"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).SourceId = (string) content.GetValueForProperty("SourceId",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).SourceId, global::System.Convert.ToString);
            }
            if (content.Contains("AuthorName"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).AuthorName = (string) content.GetValueForProperty("AuthorName",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).AuthorName, global::System.Convert.ToString);
            }
            if (content.Contains("AuthorEmail"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).AuthorEmail = (string) content.GetValueForProperty("AuthorEmail",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).AuthorEmail, global::System.Convert.ToString);
            }
            if (content.Contains("AuthorLink"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).AuthorLink = (string) content.GetValueForProperty("AuthorLink",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).AuthorLink, global::System.Convert.ToString);
            }
            if (content.Contains("SupportName"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).SupportName = (string) content.GetValueForProperty("SupportName",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).SupportName, global::System.Convert.ToString);
            }
            if (content.Contains("SupportEmail"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).SupportEmail = (string) content.GetValueForProperty("SupportEmail",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).SupportEmail, global::System.Convert.ToString);
            }
            if (content.Contains("SupportLink"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).SupportLink = (string) content.GetValueForProperty("SupportLink",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).SupportLink, global::System.Convert.ToString);
            }
            if (content.Contains("DependencyContentId"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).DependencyContentId = (string) content.GetValueForProperty("DependencyContentId",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).DependencyContentId, global::System.Convert.ToString);
            }
            if (content.Contains("DependencyVersion"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).DependencyVersion = (string) content.GetValueForProperty("DependencyVersion",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).DependencyVersion, global::System.Convert.ToString);
            }
            if (content.Contains("DependencyName"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).DependencyName = (string) content.GetValueForProperty("DependencyName",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).DependencyName, global::System.Convert.ToString);
            }
            if (content.Contains("DependencyCriterion"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).DependencyCriterion = (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataDependencies[]) content.GetValueForProperty("DependencyCriterion",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).DependencyCriterion, __y => TypeConverterExtensions.SelectToArray<Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataDependencies>(__y, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.MetadataDependenciesTypeConverter.ConvertFrom));
            }
            if (content.Contains("CategoryDomain"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).CategoryDomain = (string[]) content.GetValueForProperty("CategoryDomain",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).CategoryDomain, __y => TypeConverterExtensions.SelectToArray<string>(__y, global::System.Convert.ToString));
            }
            if (content.Contains("CategoryVertical"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).CategoryVertical = (string[]) content.GetValueForProperty("CategoryVertical",((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMetadataPropertiesPatchInternal)this).CategoryVertical, __y => TypeConverterExtensions.SelectToArray<string>(__y, global::System.Convert.ToString));
            }
            AfterDeserializePSObject(content);
        }

        /// <summary>Serializes this instance to a json string.</summary>

        /// <returns>a <see cref="System.String" /> containing this model serialized to JSON text.</returns>
        public string ToJsonString() => ToJson(null, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.SerializationMode.IncludeAll)?.ToString();
    }
    /// Metadata property bag for patch requests. This is the same as the MetadataProperties, but with nothing required
    [System.ComponentModel.TypeConverter(typeof(MetadataPropertiesPatchTypeConverter))]
    public partial interface IMetadataPropertiesPatch

    {

    }
}