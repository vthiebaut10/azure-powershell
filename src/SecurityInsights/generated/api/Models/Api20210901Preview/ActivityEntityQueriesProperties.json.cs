// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview
{
    using static Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Extensions;

    /// <summary>Describes activity entity query properties</summary>
    public partial class ActivityEntityQueriesProperties
    {

        /// <summary>
        /// <c>AfterFromJson</c> will be called after the json deserialization has finished, allowing customization of the object
        /// before it is returned. Implement this method in a partial class to enable this behavior
        /// </summary>
        /// <param name="json">The JsonNode that should be deserialized into this object.</param>

        partial void AfterFromJson(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonObject json);

        /// <summary>
        /// <c>AfterToJson</c> will be called after the json serialization has finished, allowing customization of the <see cref="Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonObject"
        /// /> before it is returned. Implement this method in a partial class to enable this behavior
        /// </summary>
        /// <param name="container">The JSON container that the serialization result will be placed in.</param>

        partial void AfterToJson(ref Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonObject container);

        /// <summary>
        /// <c>BeforeFromJson</c> will be called before the json deserialization has commenced, allowing complete customization of
        /// the object before it is deserialized.
        /// If you wish to disable the default deserialization entirely, return <c>true</c> in the <paramref name= "returnNow" />
        /// output parameter.
        /// Implement this method in a partial class to enable this behavior.
        /// </summary>
        /// <param name="json">The JsonNode that should be deserialized into this object.</param>
        /// <param name="returnNow">Determines if the rest of the deserialization should be processed, or if the method should return
        /// instantly.</param>

        partial void BeforeFromJson(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonObject json, ref bool returnNow);

        /// <summary>
        /// <c>BeforeToJson</c> will be called before the json serialization has commenced, allowing complete customization of the
        /// object before it is serialized.
        /// If you wish to disable the default serialization entirely, return <c>true</c> in the <paramref name="returnNow" /> output
        /// parameter.
        /// Implement this method in a partial class to enable this behavior.
        /// </summary>
        /// <param name="container">The JSON container that the serialization result will be placed in.</param>
        /// <param name="returnNow">Determines if the rest of the serialization should be processed, or if the method should return
        /// instantly.</param>

        partial void BeforeToJson(ref Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonObject container, ref bool returnNow);

        /// <summary>
        /// Deserializes a Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonObject into a new instance of <see cref="ActivityEntityQueriesProperties" />.
        /// </summary>
        /// <param name="json">A Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonObject instance to deserialize from.</param>
        internal ActivityEntityQueriesProperties(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonObject json)
        {
            bool returnNow = false;
            BeforeFromJson(json, ref returnNow);
            if (returnNow)
            {
                return;
            }
            {_queryDefinition = If( json?.PropertyT<Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonObject>("queryDefinitions"), out var __jsonQueryDefinitions) ? Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.ActivityEntityQueriesPropertiesQueryDefinitions.FromJson(__jsonQueryDefinitions) : QueryDefinition;}
            {_title = If( json?.PropertyT<Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonString>("title"), out var __jsonTitle) ? (string)__jsonTitle : (string)Title;}
            {_content = If( json?.PropertyT<Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonString>("content"), out var __jsonContent) ? (string)__jsonContent : (string)Content;}
            {_description = If( json?.PropertyT<Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonString>("description"), out var __jsonDescription) ? (string)__jsonDescription : (string)Description;}
            {_inputEntityType = If( json?.PropertyT<Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonString>("inputEntityType"), out var __jsonInputEntityType) ? (string)__jsonInputEntityType : (string)InputEntityType;}
            {_requiredInputFieldsSet = If( json?.PropertyT<Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonArray>("requiredInputFieldsSets"), out var __jsonRequiredInputFieldsSets) ? If( __jsonRequiredInputFieldsSets as Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonArray, out var __u) ? new global::System.Func<string[][]>(()=> global::System.Linq.Enumerable.ToArray(global::System.Linq.Enumerable.Select(__u, (__t)=>(string[]) (If( __t as Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonArray, out var __s) ? new global::System.Func<string[]>(()=> global::System.Linq.Enumerable.ToArray(global::System.Linq.Enumerable.Select(__s, (__r)=>(string) (__r is Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonString __q ? (string)(__q.ToString()) : null)) ))() : null /* arrayOf */)) ))() : null : RequiredInputFieldsSet;}
            {_entitiesFilter = If( json?.PropertyT<Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonObject>("entitiesFilter"), out var __jsonEntitiesFilter) ? Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.ActivityEntityQueriesPropertiesEntitiesFilter.FromJson(__jsonEntitiesFilter) : EntitiesFilter;}
            {_templateName = If( json?.PropertyT<Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonString>("templateName"), out var __jsonTemplateName) ? (string)__jsonTemplateName : (string)TemplateName;}
            {_enabled = If( json?.PropertyT<Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonBoolean>("enabled"), out var __jsonEnabled) ? (bool?)__jsonEnabled : Enabled;}
            {_createdTimeUtc = If( json?.PropertyT<Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonString>("createdTimeUtc"), out var __jsonCreatedTimeUtc) ? global::System.DateTime.TryParse((string)__jsonCreatedTimeUtc, global::System.Globalization.CultureInfo.InvariantCulture, global::System.Globalization.DateTimeStyles.AdjustToUniversal, out var __jsonCreatedTimeUtcValue) ? __jsonCreatedTimeUtcValue : CreatedTimeUtc : CreatedTimeUtc;}
            {_lastModifiedTimeUtc = If( json?.PropertyT<Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonString>("lastModifiedTimeUtc"), out var __jsonLastModifiedTimeUtc) ? global::System.DateTime.TryParse((string)__jsonLastModifiedTimeUtc, global::System.Globalization.CultureInfo.InvariantCulture, global::System.Globalization.DateTimeStyles.AdjustToUniversal, out var __jsonLastModifiedTimeUtcValue) ? __jsonLastModifiedTimeUtcValue : LastModifiedTimeUtc : LastModifiedTimeUtc;}
            AfterFromJson(json);
        }

        /// <summary>
        /// Deserializes a <see cref="Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonNode"/> into an instance of Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IActivityEntityQueriesProperties.
        /// </summary>
        /// <param name="node">a <see cref="Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonNode" /> to deserialize from.</param>
        /// <returns>
        /// an instance of Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IActivityEntityQueriesProperties.
        /// </returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IActivityEntityQueriesProperties FromJson(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonNode node)
        {
            return node is Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonObject json ? new ActivityEntityQueriesProperties(json) : null;
        }

        /// <summary>
        /// Serializes this instance of <see cref="ActivityEntityQueriesProperties" /> into a <see cref="Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonNode" />.
        /// </summary>
        /// <param name="container">The <see cref="Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonObject"/> container to serialize this object into. If the caller
        /// passes in <c>null</c>, a new instance will be created and returned to the caller.</param>
        /// <param name="serializationMode">Allows the caller to choose the depth of the serialization. See <see cref="Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.SerializationMode"/>.</param>
        /// <returns>
        /// a serialized instance of <see cref="ActivityEntityQueriesProperties" /> as a <see cref="Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonNode" />.
        /// </returns>
        public Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonNode ToJson(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonObject container, Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.SerializationMode serializationMode)
        {
            container = container ?? new Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonObject();

            bool returnNow = false;
            BeforeToJson(ref container, ref returnNow);
            if (returnNow)
            {
                return container;
            }
            AddIf( null != this._queryDefinition ? (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonNode) this._queryDefinition.ToJson(null,serializationMode) : null, "queryDefinitions" ,container.Add );
            AddIf( null != (((object)this._title)?.ToString()) ? (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonNode) new Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonString(this._title.ToString()) : null, "title" ,container.Add );
            AddIf( null != (((object)this._content)?.ToString()) ? (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonNode) new Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonString(this._content.ToString()) : null, "content" ,container.Add );
            AddIf( null != (((object)this._description)?.ToString()) ? (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonNode) new Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonString(this._description.ToString()) : null, "description" ,container.Add );
            AddIf( null != (((object)this._inputEntityType)?.ToString()) ? (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonNode) new Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonString(this._inputEntityType.ToString()) : null, "inputEntityType" ,container.Add );
            if (null != this._requiredInputFieldsSet)
            {
                var __w = new Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.XNodeArray();
                foreach( var __x in this._requiredInputFieldsSet )
                {
                    AddIf(null != __x ? new Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.XNodeArray(global::System.Linq.Enumerable.ToArray(System.Linq.Enumerable.Select(__x, (__v) => null != (((object)__v)?.ToString()) ? (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonNode) new Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonString(__v.ToString()) : null))) : null ,__w.Add);
                }
                container.Add("requiredInputFieldsSets",__w);
            }
            AddIf( null != this._entitiesFilter ? (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonNode) this._entitiesFilter.ToJson(null,serializationMode) : null, "entitiesFilter" ,container.Add );
            AddIf( null != (((object)this._templateName)?.ToString()) ? (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonNode) new Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonString(this._templateName.ToString()) : null, "templateName" ,container.Add );
            AddIf( null != this._enabled ? (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonNode)new Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonBoolean((bool)this._enabled) : null, "enabled" ,container.Add );
            if (serializationMode.HasFlag(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.SerializationMode.IncludeReadOnly))
            {
                AddIf( null != this._createdTimeUtc ? (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonNode) new Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonString(this._createdTimeUtc?.ToString(@"yyyy'-'MM'-'dd'T'HH':'mm':'ss.fffffffK",global::System.Globalization.CultureInfo.InvariantCulture)) : null, "createdTimeUtc" ,container.Add );
            }
            if (serializationMode.HasFlag(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.SerializationMode.IncludeReadOnly))
            {
                AddIf( null != this._lastModifiedTimeUtc ? (Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonNode) new Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Json.JsonString(this._lastModifiedTimeUtc?.ToString(@"yyyy'-'MM'-'dd'T'HH':'mm':'ss.fffffffK",global::System.Globalization.CultureInfo.InvariantCulture)) : null, "lastModifiedTimeUtc" ,container.Add );
            }
            AfterToJson(ref container);
            return container;
        }
    }
}