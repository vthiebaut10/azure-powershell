// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.PowerShell.Cmdlets.VMware.Models.Api20211201
{
    using static Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Extensions;

    /// <summary>Properties of a user-invoked script</summary>
    public partial class ScriptExecutionProperties
    {

        /// <summary>
        /// <c>AfterFromJson</c> will be called after the json deserialization has finished, allowing customization of the object
        /// before it is returned. Implement this method in a partial class to enable this behavior
        /// </summary>
        /// <param name="json">The JsonNode that should be deserialized into this object.</param>

        partial void AfterFromJson(Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonObject json);

        /// <summary>
        /// <c>AfterToJson</c> will be called after the json serialization has finished, allowing customization of the <see cref="Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonObject"
        /// /> before it is returned. Implement this method in a partial class to enable this behavior
        /// </summary>
        /// <param name="container">The JSON container that the serialization result will be placed in.</param>

        partial void AfterToJson(ref Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonObject container);

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

        partial void BeforeFromJson(Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonObject json, ref bool returnNow);

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

        partial void BeforeToJson(ref Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonObject container, ref bool returnNow);

        /// <summary>
        /// Deserializes a <see cref="Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonNode"/> into an instance of Microsoft.Azure.PowerShell.Cmdlets.VMware.Models.Api20211201.IScriptExecutionProperties.
        /// </summary>
        /// <param name="node">a <see cref="Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonNode" /> to deserialize from.</param>
        /// <returns>
        /// an instance of Microsoft.Azure.PowerShell.Cmdlets.VMware.Models.Api20211201.IScriptExecutionProperties.
        /// </returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.VMware.Models.Api20211201.IScriptExecutionProperties FromJson(Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonNode node)
        {
            return node is Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonObject json ? new ScriptExecutionProperties(json) : null;
        }

        /// <summary>
        /// Deserializes a Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonObject into a new instance of <see cref="ScriptExecutionProperties" />.
        /// </summary>
        /// <param name="json">A Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonObject instance to deserialize from.</param>
        internal ScriptExecutionProperties(Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonObject json)
        {
            bool returnNow = false;
            BeforeFromJson(json, ref returnNow);
            if (returnNow)
            {
                return;
            }
            {_scriptCmdletId = If( json?.PropertyT<Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonString>("scriptCmdletId"), out var __jsonScriptCmdletId) ? (string)__jsonScriptCmdletId : (string)ScriptCmdletId;}
            {_parameter = If( json?.PropertyT<Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonArray>("parameters"), out var __jsonParameters) ? If( __jsonParameters as Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonArray, out var __v) ? new global::System.Func<Microsoft.Azure.PowerShell.Cmdlets.VMware.Models.Api20211201.IScriptExecutionParameter[]>(()=> global::System.Linq.Enumerable.ToArray(global::System.Linq.Enumerable.Select(__v, (__u)=>(Microsoft.Azure.PowerShell.Cmdlets.VMware.Models.Api20211201.IScriptExecutionParameter) (Microsoft.Azure.PowerShell.Cmdlets.VMware.Models.Api20211201.ScriptExecutionParameter.FromJson(__u) )) ))() : null : Parameter;}
            {_hiddenParameter = If( json?.PropertyT<Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonArray>("hiddenParameters"), out var __jsonHiddenParameters) ? If( __jsonHiddenParameters as Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonArray, out var __q) ? new global::System.Func<Microsoft.Azure.PowerShell.Cmdlets.VMware.Models.Api20211201.IScriptExecutionParameter[]>(()=> global::System.Linq.Enumerable.ToArray(global::System.Linq.Enumerable.Select(__q, (__p)=>(Microsoft.Azure.PowerShell.Cmdlets.VMware.Models.Api20211201.IScriptExecutionParameter) (Microsoft.Azure.PowerShell.Cmdlets.VMware.Models.Api20211201.ScriptExecutionParameter.FromJson(__p) )) ))() : null : HiddenParameter;}
            {_failureReason = If( json?.PropertyT<Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonString>("failureReason"), out var __jsonFailureReason) ? (string)__jsonFailureReason : (string)FailureReason;}
            {_timeout = If( json?.PropertyT<Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonString>("timeout"), out var __jsonTimeout) ? (string)__jsonTimeout : (string)Timeout;}
            {_retention = If( json?.PropertyT<Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonString>("retention"), out var __jsonRetention) ? (string)__jsonRetention : (string)Retention;}
            {_submittedAt = If( json?.PropertyT<Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonString>("submittedAt"), out var __jsonSubmittedAt) ? global::System.DateTime.TryParse((string)__jsonSubmittedAt, global::System.Globalization.CultureInfo.InvariantCulture, global::System.Globalization.DateTimeStyles.AdjustToUniversal, out var __jsonSubmittedAtValue) ? __jsonSubmittedAtValue : SubmittedAt : SubmittedAt;}
            {_startedAt = If( json?.PropertyT<Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonString>("startedAt"), out var __jsonStartedAt) ? global::System.DateTime.TryParse((string)__jsonStartedAt, global::System.Globalization.CultureInfo.InvariantCulture, global::System.Globalization.DateTimeStyles.AdjustToUniversal, out var __jsonStartedAtValue) ? __jsonStartedAtValue : StartedAt : StartedAt;}
            {_finishedAt = If( json?.PropertyT<Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonString>("finishedAt"), out var __jsonFinishedAt) ? global::System.DateTime.TryParse((string)__jsonFinishedAt, global::System.Globalization.CultureInfo.InvariantCulture, global::System.Globalization.DateTimeStyles.AdjustToUniversal, out var __jsonFinishedAtValue) ? __jsonFinishedAtValue : FinishedAt : FinishedAt;}
            {_provisioningState = If( json?.PropertyT<Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonString>("provisioningState"), out var __jsonProvisioningState) ? (string)__jsonProvisioningState : (string)ProvisioningState;}
            {_output = If( json?.PropertyT<Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonArray>("output"), out var __jsonOutput) ? If( __jsonOutput as Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonArray, out var __l) ? new global::System.Func<string[]>(()=> global::System.Linq.Enumerable.ToArray(global::System.Linq.Enumerable.Select(__l, (__k)=>(string) (__k is Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonString __j ? (string)(__j.ToString()) : null)) ))() : null : Output;}
            {_namedOutput = If( json?.PropertyT<Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonObject>("namedOutputs"), out var __jsonNamedOutputs) ? Microsoft.Azure.PowerShell.Cmdlets.VMware.Models.Api20211201.ScriptExecutionPropertiesNamedOutputs.FromJson(__jsonNamedOutputs) : NamedOutput;}
            {_information = If( json?.PropertyT<Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonArray>("information"), out var __jsonInformation) ? If( __jsonInformation as Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonArray, out var __g) ? new global::System.Func<string[]>(()=> global::System.Linq.Enumerable.ToArray(global::System.Linq.Enumerable.Select(__g, (__f)=>(string) (__f is Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonString __e ? (string)(__e.ToString()) : null)) ))() : null : Information;}
            {_warning = If( json?.PropertyT<Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonArray>("warnings"), out var __jsonWarnings) ? If( __jsonWarnings as Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonArray, out var __b) ? new global::System.Func<string[]>(()=> global::System.Linq.Enumerable.ToArray(global::System.Linq.Enumerable.Select(__b, (__a)=>(string) (__a is Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonString ___z ? (string)(___z.ToString()) : null)) ))() : null : Warning;}
            {_error = If( json?.PropertyT<Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonArray>("errors"), out var __jsonErrors) ? If( __jsonErrors as Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonArray, out var ___w) ? new global::System.Func<string[]>(()=> global::System.Linq.Enumerable.ToArray(global::System.Linq.Enumerable.Select(___w, (___v)=>(string) (___v is Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonString ___u ? (string)(___u.ToString()) : null)) ))() : null : Error;}
            AfterFromJson(json);
        }

        /// <summary>
        /// Serializes this instance of <see cref="ScriptExecutionProperties" /> into a <see cref="Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonNode" />.
        /// </summary>
        /// <param name="container">The <see cref="Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonObject"/> container to serialize this object into. If the caller
        /// passes in <c>null</c>, a new instance will be created and returned to the caller.</param>
        /// <param name="serializationMode">Allows the caller to choose the depth of the serialization. See <see cref="Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.SerializationMode"/>.</param>
        /// <returns>
        /// a serialized instance of <see cref="ScriptExecutionProperties" /> as a <see cref="Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonNode" />.
        /// </returns>
        public Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonNode ToJson(Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonObject container, Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.SerializationMode serializationMode)
        {
            container = container ?? new Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonObject();

            bool returnNow = false;
            BeforeToJson(ref container, ref returnNow);
            if (returnNow)
            {
                return container;
            }
            AddIf( null != (((object)this._scriptCmdletId)?.ToString()) ? (Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonNode) new Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonString(this._scriptCmdletId.ToString()) : null, "scriptCmdletId" ,container.Add );
            if (null != this._parameter)
            {
                var __w = new Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.XNodeArray();
                foreach( var __x in this._parameter )
                {
                    AddIf(__x?.ToJson(null, serializationMode) ,__w.Add);
                }
                container.Add("parameters",__w);
            }
            if (null != this._hiddenParameter)
            {
                var __r = new Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.XNodeArray();
                foreach( var __s in this._hiddenParameter )
                {
                    AddIf(__s?.ToJson(null, serializationMode) ,__r.Add);
                }
                container.Add("hiddenParameters",__r);
            }
            AddIf( null != (((object)this._failureReason)?.ToString()) ? (Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonNode) new Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonString(this._failureReason.ToString()) : null, "failureReason" ,container.Add );
            AddIf( null != (((object)this._timeout)?.ToString()) ? (Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonNode) new Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonString(this._timeout.ToString()) : null, "timeout" ,container.Add );
            AddIf( null != (((object)this._retention)?.ToString()) ? (Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonNode) new Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonString(this._retention.ToString()) : null, "retention" ,container.Add );
            if (serializationMode.HasFlag(Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.SerializationMode.IncludeReadOnly))
            {
                AddIf( null != this._submittedAt ? (Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonNode) new Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonString(this._submittedAt?.ToString(@"yyyy'-'MM'-'dd'T'HH':'mm':'ss.fffffffK",global::System.Globalization.CultureInfo.InvariantCulture)) : null, "submittedAt" ,container.Add );
            }
            if (serializationMode.HasFlag(Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.SerializationMode.IncludeReadOnly))
            {
                AddIf( null != this._startedAt ? (Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonNode) new Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonString(this._startedAt?.ToString(@"yyyy'-'MM'-'dd'T'HH':'mm':'ss.fffffffK",global::System.Globalization.CultureInfo.InvariantCulture)) : null, "startedAt" ,container.Add );
            }
            if (serializationMode.HasFlag(Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.SerializationMode.IncludeReadOnly))
            {
                AddIf( null != this._finishedAt ? (Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonNode) new Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonString(this._finishedAt?.ToString(@"yyyy'-'MM'-'dd'T'HH':'mm':'ss.fffffffK",global::System.Globalization.CultureInfo.InvariantCulture)) : null, "finishedAt" ,container.Add );
            }
            if (serializationMode.HasFlag(Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.SerializationMode.IncludeReadOnly))
            {
                AddIf( null != (((object)this._provisioningState)?.ToString()) ? (Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonNode) new Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonString(this._provisioningState.ToString()) : null, "provisioningState" ,container.Add );
            }
            if (null != this._output)
            {
                var __m = new Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.XNodeArray();
                foreach( var __n in this._output )
                {
                    AddIf(null != (((object)__n)?.ToString()) ? (Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonNode) new Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonString(__n.ToString()) : null ,__m.Add);
                }
                container.Add("output",__m);
            }
            AddIf( null != this._namedOutput ? (Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonNode) this._namedOutput.ToJson(null,serializationMode) : null, "namedOutputs" ,container.Add );
            if (serializationMode.HasFlag(Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.SerializationMode.IncludeReadOnly))
            {
                if (null != this._information)
                {
                    var __h = new Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.XNodeArray();
                    foreach( var __i in this._information )
                    {
                        AddIf(null != (((object)__i)?.ToString()) ? (Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonNode) new Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonString(__i.ToString()) : null ,__h.Add);
                    }
                    container.Add("information",__h);
                }
            }
            if (serializationMode.HasFlag(Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.SerializationMode.IncludeReadOnly))
            {
                if (null != this._warning)
                {
                    var __c = new Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.XNodeArray();
                    foreach( var __d in this._warning )
                    {
                        AddIf(null != (((object)__d)?.ToString()) ? (Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonNode) new Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonString(__d.ToString()) : null ,__c.Add);
                    }
                    container.Add("warnings",__c);
                }
            }
            if (serializationMode.HasFlag(Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.SerializationMode.IncludeReadOnly))
            {
                if (null != this._error)
                {
                    var ___x = new Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.XNodeArray();
                    foreach( var ___y in this._error )
                    {
                        AddIf(null != (((object)___y)?.ToString()) ? (Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonNode) new Microsoft.Azure.PowerShell.Cmdlets.VMware.Runtime.Json.JsonString(___y.ToString()) : null ,___x.Add);
                    }
                    container.Add("errors",___x);
                }
            }
            AfterToJson(ref container);
            return container;
        }
    }
}