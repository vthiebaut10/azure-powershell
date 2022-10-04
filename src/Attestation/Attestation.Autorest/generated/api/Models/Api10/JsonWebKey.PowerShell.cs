// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10
{
    using Microsoft.Azure.PowerShell.Cmdlets.Attestation.Runtime.PowerShell;

    [System.ComponentModel.TypeConverter(typeof(JsonWebKeyTypeConverter))]
    public partial class JsonWebKey
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
        /// Deserializes a <see cref="global::System.Collections.IDictionary" /> into an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.JsonWebKey"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Collections.IDictionary content that should be used.</param>
        /// <returns>
        /// an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKey" />.
        /// </returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKey DeserializeFromDictionary(global::System.Collections.IDictionary content)
        {
            return new JsonWebKey(content);
        }

        /// <summary>
        /// Deserializes a <see cref="global::System.Management.Automation.PSObject" /> into an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.JsonWebKey"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Management.Automation.PSObject content that should be used.</param>
        /// <returns>
        /// an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKey" />.
        /// </returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKey DeserializeFromPSObject(global::System.Management.Automation.PSObject content)
        {
            return new JsonWebKey(content);
        }

        /// <summary>
        /// Creates a new instance of <see cref="JsonWebKey" />, deserializing the content from a json string.
        /// </summary>
        /// <param name="jsonText">a string containing a JSON serialized instance of this model.</param>
        /// <returns>an instance of the <see cref="JsonWebKey" /> model class.</returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKey FromJsonString(string jsonText) => FromJson(Microsoft.Azure.PowerShell.Cmdlets.Attestation.Runtime.Json.JsonNode.Parse(jsonText));

        /// <summary>
        /// Deserializes a <see cref="global::System.Collections.IDictionary" /> into a new instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.JsonWebKey"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Collections.IDictionary content that should be used.</param>
        internal JsonWebKey(global::System.Collections.IDictionary content)
        {
            bool returnNow = false;
            BeforeDeserializeDictionary(content, ref returnNow);
            if (returnNow)
            {
                return;
            }
            // actually deserialize
            if (content.Contains("Alg"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Alg = (string) content.GetValueForProperty("Alg",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Alg, global::System.Convert.ToString);
            }
            if (content.Contains("Crv"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Crv = (string) content.GetValueForProperty("Crv",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Crv, global::System.Convert.ToString);
            }
            if (content.Contains("D"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).D = (string) content.GetValueForProperty("D",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).D, global::System.Convert.ToString);
            }
            if (content.Contains("Dp"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Dp = (string) content.GetValueForProperty("Dp",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Dp, global::System.Convert.ToString);
            }
            if (content.Contains("Dq"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Dq = (string) content.GetValueForProperty("Dq",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Dq, global::System.Convert.ToString);
            }
            if (content.Contains("E"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).E = (string) content.GetValueForProperty("E",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).E, global::System.Convert.ToString);
            }
            if (content.Contains("K"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).K = (string) content.GetValueForProperty("K",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).K, global::System.Convert.ToString);
            }
            if (content.Contains("Kid"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Kid = (string) content.GetValueForProperty("Kid",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Kid, global::System.Convert.ToString);
            }
            if (content.Contains("Kty"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Kty = (string) content.GetValueForProperty("Kty",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Kty, global::System.Convert.ToString);
            }
            if (content.Contains("N"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).N = (string) content.GetValueForProperty("N",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).N, global::System.Convert.ToString);
            }
            if (content.Contains("P"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).P = (string) content.GetValueForProperty("P",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).P, global::System.Convert.ToString);
            }
            if (content.Contains("Q"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Q = (string) content.GetValueForProperty("Q",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Q, global::System.Convert.ToString);
            }
            if (content.Contains("Qi"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Qi = (string) content.GetValueForProperty("Qi",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Qi, global::System.Convert.ToString);
            }
            if (content.Contains("Use"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Use = (string) content.GetValueForProperty("Use",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Use, global::System.Convert.ToString);
            }
            if (content.Contains("X"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).X = (string) content.GetValueForProperty("X",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).X, global::System.Convert.ToString);
            }
            if (content.Contains("X5C"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).X5C = (string[]) content.GetValueForProperty("X5C",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).X5C, __y => TypeConverterExtensions.SelectToArray<string>(__y, global::System.Convert.ToString));
            }
            if (content.Contains("Y"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Y = (string) content.GetValueForProperty("Y",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Y, global::System.Convert.ToString);
            }
            AfterDeserializeDictionary(content);
        }

        /// <summary>
        /// Deserializes a <see cref="global::System.Management.Automation.PSObject" /> into a new instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.JsonWebKey"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Management.Automation.PSObject content that should be used.</param>
        internal JsonWebKey(global::System.Management.Automation.PSObject content)
        {
            bool returnNow = false;
            BeforeDeserializePSObject(content, ref returnNow);
            if (returnNow)
            {
                return;
            }
            // actually deserialize
            if (content.Contains("Alg"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Alg = (string) content.GetValueForProperty("Alg",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Alg, global::System.Convert.ToString);
            }
            if (content.Contains("Crv"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Crv = (string) content.GetValueForProperty("Crv",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Crv, global::System.Convert.ToString);
            }
            if (content.Contains("D"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).D = (string) content.GetValueForProperty("D",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).D, global::System.Convert.ToString);
            }
            if (content.Contains("Dp"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Dp = (string) content.GetValueForProperty("Dp",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Dp, global::System.Convert.ToString);
            }
            if (content.Contains("Dq"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Dq = (string) content.GetValueForProperty("Dq",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Dq, global::System.Convert.ToString);
            }
            if (content.Contains("E"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).E = (string) content.GetValueForProperty("E",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).E, global::System.Convert.ToString);
            }
            if (content.Contains("K"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).K = (string) content.GetValueForProperty("K",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).K, global::System.Convert.ToString);
            }
            if (content.Contains("Kid"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Kid = (string) content.GetValueForProperty("Kid",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Kid, global::System.Convert.ToString);
            }
            if (content.Contains("Kty"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Kty = (string) content.GetValueForProperty("Kty",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Kty, global::System.Convert.ToString);
            }
            if (content.Contains("N"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).N = (string) content.GetValueForProperty("N",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).N, global::System.Convert.ToString);
            }
            if (content.Contains("P"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).P = (string) content.GetValueForProperty("P",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).P, global::System.Convert.ToString);
            }
            if (content.Contains("Q"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Q = (string) content.GetValueForProperty("Q",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Q, global::System.Convert.ToString);
            }
            if (content.Contains("Qi"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Qi = (string) content.GetValueForProperty("Qi",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Qi, global::System.Convert.ToString);
            }
            if (content.Contains("Use"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Use = (string) content.GetValueForProperty("Use",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Use, global::System.Convert.ToString);
            }
            if (content.Contains("X"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).X = (string) content.GetValueForProperty("X",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).X, global::System.Convert.ToString);
            }
            if (content.Contains("X5C"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).X5C = (string[]) content.GetValueForProperty("X5C",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).X5C, __y => TypeConverterExtensions.SelectToArray<string>(__y, global::System.Convert.ToString));
            }
            if (content.Contains("Y"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Y = (string) content.GetValueForProperty("Y",((Microsoft.Azure.PowerShell.Cmdlets.Attestation.Models.Api10.IJsonWebKeyInternal)this).Y, global::System.Convert.ToString);
            }
            AfterDeserializePSObject(content);
        }

        /// <summary>Serializes this instance to a json string.</summary>

        /// <returns>a <see cref="System.String" /> containing this model serialized to JSON text.</returns>
        public string ToJsonString() => ToJson(null, Microsoft.Azure.PowerShell.Cmdlets.Attestation.Runtime.SerializationMode.IncludeAll)?.ToString();

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
    [System.ComponentModel.TypeConverter(typeof(JsonWebKeyTypeConverter))]
    public partial interface IJsonWebKey

    {

    }
}