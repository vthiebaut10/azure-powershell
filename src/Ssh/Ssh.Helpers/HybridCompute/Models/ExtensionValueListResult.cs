// <auto-generated>
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>

namespace Microsoft.Azure.PowerShell.Ssh.Helpers.HybridCompute.Models
{
    using Newtonsoft.Json;
    using System.Collections;
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>
    /// The List Extension Metadata response.
    /// </summary>
    public partial class ExtensionValueListResult
    {
        /// <summary>
        /// Initializes a new instance of the ExtensionValueListResult class.
        /// </summary>
        public ExtensionValueListResult()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the ExtensionValueListResult class.
        /// </summary>
        /// <param name="value">The list of extension metadata</param>
        public ExtensionValueListResult(IList<ExtensionValue> value = default(IList<ExtensionValue>))
        {
            Value = value;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets the list of extension metadata
        /// </summary>
        [JsonProperty(PropertyName = "value")]
        public IList<ExtensionValue> Value { get; private set; }

    }
}
