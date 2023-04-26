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
    using System.Linq;

    /// <summary>
    /// The metadata of the cloud environment (Azure/GCP/AWS/OCI...).
    /// </summary>
    public partial class CloudMetadata
    {
        /// <summary>
        /// Initializes a new instance of the CloudMetadata class.
        /// </summary>
        public CloudMetadata()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the CloudMetadata class.
        /// </summary>
        /// <param name="provider">Specifies the cloud provider
        /// (Azure/AWS/GCP...).</param>
        public CloudMetadata(string provider = default(string))
        {
            Provider = provider;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets specifies the cloud provider (Azure/AWS/GCP...).
        /// </summary>
        [JsonProperty(PropertyName = "provider")]
        public string Provider { get; private set; }

    }
}
