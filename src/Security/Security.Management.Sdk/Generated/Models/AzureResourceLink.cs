// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.Management.Security.Models
{
    using System.Linq;

    /// <summary>
    /// Describes an Azure resource with kind
    /// </summary>
    public partial class AzureResourceLink
    {
        /// <summary>
        /// Initializes a new instance of the AzureResourceLink class.
        /// </summary>
        public AzureResourceLink()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the AzureResourceLink class.
        /// </summary>

        /// <param name="id">Azure resource Id
        /// </param>
        public AzureResourceLink(string id = default(string))

        {
            this.Id = id;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();


        /// <summary>
        /// Gets azure resource Id
        /// </summary>
        [Newtonsoft.Json.JsonProperty(PropertyName = "id")]
        public string Id {get; private set; }
    }
}