// <auto-generated>
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>

namespace Microsoft.Azure.Commands.Compute.Helpers.Network.Models
{
    using Newtonsoft.Json;
    using System.Linq;

    /// <summary>
    /// Details of UnprepareNetworkPolicies for Subnet.
    /// </summary>
    public partial class UnprepareNetworkPoliciesRequest
    {
        /// <summary>
        /// Initializes a new instance of the UnprepareNetworkPoliciesRequest
        /// class.
        /// </summary>
        public UnprepareNetworkPoliciesRequest()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the UnprepareNetworkPoliciesRequest
        /// class.
        /// </summary>
        /// <param name="serviceName">The name of the service for which subnet
        /// is being unprepared for.</param>
        public UnprepareNetworkPoliciesRequest(string serviceName = default(string))
        {
            ServiceName = serviceName;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets the name of the service for which subnet is being
        /// unprepared for.
        /// </summary>
        [JsonProperty(PropertyName = "serviceName")]
        public string ServiceName { get; set; }

    }
}
