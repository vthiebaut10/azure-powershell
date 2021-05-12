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
    /// Describes the ICMP configuration.
    /// </summary>
    public partial class ConnectionMonitorIcmpConfiguration
    {
        /// <summary>
        /// Initializes a new instance of the
        /// ConnectionMonitorIcmpConfiguration class.
        /// </summary>
        public ConnectionMonitorIcmpConfiguration()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the
        /// ConnectionMonitorIcmpConfiguration class.
        /// </summary>
        /// <param name="disableTraceRoute">Value indicating whether path
        /// evaluation with trace route should be disabled.</param>
        public ConnectionMonitorIcmpConfiguration(bool? disableTraceRoute = default(bool?))
        {
            DisableTraceRoute = disableTraceRoute;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets value indicating whether path evaluation with trace
        /// route should be disabled.
        /// </summary>
        [JsonProperty(PropertyName = "disableTraceRoute")]
        public bool? DisableTraceRoute { get; set; }

    }
}
