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
    using Microsoft.Rest;
    using Microsoft.Rest.Serialization;
    using Newtonsoft.Json;
    using System.Linq;

    /// <summary>
    /// Load balancer backend addresses.
    /// </summary>
    [Rest.Serialization.JsonTransformation]
    public partial class LoadBalancerBackendAddress
    {
        /// <summary>
        /// Initializes a new instance of the LoadBalancerBackendAddress class.
        /// </summary>
        public LoadBalancerBackendAddress()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the LoadBalancerBackendAddress class.
        /// </summary>
        /// <param name="virtualNetwork">Reference to an existing virtual
        /// network.</param>
        /// <param name="subnet">Reference to an existing subnet.</param>
        /// <param name="ipAddress">IP Address belonging to the referenced
        /// virtual network.</param>
        /// <param name="networkInterfaceIPConfiguration">Reference to IP
        /// address defined in network interfaces.</param>
        /// <param name="loadBalancerFrontendIPConfiguration">Reference to the
        /// frontend ip address configuration defined in regional
        /// loadbalancer.</param>
        /// <param name="name">Name of the backend address.</param>
        public LoadBalancerBackendAddress(SubResource virtualNetwork = default(SubResource), SubResource subnet = default(SubResource), string ipAddress = default(string), SubResource networkInterfaceIPConfiguration = default(SubResource), SubResource loadBalancerFrontendIPConfiguration = default(SubResource), string name = default(string))
        {
            VirtualNetwork = virtualNetwork;
            Subnet = subnet;
            IpAddress = ipAddress;
            NetworkInterfaceIPConfiguration = networkInterfaceIPConfiguration;
            LoadBalancerFrontendIPConfiguration = loadBalancerFrontendIPConfiguration;
            Name = name;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets reference to an existing virtual network.
        /// </summary>
        [JsonProperty(PropertyName = "properties.virtualNetwork")]
        public SubResource VirtualNetwork { get; set; }

        /// <summary>
        /// Gets or sets reference to an existing subnet.
        /// </summary>
        [JsonProperty(PropertyName = "properties.subnet")]
        public SubResource Subnet { get; set; }

        /// <summary>
        /// Gets or sets IP Address belonging to the referenced virtual
        /// network.
        /// </summary>
        [JsonProperty(PropertyName = "properties.ipAddress")]
        public string IpAddress { get; set; }

        /// <summary>
        /// Gets reference to IP address defined in network interfaces.
        /// </summary>
        [JsonProperty(PropertyName = "properties.networkInterfaceIPConfiguration")]
        public SubResource NetworkInterfaceIPConfiguration { get; private set; }

        /// <summary>
        /// Gets or sets reference to the frontend ip address configuration
        /// defined in regional loadbalancer.
        /// </summary>
        [JsonProperty(PropertyName = "properties.loadBalancerFrontendIPConfiguration")]
        public SubResource LoadBalancerFrontendIPConfiguration { get; set; }

        /// <summary>
        /// Gets or sets name of the backend address.
        /// </summary>
        [JsonProperty(PropertyName = "name")]
        public string Name { get; set; }

    }
}
