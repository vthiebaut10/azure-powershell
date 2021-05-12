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
    /// Parameters that define the representation of topology.
    /// </summary>
    public partial class TopologyParameters
    {
        /// <summary>
        /// Initializes a new instance of the TopologyParameters class.
        /// </summary>
        public TopologyParameters()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the TopologyParameters class.
        /// </summary>
        /// <param name="targetResourceGroupName">The name of the target
        /// resource group to perform topology on.</param>
        /// <param name="targetVirtualNetwork">The reference to the Virtual
        /// Network resource.</param>
        /// <param name="targetSubnet">The reference to the Subnet
        /// resource.</param>
        public TopologyParameters(string targetResourceGroupName = default(string), SubResource targetVirtualNetwork = default(SubResource), SubResource targetSubnet = default(SubResource))
        {
            TargetResourceGroupName = targetResourceGroupName;
            TargetVirtualNetwork = targetVirtualNetwork;
            TargetSubnet = targetSubnet;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets the name of the target resource group to perform
        /// topology on.
        /// </summary>
        [JsonProperty(PropertyName = "targetResourceGroupName")]
        public string TargetResourceGroupName { get; set; }

        /// <summary>
        /// Gets or sets the reference to the Virtual Network resource.
        /// </summary>
        [JsonProperty(PropertyName = "targetVirtualNetwork")]
        public SubResource TargetVirtualNetwork { get; set; }

        /// <summary>
        /// Gets or sets the reference to the Subnet resource.
        /// </summary>
        [JsonProperty(PropertyName = "targetSubnet")]
        public SubResource TargetSubnet { get; set; }

    }
}
