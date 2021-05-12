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
    using System.Collections;
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>
    /// DSCP Configuration in a resource group.
    /// </summary>
    [Rest.Serialization.JsonTransformation]
    public partial class DscpConfiguration : Resource
    {
        /// <summary>
        /// Initializes a new instance of the DscpConfiguration class.
        /// </summary>
        public DscpConfiguration()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the DscpConfiguration class.
        /// </summary>
        /// <param name="id">Resource ID.</param>
        /// <param name="name">Resource name.</param>
        /// <param name="type">Resource type.</param>
        /// <param name="location">Resource location.</param>
        /// <param name="tags">Resource tags.</param>
        /// <param name="markings">List of markings to be used in the
        /// configuration.</param>
        /// <param name="sourceIpRanges">Source IP ranges.</param>
        /// <param name="destinationIpRanges">Destination IP ranges.</param>
        /// <param name="sourcePortRanges">Sources port ranges.</param>
        /// <param name="destinationPortRanges">Destination port
        /// ranges.</param>
        /// <param name="protocol">RNM supported protocol types. Possible
        /// values include: 'DoNotUse', 'Icmp', 'Tcp', 'Udp', 'Gre', 'Esp',
        /// 'Ah', 'Vxlan', 'All'</param>
        /// <param name="qosCollectionId">Qos Collection ID generated by
        /// RNM.</param>
        /// <param name="associatedNetworkInterfaces">Associated Network
        /// Interfaces to the DSCP Configuration.</param>
        /// <param name="resourceGuid">The resource GUID property of the DSCP
        /// Configuration resource.</param>
        /// <param name="provisioningState">The provisioning state of the DSCP
        /// Configuration resource. Possible values include: 'Succeeded',
        /// 'Updating', 'Deleting', 'Failed'</param>
        /// <param name="etag">A unique read-only string that changes whenever
        /// the resource is updated.</param>
        public DscpConfiguration(string id = default(string), string name = default(string), string type = default(string), string location = default(string), IDictionary<string, string> tags = default(IDictionary<string, string>), IList<int?> markings = default(IList<int?>), IList<QosIpRange> sourceIpRanges = default(IList<QosIpRange>), IList<QosIpRange> destinationIpRanges = default(IList<QosIpRange>), IList<QosPortRange> sourcePortRanges = default(IList<QosPortRange>), IList<QosPortRange> destinationPortRanges = default(IList<QosPortRange>), string protocol = default(string), string qosCollectionId = default(string), IList<NetworkInterface> associatedNetworkInterfaces = default(IList<NetworkInterface>), string resourceGuid = default(string), string provisioningState = default(string), string etag = default(string))
            : base(id, name, type, location, tags)
        {
            Markings = markings;
            SourceIpRanges = sourceIpRanges;
            DestinationIpRanges = destinationIpRanges;
            SourcePortRanges = sourcePortRanges;
            DestinationPortRanges = destinationPortRanges;
            Protocol = protocol;
            QosCollectionId = qosCollectionId;
            AssociatedNetworkInterfaces = associatedNetworkInterfaces;
            ResourceGuid = resourceGuid;
            ProvisioningState = provisioningState;
            Etag = etag;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets list of markings to be used in the configuration.
        /// </summary>
        [JsonProperty(PropertyName = "properties.markings")]
        public IList<int?> Markings { get; set; }

        /// <summary>
        /// Gets or sets source IP ranges.
        /// </summary>
        [JsonProperty(PropertyName = "properties.sourceIpRanges")]
        public IList<QosIpRange> SourceIpRanges { get; set; }

        /// <summary>
        /// Gets or sets destination IP ranges.
        /// </summary>
        [JsonProperty(PropertyName = "properties.destinationIpRanges")]
        public IList<QosIpRange> DestinationIpRanges { get; set; }

        /// <summary>
        /// Gets or sets sources port ranges.
        /// </summary>
        [JsonProperty(PropertyName = "properties.sourcePortRanges")]
        public IList<QosPortRange> SourcePortRanges { get; set; }

        /// <summary>
        /// Gets or sets destination port ranges.
        /// </summary>
        [JsonProperty(PropertyName = "properties.destinationPortRanges")]
        public IList<QosPortRange> DestinationPortRanges { get; set; }

        /// <summary>
        /// Gets or sets RNM supported protocol types. Possible values include:
        /// 'DoNotUse', 'Icmp', 'Tcp', 'Udp', 'Gre', 'Esp', 'Ah', 'Vxlan',
        /// 'All'
        /// </summary>
        [JsonProperty(PropertyName = "properties.protocol")]
        public string Protocol { get; set; }

        /// <summary>
        /// Gets qos Collection ID generated by RNM.
        /// </summary>
        [JsonProperty(PropertyName = "properties.qosCollectionId")]
        public string QosCollectionId { get; private set; }

        /// <summary>
        /// Gets associated Network Interfaces to the DSCP Configuration.
        /// </summary>
        [JsonProperty(PropertyName = "properties.associatedNetworkInterfaces")]
        public IList<NetworkInterface> AssociatedNetworkInterfaces { get; private set; }

        /// <summary>
        /// Gets the resource GUID property of the DSCP Configuration resource.
        /// </summary>
        [JsonProperty(PropertyName = "properties.resourceGuid")]
        public string ResourceGuid { get; private set; }

        /// <summary>
        /// Gets the provisioning state of the DSCP Configuration resource.
        /// Possible values include: 'Succeeded', 'Updating', 'Deleting',
        /// 'Failed'
        /// </summary>
        [JsonProperty(PropertyName = "properties.provisioningState")]
        public string ProvisioningState { get; private set; }

        /// <summary>
        /// Gets a unique read-only string that changes whenever the resource
        /// is updated.
        /// </summary>
        [JsonProperty(PropertyName = "etag")]
        public string Etag { get; private set; }

    }
}
