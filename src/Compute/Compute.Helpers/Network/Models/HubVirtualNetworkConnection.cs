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
    /// HubVirtualNetworkConnection Resource.
    /// </summary>
    [Rest.Serialization.JsonTransformation]
    public partial class HubVirtualNetworkConnection : SubResource
    {
        /// <summary>
        /// Initializes a new instance of the HubVirtualNetworkConnection
        /// class.
        /// </summary>
        public HubVirtualNetworkConnection()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the HubVirtualNetworkConnection
        /// class.
        /// </summary>
        /// <param name="id">Resource ID.</param>
        /// <param name="remoteVirtualNetwork">Reference to the remote virtual
        /// network.</param>
        /// <param name="allowHubToRemoteVnetTransit">Deprecated: VirtualHub to
        /// RemoteVnet transit to enabled or not.</param>
        /// <param name="allowRemoteVnetToUseHubVnetGateways">Deprecated: Allow
        /// RemoteVnet to use Virtual Hub's gateways.</param>
        /// <param name="enableInternetSecurity">Enable internet
        /// security.</param>
        /// <param name="routingConfiguration">The Routing Configuration
        /// indicating the associated and propagated route tables on this
        /// connection.</param>
        /// <param name="provisioningState">The provisioning state of the hub
        /// virtual network connection resource. Possible values include:
        /// 'Succeeded', 'Updating', 'Deleting', 'Failed'</param>
        /// <param name="name">The name of the resource that is unique within a
        /// resource group. This name can be used to access the
        /// resource.</param>
        /// <param name="etag">A unique read-only string that changes whenever
        /// the resource is updated.</param>
        public HubVirtualNetworkConnection(string id = default(string), SubResource remoteVirtualNetwork = default(SubResource), bool? allowHubToRemoteVnetTransit = default(bool?), bool? allowRemoteVnetToUseHubVnetGateways = default(bool?), bool? enableInternetSecurity = default(bool?), RoutingConfiguration routingConfiguration = default(RoutingConfiguration), string provisioningState = default(string), string name = default(string), string etag = default(string))
            : base(id)
        {
            RemoteVirtualNetwork = remoteVirtualNetwork;
            AllowHubToRemoteVnetTransit = allowHubToRemoteVnetTransit;
            AllowRemoteVnetToUseHubVnetGateways = allowRemoteVnetToUseHubVnetGateways;
            EnableInternetSecurity = enableInternetSecurity;
            RoutingConfiguration = routingConfiguration;
            ProvisioningState = provisioningState;
            Name = name;
            Etag = etag;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets reference to the remote virtual network.
        /// </summary>
        [JsonProperty(PropertyName = "properties.remoteVirtualNetwork")]
        public SubResource RemoteVirtualNetwork { get; set; }

        /// <summary>
        /// Gets or sets deprecated: VirtualHub to RemoteVnet transit to
        /// enabled or not.
        /// </summary>
        [JsonProperty(PropertyName = "properties.allowHubToRemoteVnetTransit")]
        public bool? AllowHubToRemoteVnetTransit { get; set; }

        /// <summary>
        /// Gets or sets deprecated: Allow RemoteVnet to use Virtual Hub's
        /// gateways.
        /// </summary>
        [JsonProperty(PropertyName = "properties.allowRemoteVnetToUseHubVnetGateways")]
        public bool? AllowRemoteVnetToUseHubVnetGateways { get; set; }

        /// <summary>
        /// Gets or sets enable internet security.
        /// </summary>
        [JsonProperty(PropertyName = "properties.enableInternetSecurity")]
        public bool? EnableInternetSecurity { get; set; }

        /// <summary>
        /// Gets or sets the Routing Configuration indicating the associated
        /// and propagated route tables on this connection.
        /// </summary>
        [JsonProperty(PropertyName = "properties.routingConfiguration")]
        public RoutingConfiguration RoutingConfiguration { get; set; }

        /// <summary>
        /// Gets the provisioning state of the hub virtual network connection
        /// resource. Possible values include: 'Succeeded', 'Updating',
        /// 'Deleting', 'Failed'
        /// </summary>
        [JsonProperty(PropertyName = "properties.provisioningState")]
        public string ProvisioningState { get; private set; }

        /// <summary>
        /// Gets or sets the name of the resource that is unique within a
        /// resource group. This name can be used to access the resource.
        /// </summary>
        [JsonProperty(PropertyName = "name")]
        public string Name { get; set; }

        /// <summary>
        /// Gets a unique read-only string that changes whenever the resource
        /// is updated.
        /// </summary>
        [JsonProperty(PropertyName = "etag")]
        public string Etag { get; private set; }

    }
}
