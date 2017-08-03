// Code generated by Microsoft (R) AutoRest Code Generator 1.0.1.0
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.

namespace Microsoft.Azure.Management.Internal.Network.Version2017_03_01.Models
{
    using Microsoft.Azure;
    using Microsoft.Azure.Management;
    using Microsoft.Azure.Management.Internal;
    using Microsoft.Azure.Management.Internal.Network;
    using Microsoft.Azure.Management.Internal.Network.Version2017_03_01;
    using Microsoft.Rest;
    using Microsoft.Rest.Serialization;
    using Newtonsoft.Json;
    using System.Collections;
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>
    /// Subnet in a virtual network resource.
    /// </summary>
    [Rest.Serialization.JsonTransformation]
    public partial class Subnet : SubResource
    {
        /// <summary>
        /// Initializes a new instance of the Subnet class.
        /// </summary>
        public Subnet()
        {
          CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the Subnet class.
        /// </summary>
        /// <param name="id">Resource ID.</param>
        /// <param name="addressPrefix">The address prefix for the
        /// subnet.</param>
        /// <param name="networkSecurityGroup">The reference of the
        /// NetworkSecurityGroup resource.</param>
        /// <param name="routeTable">The reference of the RouteTable
        /// resource.</param>
        /// <param name="ipConfigurations">Gets an array of references to the
        /// network interface IP configurations using subnet.</param>
        /// <param name="resourceNavigationLinks">Gets an array of references
        /// to the external resources using subnet.</param>
        /// <param name="provisioningState">The provisioning state of the
        /// resource.</param>
        /// <param name="name">The name of the resource that is unique within a
        /// resource group. This name can be used to access the
        /// resource.</param>
        /// <param name="etag">A unique read-only string that changes whenever
        /// the resource is updated.</param>
        public Subnet(string id = default(string), string addressPrefix = default(string), NetworkSecurityGroup networkSecurityGroup = default(NetworkSecurityGroup), RouteTable routeTable = default(RouteTable), IList<IPConfiguration> ipConfigurations = default(IList<IPConfiguration>), IList<ResourceNavigationLink> resourceNavigationLinks = default(IList<ResourceNavigationLink>), string provisioningState = default(string), string name = default(string), string etag = default(string))
            : base(id)
        {
            AddressPrefix = addressPrefix;
            NetworkSecurityGroup = networkSecurityGroup;
            RouteTable = routeTable;
            IpConfigurations = ipConfigurations;
            ResourceNavigationLinks = resourceNavigationLinks;
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
        /// Gets or sets the address prefix for the subnet.
        /// </summary>
        [JsonProperty(PropertyName = "properties.addressPrefix")]
        public string AddressPrefix { get; set; }

        /// <summary>
        /// Gets or sets the reference of the NetworkSecurityGroup resource.
        /// </summary>
        [JsonProperty(PropertyName = "properties.networkSecurityGroup")]
        public NetworkSecurityGroup NetworkSecurityGroup { get; set; }

        /// <summary>
        /// Gets or sets the reference of the RouteTable resource.
        /// </summary>
        [JsonProperty(PropertyName = "properties.routeTable")]
        public RouteTable RouteTable { get; set; }

        /// <summary>
        /// Gets an array of references to the network interface IP
        /// configurations using subnet.
        /// </summary>
        [JsonProperty(PropertyName = "properties.ipConfigurations")]
        public IList<IPConfiguration> IpConfigurations { get; private set; }

        /// <summary>
        /// Gets an array of references to the external resources using subnet.
        /// </summary>
        [JsonProperty(PropertyName = "properties.resourceNavigationLinks")]
        public IList<ResourceNavigationLink> ResourceNavigationLinks { get; set; }

        /// <summary>
        /// Gets or sets the provisioning state of the resource.
        /// </summary>
        [JsonProperty(PropertyName = "properties.provisioningState")]
        public string ProvisioningState { get; set; }

        /// <summary>
        /// Gets or sets the name of the resource that is unique within a
        /// resource group. This name can be used to access the resource.
        /// </summary>
        [JsonProperty(PropertyName = "name")]
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets a unique read-only string that changes whenever the
        /// resource is updated.
        /// </summary>
        [JsonProperty(PropertyName = "etag")]
        public string Etag { get; set; }

    }
}
