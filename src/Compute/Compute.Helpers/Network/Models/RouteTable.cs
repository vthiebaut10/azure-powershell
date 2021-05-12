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
    /// Route table resource.
    /// </summary>
    [Rest.Serialization.JsonTransformation]
    public partial class RouteTable : Resource
    {
        /// <summary>
        /// Initializes a new instance of the RouteTable class.
        /// </summary>
        public RouteTable()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the RouteTable class.
        /// </summary>
        /// <param name="id">Resource ID.</param>
        /// <param name="name">Resource name.</param>
        /// <param name="type">Resource type.</param>
        /// <param name="location">Resource location.</param>
        /// <param name="tags">Resource tags.</param>
        /// <param name="routes">Collection of routes contained within a route
        /// table.</param>
        /// <param name="subnets">A collection of references to
        /// subnets.</param>
        /// <param name="disableBgpRoutePropagation">Whether to disable the
        /// routes learned by BGP on that route table. True means
        /// disable.</param>
        /// <param name="provisioningState">The provisioning state of the route
        /// table resource. Possible values include: 'Succeeded', 'Updating',
        /// 'Deleting', 'Failed'</param>
        /// <param name="resourceGuid">The resource GUID property of the route
        /// table.</param>
        /// <param name="etag">A unique read-only string that changes whenever
        /// the resource is updated.</param>
        public RouteTable(string id = default(string), string name = default(string), string type = default(string), string location = default(string), IDictionary<string, string> tags = default(IDictionary<string, string>), IList<Route> routes = default(IList<Route>), IList<Subnet> subnets = default(IList<Subnet>), bool? disableBgpRoutePropagation = default(bool?), string provisioningState = default(string), string resourceGuid = default(string), string etag = default(string))
            : base(id, name, type, location, tags)
        {
            Routes = routes;
            Subnets = subnets;
            DisableBgpRoutePropagation = disableBgpRoutePropagation;
            ProvisioningState = provisioningState;
            ResourceGuid = resourceGuid;
            Etag = etag;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets collection of routes contained within a route table.
        /// </summary>
        [JsonProperty(PropertyName = "properties.routes")]
        public IList<Route> Routes { get; set; }

        /// <summary>
        /// Gets a collection of references to subnets.
        /// </summary>
        [JsonProperty(PropertyName = "properties.subnets")]
        public IList<Subnet> Subnets { get; private set; }

        /// <summary>
        /// Gets or sets whether to disable the routes learned by BGP on that
        /// route table. True means disable.
        /// </summary>
        [JsonProperty(PropertyName = "properties.disableBgpRoutePropagation")]
        public bool? DisableBgpRoutePropagation { get; set; }

        /// <summary>
        /// Gets the provisioning state of the route table resource. Possible
        /// values include: 'Succeeded', 'Updating', 'Deleting', 'Failed'
        /// </summary>
        [JsonProperty(PropertyName = "properties.provisioningState")]
        public string ProvisioningState { get; private set; }

        /// <summary>
        /// Gets the resource GUID property of the route table.
        /// </summary>
        [JsonProperty(PropertyName = "properties.resourceGuid")]
        public string ResourceGuid { get; private set; }

        /// <summary>
        /// Gets a unique read-only string that changes whenever the resource
        /// is updated.
        /// </summary>
        [JsonProperty(PropertyName = "etag")]
        public string Etag { get; private set; }

    }
}
