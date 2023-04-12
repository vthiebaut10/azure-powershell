// <auto-generated>
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>

namespace Microsoft.Azure.PowerShell.Ssh.Helpers.HybridConnectivity.Models
{
    using Newtonsoft.Json;
    using System.Linq;

    /// <summary>
    /// The endpoint for the target resource.
    /// </summary>
    public partial class EndpointResource : ProxyResource
    {
        /// <summary>
        /// Initializes a new instance of the EndpointResource class.
        /// </summary>
        public EndpointResource()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the EndpointResource class.
        /// </summary>
        /// <param name="id">Fully qualified resource ID for the resource. E.g.
        /// "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}"</param>
        /// <param name="name">The name of the resource</param>
        /// <param name="type">The type of the resource. E.g.
        /// "Microsoft.Compute/virtualMachines" or
        /// "Microsoft.Storage/storageAccounts"</param>
        /// <param name="systemData">Azure Resource Manager metadata containing
        /// createdBy and modifiedBy information.</param>
        /// <param name="properties">The endpoint properties.</param>
        public EndpointResource(string id = default(string), string name = default(string), string type = default(string), SystemData systemData = default(SystemData), EndpointProperties properties = default(EndpointProperties))
            : base(id, name, type, systemData)
        {
            Properties = properties;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets the endpoint properties.
        /// </summary>
        [JsonProperty(PropertyName = "properties")]
        public EndpointProperties Properties { get; set; }

        /// <summary>
        /// Validate the object.
        /// </summary>
        /// <exception cref="Rest.ValidationException">
        /// Thrown if validation fails
        /// </exception>
        public virtual void Validate()
        {
            if (Properties != null)
            {
                Properties.Validate();
            }
        }
    }
}
