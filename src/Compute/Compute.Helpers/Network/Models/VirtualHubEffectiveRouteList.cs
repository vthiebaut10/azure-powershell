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
    using System.Collections;
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>
    /// EffectiveRoutes List.
    /// </summary>
    public partial class VirtualHubEffectiveRouteList
    {
        /// <summary>
        /// Initializes a new instance of the VirtualHubEffectiveRouteList
        /// class.
        /// </summary>
        public VirtualHubEffectiveRouteList()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the VirtualHubEffectiveRouteList
        /// class.
        /// </summary>
        /// <param name="value">The list of effective routes configured on the
        /// virtual hub or the specified resource.</param>
        public VirtualHubEffectiveRouteList(IList<VirtualHubEffectiveRoute> value = default(IList<VirtualHubEffectiveRoute>))
        {
            Value = value;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets the list of effective routes configured on the virtual
        /// hub or the specified resource.
        /// </summary>
        [JsonProperty(PropertyName = "value")]
        public IList<VirtualHubEffectiveRoute> Value { get; set; }

    }
}
