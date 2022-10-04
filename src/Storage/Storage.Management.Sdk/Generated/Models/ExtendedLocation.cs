// <auto-generated>
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>

namespace Microsoft.Azure.Management.Storage.Models
{
    using Newtonsoft.Json;
    using System.Linq;

    /// <summary>
    /// The complex type of the extended location.
    /// </summary>
    public partial class ExtendedLocation
    {
        /// <summary>
        /// Initializes a new instance of the ExtendedLocation class.
        /// </summary>
        public ExtendedLocation()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the ExtendedLocation class.
        /// </summary>
        /// <param name="name">The name of the extended location.</param>
        /// <param name="type">The type of the extended location. Possible
        /// values include: 'EdgeZone'</param>
        public ExtendedLocation(string name = default(string), string type = default(string))
        {
            Name = name;
            Type = type;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets the name of the extended location.
        /// </summary>
        [JsonProperty(PropertyName = "name")]
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets the type of the extended location. Possible values
        /// include: 'EdgeZone'
        /// </summary>
        [JsonProperty(PropertyName = "type")]
        public string Type { get; set; }

    }
}
