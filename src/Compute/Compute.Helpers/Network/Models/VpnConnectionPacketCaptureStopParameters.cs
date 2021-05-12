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
    /// Vpn Connection packet capture parameters supplied to stop packet
    /// capture on gateway connection.
    /// </summary>
    public partial class VpnConnectionPacketCaptureStopParameters
    {
        /// <summary>
        /// Initializes a new instance of the
        /// VpnConnectionPacketCaptureStopParameters class.
        /// </summary>
        public VpnConnectionPacketCaptureStopParameters()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the
        /// VpnConnectionPacketCaptureStopParameters class.
        /// </summary>
        /// <param name="sasUrl">SAS url for packet capture on vpn
        /// connection.</param>
        /// <param name="linkConnectionNames">List of site link connection
        /// names.</param>
        public VpnConnectionPacketCaptureStopParameters(string sasUrl = default(string), IList<string> linkConnectionNames = default(IList<string>))
        {
            SasUrl = sasUrl;
            LinkConnectionNames = linkConnectionNames;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets SAS url for packet capture on vpn connection.
        /// </summary>
        [JsonProperty(PropertyName = "sasUrl")]
        public string SasUrl { get; set; }

        /// <summary>
        /// Gets or sets list of site link connection names.
        /// </summary>
        [JsonProperty(PropertyName = "linkConnectionNames")]
        public IList<string> LinkConnectionNames { get; set; }

    }
}
