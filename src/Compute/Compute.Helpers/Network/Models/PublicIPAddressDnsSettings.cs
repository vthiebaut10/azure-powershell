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
    /// Contains FQDN of the DNS record associated with the public IP address.
    /// </summary>
    public partial class PublicIPAddressDnsSettings
    {
        /// <summary>
        /// Initializes a new instance of the PublicIPAddressDnsSettings class.
        /// </summary>
        public PublicIPAddressDnsSettings()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the PublicIPAddressDnsSettings class.
        /// </summary>
        /// <param name="domainNameLabel">The domain name label. The
        /// concatenation of the domain name label and the regionalized DNS
        /// zone make up the fully qualified domain name associated with the
        /// public IP address. If a domain name label is specified, an A DNS
        /// record is created for the public IP in the Microsoft Azure DNS
        /// system.</param>
        /// <param name="fqdn">The Fully Qualified Domain Name of the A DNS
        /// record associated with the public IP. This is the concatenation of
        /// the domainNameLabel and the regionalized DNS zone.</param>
        /// <param name="reverseFqdn">The reverse FQDN. A user-visible, fully
        /// qualified domain name that resolves to this public IP address. If
        /// the reverseFqdn is specified, then a PTR DNS record is created
        /// pointing from the IP address in the in-addr.arpa domain to the
        /// reverse FQDN.</param>
        public PublicIPAddressDnsSettings(string domainNameLabel = default(string), string fqdn = default(string), string reverseFqdn = default(string))
        {
            DomainNameLabel = domainNameLabel;
            Fqdn = fqdn;
            ReverseFqdn = reverseFqdn;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets the domain name label. The concatenation of the domain
        /// name label and the regionalized DNS zone make up the fully
        /// qualified domain name associated with the public IP address. If a
        /// domain name label is specified, an A DNS record is created for the
        /// public IP in the Microsoft Azure DNS system.
        /// </summary>
        [JsonProperty(PropertyName = "domainNameLabel")]
        public string DomainNameLabel { get; set; }

        /// <summary>
        /// Gets or sets the Fully Qualified Domain Name of the A DNS record
        /// associated with the public IP. This is the concatenation of the
        /// domainNameLabel and the regionalized DNS zone.
        /// </summary>
        [JsonProperty(PropertyName = "fqdn")]
        public string Fqdn { get; set; }

        /// <summary>
        /// Gets or sets the reverse FQDN. A user-visible, fully qualified
        /// domain name that resolves to this public IP address. If the
        /// reverseFqdn is specified, then a PTR DNS record is created pointing
        /// from the IP address in the in-addr.arpa domain to the reverse FQDN.
        /// </summary>
        [JsonProperty(PropertyName = "reverseFqdn")]
        public string ReverseFqdn { get; set; }

    }
}
