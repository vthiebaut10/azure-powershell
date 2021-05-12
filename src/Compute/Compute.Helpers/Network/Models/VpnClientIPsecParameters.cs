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
    using Newtonsoft.Json;
    using System.Linq;

    /// <summary>
    /// An IPSec parameters for a virtual network gateway P2S connection.
    /// </summary>
    public partial class VpnClientIPsecParameters
    {
        /// <summary>
        /// Initializes a new instance of the VpnClientIPsecParameters class.
        /// </summary>
        public VpnClientIPsecParameters()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the VpnClientIPsecParameters class.
        /// </summary>
        /// <param name="saLifeTimeSeconds">The IPSec Security Association
        /// (also called Quick Mode or Phase 2 SA) lifetime in seconds for P2S
        /// client.</param>
        /// <param name="saDataSizeKilobytes">The IPSec Security Association
        /// (also called Quick Mode or Phase 2 SA) payload size in KB for P2S
        /// client..</param>
        /// <param name="ipsecEncryption">The IPSec encryption algorithm (IKE
        /// phase 1). Possible values include: 'None', 'DES', 'DES3', 'AES128',
        /// 'AES192', 'AES256', 'GCMAES128', 'GCMAES192', 'GCMAES256'</param>
        /// <param name="ipsecIntegrity">The IPSec integrity algorithm (IKE
        /// phase 1). Possible values include: 'MD5', 'SHA1', 'SHA256',
        /// 'GCMAES128', 'GCMAES192', 'GCMAES256'</param>
        /// <param name="ikeEncryption">The IKE encryption algorithm (IKE phase
        /// 2). Possible values include: 'DES', 'DES3', 'AES128', 'AES192',
        /// 'AES256', 'GCMAES256', 'GCMAES128'</param>
        /// <param name="ikeIntegrity">The IKE integrity algorithm (IKE phase
        /// 2). Possible values include: 'MD5', 'SHA1', 'SHA256', 'SHA384',
        /// 'GCMAES256', 'GCMAES128'</param>
        /// <param name="dhGroup">The DH Group used in IKE Phase 1 for initial
        /// SA. Possible values include: 'None', 'DHGroup1', 'DHGroup2',
        /// 'DHGroup14', 'DHGroup2048', 'ECP256', 'ECP384', 'DHGroup24'</param>
        /// <param name="pfsGroup">The Pfs Group used in IKE Phase 2 for new
        /// child SA. Possible values include: 'None', 'PFS1', 'PFS2',
        /// 'PFS2048', 'ECP256', 'ECP384', 'PFS24', 'PFS14', 'PFSMM'</param>
        public VpnClientIPsecParameters(int saLifeTimeSeconds, int saDataSizeKilobytes, string ipsecEncryption, string ipsecIntegrity, string ikeEncryption, string ikeIntegrity, string dhGroup, string pfsGroup)
        {
            SaLifeTimeSeconds = saLifeTimeSeconds;
            SaDataSizeKilobytes = saDataSizeKilobytes;
            IpsecEncryption = ipsecEncryption;
            IpsecIntegrity = ipsecIntegrity;
            IkeEncryption = ikeEncryption;
            IkeIntegrity = ikeIntegrity;
            DhGroup = dhGroup;
            PfsGroup = pfsGroup;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets the IPSec Security Association (also called Quick Mode
        /// or Phase 2 SA) lifetime in seconds for P2S client.
        /// </summary>
        [JsonProperty(PropertyName = "saLifeTimeSeconds")]
        public int SaLifeTimeSeconds { get; set; }

        /// <summary>
        /// Gets or sets the IPSec Security Association (also called Quick Mode
        /// or Phase 2 SA) payload size in KB for P2S client..
        /// </summary>
        [JsonProperty(PropertyName = "saDataSizeKilobytes")]
        public int SaDataSizeKilobytes { get; set; }

        /// <summary>
        /// Gets or sets the IPSec encryption algorithm (IKE phase 1). Possible
        /// values include: 'None', 'DES', 'DES3', 'AES128', 'AES192',
        /// 'AES256', 'GCMAES128', 'GCMAES192', 'GCMAES256'
        /// </summary>
        [JsonProperty(PropertyName = "ipsecEncryption")]
        public string IpsecEncryption { get; set; }

        /// <summary>
        /// Gets or sets the IPSec integrity algorithm (IKE phase 1). Possible
        /// values include: 'MD5', 'SHA1', 'SHA256', 'GCMAES128', 'GCMAES192',
        /// 'GCMAES256'
        /// </summary>
        [JsonProperty(PropertyName = "ipsecIntegrity")]
        public string IpsecIntegrity { get; set; }

        /// <summary>
        /// Gets or sets the IKE encryption algorithm (IKE phase 2). Possible
        /// values include: 'DES', 'DES3', 'AES128', 'AES192', 'AES256',
        /// 'GCMAES256', 'GCMAES128'
        /// </summary>
        [JsonProperty(PropertyName = "ikeEncryption")]
        public string IkeEncryption { get; set; }

        /// <summary>
        /// Gets or sets the IKE integrity algorithm (IKE phase 2). Possible
        /// values include: 'MD5', 'SHA1', 'SHA256', 'SHA384', 'GCMAES256',
        /// 'GCMAES128'
        /// </summary>
        [JsonProperty(PropertyName = "ikeIntegrity")]
        public string IkeIntegrity { get; set; }

        /// <summary>
        /// Gets or sets the DH Group used in IKE Phase 1 for initial SA.
        /// Possible values include: 'None', 'DHGroup1', 'DHGroup2',
        /// 'DHGroup14', 'DHGroup2048', 'ECP256', 'ECP384', 'DHGroup24'
        /// </summary>
        [JsonProperty(PropertyName = "dhGroup")]
        public string DhGroup { get; set; }

        /// <summary>
        /// Gets or sets the Pfs Group used in IKE Phase 2 for new child SA.
        /// Possible values include: 'None', 'PFS1', 'PFS2', 'PFS2048',
        /// 'ECP256', 'ECP384', 'PFS24', 'PFS14', 'PFSMM'
        /// </summary>
        [JsonProperty(PropertyName = "pfsGroup")]
        public string PfsGroup { get; set; }

        /// <summary>
        /// Validate the object.
        /// </summary>
        /// <exception cref="ValidationException">
        /// Thrown if validation fails
        /// </exception>
        public virtual void Validate()
        {
            if (IpsecEncryption == null)
            {
                throw new ValidationException(ValidationRules.CannotBeNull, "IpsecEncryption");
            }
            if (IpsecIntegrity == null)
            {
                throw new ValidationException(ValidationRules.CannotBeNull, "IpsecIntegrity");
            }
            if (IkeEncryption == null)
            {
                throw new ValidationException(ValidationRules.CannotBeNull, "IkeEncryption");
            }
            if (IkeIntegrity == null)
            {
                throw new ValidationException(ValidationRules.CannotBeNull, "IkeIntegrity");
            }
            if (DhGroup == null)
            {
                throw new ValidationException(ValidationRules.CannotBeNull, "DhGroup");
            }
            if (PfsGroup == null)
            {
                throw new ValidationException(ValidationRules.CannotBeNull, "PfsGroup");
            }
        }
    }
}
