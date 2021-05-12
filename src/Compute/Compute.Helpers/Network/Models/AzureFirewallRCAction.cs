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
    /// Properties of the AzureFirewallRCAction.
    /// </summary>
    public partial class AzureFirewallRCAction
    {
        /// <summary>
        /// Initializes a new instance of the AzureFirewallRCAction class.
        /// </summary>
        public AzureFirewallRCAction()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the AzureFirewallRCAction class.
        /// </summary>
        /// <param name="type">The type of action. Possible values include:
        /// 'Allow', 'Deny'</param>
        public AzureFirewallRCAction(string type = default(string))
        {
            Type = type;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets the type of action. Possible values include: 'Allow',
        /// 'Deny'
        /// </summary>
        [JsonProperty(PropertyName = "type")]
        public string Type { get; set; }

    }
}
