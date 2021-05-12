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
    /// Log Analytics Resources for Firewall Policy Insights.
    /// </summary>
    public partial class FirewallPolicyLogAnalyticsResources
    {
        /// <summary>
        /// Initializes a new instance of the
        /// FirewallPolicyLogAnalyticsResources class.
        /// </summary>
        public FirewallPolicyLogAnalyticsResources()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the
        /// FirewallPolicyLogAnalyticsResources class.
        /// </summary>
        /// <param name="workspaces">List of workspaces for Firewall Policy
        /// Insights.</param>
        /// <param name="defaultWorkspaceId">The default workspace Id for
        /// Firewall Policy Insights.</param>
        public FirewallPolicyLogAnalyticsResources(IList<FirewallPolicyLogAnalyticsWorkspace> workspaces = default(IList<FirewallPolicyLogAnalyticsWorkspace>), SubResource defaultWorkspaceId = default(SubResource))
        {
            Workspaces = workspaces;
            DefaultWorkspaceId = defaultWorkspaceId;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets list of workspaces for Firewall Policy Insights.
        /// </summary>
        [JsonProperty(PropertyName = "workspaces")]
        public IList<FirewallPolicyLogAnalyticsWorkspace> Workspaces { get; set; }

        /// <summary>
        /// Gets or sets the default workspace Id for Firewall Policy Insights.
        /// </summary>
        [JsonProperty(PropertyName = "defaultWorkspaceId")]
        public SubResource DefaultWorkspaceId { get; set; }

    }
}
