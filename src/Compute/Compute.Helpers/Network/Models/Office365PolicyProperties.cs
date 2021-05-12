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
    /// Network Virtual Appliance Sku Properties.
    /// </summary>
    public partial class Office365PolicyProperties
    {
        /// <summary>
        /// Initializes a new instance of the Office365PolicyProperties class.
        /// </summary>
        public Office365PolicyProperties()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the Office365PolicyProperties class.
        /// </summary>
        /// <param name="breakOutCategories">Office 365 breakout
        /// categories.</param>
        public Office365PolicyProperties(BreakOutCategoryPolicies breakOutCategories = default(BreakOutCategoryPolicies))
        {
            BreakOutCategories = breakOutCategories;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets office 365 breakout categories.
        /// </summary>
        [JsonProperty(PropertyName = "breakOutCategories")]
        public BreakOutCategoryPolicies BreakOutCategories { get; set; }

    }
}
