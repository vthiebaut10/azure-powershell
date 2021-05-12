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
    using System.Collections;
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>
    /// The auto-approval list of the private link service.
    /// </summary>
    public partial class PrivateLinkServicePropertiesAutoApproval : ResourceSet
    {
        /// <summary>
        /// Initializes a new instance of the
        /// PrivateLinkServicePropertiesAutoApproval class.
        /// </summary>
        public PrivateLinkServicePropertiesAutoApproval()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the
        /// PrivateLinkServicePropertiesAutoApproval class.
        /// </summary>
        /// <param name="subscriptions">The list of subscriptions.</param>
        public PrivateLinkServicePropertiesAutoApproval(IList<string> subscriptions = default(IList<string>))
            : base(subscriptions)
        {
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

    }
}
