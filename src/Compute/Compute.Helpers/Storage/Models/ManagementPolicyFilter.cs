// <auto-generated>
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>

namespace Microsoft.Azure.Commands.Compute.Helpers.Storage.Models
{
    using Microsoft.Rest;
    using Newtonsoft.Json;
    using System.Collections;
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>
    /// Filters limit rule actions to a subset of blobs within the storage
    /// account. If multiple filters are defined, a logical AND is performed on
    /// all filters.
    /// </summary>
    public partial class ManagementPolicyFilter
    {
        /// <summary>
        /// Initializes a new instance of the ManagementPolicyFilter class.
        /// </summary>
        public ManagementPolicyFilter()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the ManagementPolicyFilter class.
        /// </summary>
        /// <param name="blobTypes">An array of predefined enum values.
        /// Currently blockBlob supports all tiering and delete actions. Only
        /// delete actions are supported for appendBlob.</param>
        /// <param name="prefixMatch">An array of strings for prefixes to be
        /// match.</param>
        /// <param name="blobIndexMatch">An array of blob index tag based
        /// filters, there can be at most 10 tag filters</param>
        public ManagementPolicyFilter(IList<string> blobTypes, IList<string> prefixMatch = default(IList<string>), IList<TagFilter> blobIndexMatch = default(IList<TagFilter>))
        {
            PrefixMatch = prefixMatch;
            BlobTypes = blobTypes;
            BlobIndexMatch = blobIndexMatch;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets an array of strings for prefixes to be match.
        /// </summary>
        [JsonProperty(PropertyName = "prefixMatch")]
        public IList<string> PrefixMatch { get; set; }

        /// <summary>
        /// Gets or sets an array of predefined enum values. Currently
        /// blockBlob supports all tiering and delete actions. Only delete
        /// actions are supported for appendBlob.
        /// </summary>
        [JsonProperty(PropertyName = "blobTypes")]
        public IList<string> BlobTypes { get; set; }

        /// <summary>
        /// Gets or sets an array of blob index tag based filters, there can be
        /// at most 10 tag filters
        /// </summary>
        [JsonProperty(PropertyName = "blobIndexMatch")]
        public IList<TagFilter> BlobIndexMatch { get; set; }

        /// <summary>
        /// Validate the object.
        /// </summary>
        /// <exception cref="ValidationException">
        /// Thrown if validation fails
        /// </exception>
        public virtual void Validate()
        {
            if (BlobTypes == null)
            {
                throw new ValidationException(ValidationRules.CannotBeNull, "BlobTypes");
            }
            if (BlobIndexMatch != null)
            {
                foreach (var element in BlobIndexMatch)
                {
                    if (element != null)
                    {
                        element.Validate();
                    }
                }
            }
        }
    }
}
