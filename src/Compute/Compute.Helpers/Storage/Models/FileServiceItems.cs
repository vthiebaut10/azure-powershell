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
    using Newtonsoft.Json;
    using System.Collections;
    using System.Collections.Generic;
    using System.Linq;

    public partial class FileServiceItems
    {
        /// <summary>
        /// Initializes a new instance of the FileServiceItems class.
        /// </summary>
        public FileServiceItems()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the FileServiceItems class.
        /// </summary>
        /// <param name="value">List of file services returned.</param>
        public FileServiceItems(IList<FileServiceProperties> value = default(IList<FileServiceProperties>))
        {
            Value = value;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets list of file services returned.
        /// </summary>
        [JsonProperty(PropertyName = "value")]
        public IList<FileServiceProperties> Value { get; private set; }

    }
}
