// <auto-generated>
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>

namespace Microsoft.Azure.Management.Security.Models
{
    using Newtonsoft.Json;
    using System.Linq;

    /// <summary>
    /// Application's condition
    /// </summary>
    public partial class ApplicationCondition
    {
        /// <summary>
        /// Initializes a new instance of the ApplicationCondition class.
        /// </summary>
        public ApplicationCondition()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the ApplicationCondition class.
        /// </summary>
        /// <param name="property">The application Condition's Property, e.g.
        /// ID, see examples</param>
        /// <param name="value">The application Condition's Value like IDs that
        /// contain some string, see examples</param>
        /// <param name="operatorProperty">The application Condition's
        /// Operator, for example Contains for id or In for list of possible
        /// IDs, see examples. Possible values include: 'Contains', 'Equals',
        /// 'In'</param>
        public ApplicationCondition(string property = default(string), string value = default(string), string operatorProperty = default(string))
        {
            Property = property;
            Value = value;
            OperatorProperty = operatorProperty;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets the application Condition's Property, e.g. ID, see
        /// examples
        /// </summary>
        [JsonProperty(PropertyName = "property")]
        public string Property { get; set; }

        /// <summary>
        /// Gets or sets the application Condition's Value like IDs that
        /// contain some string, see examples
        /// </summary>
        [JsonProperty(PropertyName = "value")]
        public string Value { get; set; }

        /// <summary>
        /// Gets or sets the application Condition's Operator, for example
        /// Contains for id or In for list of possible IDs, see examples.
        /// Possible values include: 'Contains', 'Equals', 'In'
        /// </summary>
        [JsonProperty(PropertyName = "operator")]
        public string OperatorProperty { get; set; }

    }
}
