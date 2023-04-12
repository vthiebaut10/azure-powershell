// <auto-generated>
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>

namespace Microsoft.Azure.PowerShell.Ssh.Helpers.HybridConnectivity.Models
{
    using Microsoft.Rest;
    using Microsoft.Rest.Serialization;
    using Newtonsoft.Json;
    using System.Linq;

    /// <summary>
    /// The endpoint access for the target resource.
    /// </summary>
    [Rest.Serialization.JsonTransformation]
    public partial class EndpointAccessResource
    {
        /// <summary>
        /// Initializes a new instance of the EndpointAccessResource class.
        /// </summary>
        public EndpointAccessResource()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the EndpointAccessResource class.
        /// </summary>
        /// <param name="namespaceName">The namespace name.</param>
        /// <param name="namespaceNameSuffix">The suffix domain name of relay
        /// namespace.</param>
        /// <param name="hybridConnectionName">Azure Relay hybrid connection
        /// name for the resource.</param>
        /// <param name="accessKey">Access key for hybrid connection.</param>
        /// <param name="expiresOn">The expiration of access key in unix
        /// time.</param>
        /// <param name="serviceConfigurationToken">The token to access the
        /// enabled service.</param>
        public EndpointAccessResource(string namespaceName, string namespaceNameSuffix, string hybridConnectionName, string accessKey = default(string), long? expiresOn = default(long?), string serviceConfigurationToken = default(string))
        {
            NamespaceName = namespaceName;
            NamespaceNameSuffix = namespaceNameSuffix;
            HybridConnectionName = hybridConnectionName;
            AccessKey = accessKey;
            ExpiresOn = expiresOn;
            ServiceConfigurationToken = serviceConfigurationToken;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets the namespace name.
        /// </summary>
        [JsonProperty(PropertyName = "relay.namespaceName")]
        public string NamespaceName { get; set; }

        /// <summary>
        /// Gets or sets the suffix domain name of relay namespace.
        /// </summary>
        [JsonProperty(PropertyName = "relay.namespaceNameSuffix")]
        public string NamespaceNameSuffix { get; set; }

        /// <summary>
        /// Gets or sets azure Relay hybrid connection name for the resource.
        /// </summary>
        [JsonProperty(PropertyName = "relay.hybridConnectionName")]
        public string HybridConnectionName { get; set; }

        /// <summary>
        /// Gets access key for hybrid connection.
        /// </summary>
        [JsonProperty(PropertyName = "relay.accessKey")]
        public string AccessKey { get; private set; }

        /// <summary>
        /// Gets or sets the expiration of access key in unix time.
        /// </summary>
        [JsonProperty(PropertyName = "relay.expiresOn")]
        public long? ExpiresOn { get; set; }

        /// <summary>
        /// Gets or sets the token to access the enabled service.
        /// </summary>
        [JsonProperty(PropertyName = "relay.serviceConfigurationToken")]
        public string ServiceConfigurationToken { get; set; }

        /// <summary>
        /// Validate the object.
        /// </summary>
        /// <exception cref="ValidationException">
        /// Thrown if validation fails
        /// </exception>
        public virtual void Validate()
        {
            if (NamespaceName == null)
            {
                throw new ValidationException(ValidationRules.CannotBeNull, "NamespaceName");
            }
            if (NamespaceNameSuffix == null)
            {
                throw new ValidationException(ValidationRules.CannotBeNull, "NamespaceNameSuffix");
            }
            if (HybridConnectionName == null)
            {
                throw new ValidationException(ValidationRules.CannotBeNull, "HybridConnectionName");
            }
            if (NamespaceName != null)
            {
                if (NamespaceName.Length > 200)
                {
                    throw new ValidationException(ValidationRules.MaxLength, "NamespaceName", 200);
                }
                if (NamespaceName.Length < 1)
                {
                    throw new ValidationException(ValidationRules.MinLength, "NamespaceName", 1);
                }
            }
            if (NamespaceNameSuffix != null)
            {
                if (NamespaceNameSuffix.Length > 100)
                {
                    throw new ValidationException(ValidationRules.MaxLength, "NamespaceNameSuffix", 100);
                }
                if (NamespaceNameSuffix.Length < 1)
                {
                    throw new ValidationException(ValidationRules.MinLength, "NamespaceNameSuffix", 1);
                }
            }
        }
    }
}
