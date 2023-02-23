// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Models.Api20221001Preview
{
    using static Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Runtime.Extensions;

    /// <summary>Identity for the container group.</summary>
    public partial class ContainerGroupIdentity :
        Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Models.Api20221001Preview.IContainerGroupIdentity,
        Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Models.Api20221001Preview.IContainerGroupIdentityInternal
    {

        /// <summary>Internal Acessors for PrincipalId</summary>
        string Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Models.Api20221001Preview.IContainerGroupIdentityInternal.PrincipalId { get => this._principalId; set { {_principalId = value;} } }

        /// <summary>Internal Acessors for TenantId</summary>
        string Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Models.Api20221001Preview.IContainerGroupIdentityInternal.TenantId { get => this._tenantId; set { {_tenantId = value;} } }

        /// <summary>Backing field for <see cref="PrincipalId" /> property.</summary>
        private string _principalId;

        /// <summary>
        /// The principal id of the container group identity. This property will only be provided for a system assigned identity.
        /// </summary>
        [Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Origin(Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.PropertyOrigin.Owned)]
        public string PrincipalId { get => this._principalId; }

        /// <summary>Backing field for <see cref="TenantId" /> property.</summary>
        private string _tenantId;

        /// <summary>
        /// The tenant id associated with the container group. This property will only be provided for a system assigned identity.
        /// </summary>
        [Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Origin(Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.PropertyOrigin.Owned)]
        public string TenantId { get => this._tenantId; }

        /// <summary>Backing field for <see cref="Type" /> property.</summary>
        private Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Support.ResourceIdentityType? _type;

        /// <summary>
        /// The type of identity used for the container group. The type 'SystemAssigned, UserAssigned' includes both an implicitly
        /// created identity and a set of user assigned identities. The type 'None' will remove any identities from the container
        /// group.
        /// </summary>
        [Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Origin(Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.PropertyOrigin.Owned)]
        public Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Support.ResourceIdentityType? Type { get => this._type; set => this._type = value; }

        /// <summary>Backing field for <see cref="UserAssignedIdentity" /> property.</summary>
        private Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Models.Api20221001Preview.IContainerGroupIdentityUserAssignedIdentities _userAssignedIdentity;

        /// <summary>The list of user identities associated with the container group.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Origin(Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.PropertyOrigin.Owned)]
        public Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Models.Api20221001Preview.IContainerGroupIdentityUserAssignedIdentities UserAssignedIdentity { get => (this._userAssignedIdentity = this._userAssignedIdentity ?? new Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Models.Api20221001Preview.ContainerGroupIdentityUserAssignedIdentities()); set => this._userAssignedIdentity = value; }

        /// <summary>Creates an new <see cref="ContainerGroupIdentity" /> instance.</summary>
        public ContainerGroupIdentity()
        {

        }
    }
    /// Identity for the container group.
    public partial interface IContainerGroupIdentity :
        Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Runtime.IJsonSerializable
    {
        /// <summary>
        /// The principal id of the container group identity. This property will only be provided for a system assigned identity.
        /// </summary>
        [Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"The principal id of the container group identity. This property will only be provided for a system assigned identity.",
        SerializedName = @"principalId",
        PossibleTypes = new [] { typeof(string) })]
        string PrincipalId { get;  }
        /// <summary>
        /// The tenant id associated with the container group. This property will only be provided for a system assigned identity.
        /// </summary>
        [Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"The tenant id associated with the container group. This property will only be provided for a system assigned identity.",
        SerializedName = @"tenantId",
        PossibleTypes = new [] { typeof(string) })]
        string TenantId { get;  }
        /// <summary>
        /// The type of identity used for the container group. The type 'SystemAssigned, UserAssigned' includes both an implicitly
        /// created identity and a set of user assigned identities. The type 'None' will remove any identities from the container
        /// group.
        /// </summary>
        [Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The type of identity used for the container group. The type 'SystemAssigned, UserAssigned' includes both an implicitly created identity and a set of user assigned identities. The type 'None' will remove any identities from the container group.",
        SerializedName = @"type",
        PossibleTypes = new [] { typeof(Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Support.ResourceIdentityType) })]
        Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Support.ResourceIdentityType? Type { get; set; }
        /// <summary>The list of user identities associated with the container group.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The list of user identities associated with the container group.",
        SerializedName = @"userAssignedIdentities",
        PossibleTypes = new [] { typeof(Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Models.Api20221001Preview.IContainerGroupIdentityUserAssignedIdentities) })]
        Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Models.Api20221001Preview.IContainerGroupIdentityUserAssignedIdentities UserAssignedIdentity { get; set; }

    }
    /// Identity for the container group.
    internal partial interface IContainerGroupIdentityInternal

    {
        /// <summary>
        /// The principal id of the container group identity. This property will only be provided for a system assigned identity.
        /// </summary>
        string PrincipalId { get; set; }
        /// <summary>
        /// The tenant id associated with the container group. This property will only be provided for a system assigned identity.
        /// </summary>
        string TenantId { get; set; }
        /// <summary>
        /// The type of identity used for the container group. The type 'SystemAssigned, UserAssigned' includes both an implicitly
        /// created identity and a set of user assigned identities. The type 'None' will remove any identities from the container
        /// group.
        /// </summary>
        Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Support.ResourceIdentityType? Type { get; set; }
        /// <summary>The list of user identities associated with the container group.</summary>
        Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Models.Api20221001Preview.IContainerGroupIdentityUserAssignedIdentities UserAssignedIdentity { get; set; }

    }
}