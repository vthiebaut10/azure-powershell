// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Models.Api20221001Preview
{
    using static Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Runtime.Extensions;

    /// <summary>IP address for the container group.</summary>
    public partial class IPAddress :
        Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Models.Api20221001Preview.IIPAddress,
        Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Models.Api20221001Preview.IIPAddressInternal
    {

        /// <summary>Backing field for <see cref="AutoGeneratedDomainNameLabelScope" /> property.</summary>
        private Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Support.DnsNameLabelReusePolicy? _autoGeneratedDomainNameLabelScope;

        /// <summary>
        /// The value representing the security enum. The 'Unsecure' value is the default value if not selected and means the object's
        /// domain name label is not secured against subdomain takeover. The 'TenantReuse' value is the default value if selected
        /// and means the object's domain name label can be reused within the same tenant. The 'SubscriptionReuse' value means the
        /// object's domain name label can be reused within the same subscription. The 'ResourceGroupReuse' value means the object's
        /// domain name label can be reused within the same resource group. The 'NoReuse' value means the object's domain name label
        /// cannot be reused within the same resource group, subscription, or tenant.
        /// </summary>
        [Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Origin(Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.PropertyOrigin.Owned)]
        public Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Support.DnsNameLabelReusePolicy? AutoGeneratedDomainNameLabelScope { get => this._autoGeneratedDomainNameLabelScope; set => this._autoGeneratedDomainNameLabelScope = value; }

        /// <summary>Backing field for <see cref="DnsNameLabel" /> property.</summary>
        private string _dnsNameLabel;

        /// <summary>The Dns name label for the IP.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Origin(Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.PropertyOrigin.Owned)]
        public string DnsNameLabel { get => this._dnsNameLabel; set => this._dnsNameLabel = value; }

        /// <summary>Backing field for <see cref="Fqdn" /> property.</summary>
        private string _fqdn;

        /// <summary>The FQDN for the IP.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Origin(Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.PropertyOrigin.Owned)]
        public string Fqdn { get => this._fqdn; }

        /// <summary>Backing field for <see cref="IP" /> property.</summary>
        private string _iP;

        /// <summary>The IP exposed to the public internet.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Origin(Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.PropertyOrigin.Owned)]
        public string IP { get => this._iP; set => this._iP = value; }

        /// <summary>Internal Acessors for Fqdn</summary>
        string Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Models.Api20221001Preview.IIPAddressInternal.Fqdn { get => this._fqdn; set { {_fqdn = value;} } }

        /// <summary>Backing field for <see cref="Port" /> property.</summary>
        private Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Models.Api20221001Preview.IPort[] _port;

        /// <summary>The list of ports exposed on the container group.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Origin(Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.PropertyOrigin.Owned)]
        public Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Models.Api20221001Preview.IPort[] Port { get => this._port; set => this._port = value; }

        /// <summary>Backing field for <see cref="Type" /> property.</summary>
        private Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Support.ContainerGroupIPAddressType _type;

        /// <summary>Specifies if the IP is exposed to the public internet or private VNET.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Origin(Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.PropertyOrigin.Owned)]
        public Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Support.ContainerGroupIPAddressType Type { get => this._type; set => this._type = value; }

        /// <summary>Creates an new <see cref="IPAddress" /> instance.</summary>
        public IPAddress()
        {

        }
    }
    /// IP address for the container group.
    public partial interface IIPAddress :
        Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Runtime.IJsonSerializable
    {
        /// <summary>
        /// The value representing the security enum. The 'Unsecure' value is the default value if not selected and means the object's
        /// domain name label is not secured against subdomain takeover. The 'TenantReuse' value is the default value if selected
        /// and means the object's domain name label can be reused within the same tenant. The 'SubscriptionReuse' value means the
        /// object's domain name label can be reused within the same subscription. The 'ResourceGroupReuse' value means the object's
        /// domain name label can be reused within the same resource group. The 'NoReuse' value means the object's domain name label
        /// cannot be reused within the same resource group, subscription, or tenant.
        /// </summary>
        [Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The value representing the security enum. The 'Unsecure' value is the default value if not selected and means the object's domain name label is not secured against subdomain takeover. The 'TenantReuse' value is the default value if selected and means the object's domain name label can be reused within the same tenant. The 'SubscriptionReuse' value means the object's domain name label can be reused within the same subscription. The 'ResourceGroupReuse' value means the object's domain name label can be reused within the same resource group. The 'NoReuse' value means the object's domain name label cannot be reused within the same resource group, subscription, or tenant.",
        SerializedName = @"autoGeneratedDomainNameLabelScope",
        PossibleTypes = new [] { typeof(Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Support.DnsNameLabelReusePolicy) })]
        Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Support.DnsNameLabelReusePolicy? AutoGeneratedDomainNameLabelScope { get; set; }
        /// <summary>The Dns name label for the IP.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The Dns name label for the IP.",
        SerializedName = @"dnsNameLabel",
        PossibleTypes = new [] { typeof(string) })]
        string DnsNameLabel { get; set; }
        /// <summary>The FQDN for the IP.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"The FQDN for the IP.",
        SerializedName = @"fqdn",
        PossibleTypes = new [] { typeof(string) })]
        string Fqdn { get;  }
        /// <summary>The IP exposed to the public internet.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The IP exposed to the public internet.",
        SerializedName = @"ip",
        PossibleTypes = new [] { typeof(string) })]
        string IP { get; set; }
        /// <summary>The list of ports exposed on the container group.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Runtime.Info(
        Required = true,
        ReadOnly = false,
        Description = @"The list of ports exposed on the container group.",
        SerializedName = @"ports",
        PossibleTypes = new [] { typeof(Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Models.Api20221001Preview.IPort) })]
        Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Models.Api20221001Preview.IPort[] Port { get; set; }
        /// <summary>Specifies if the IP is exposed to the public internet or private VNET.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Runtime.Info(
        Required = true,
        ReadOnly = false,
        Description = @"Specifies if the IP is exposed to the public internet or private VNET.",
        SerializedName = @"type",
        PossibleTypes = new [] { typeof(Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Support.ContainerGroupIPAddressType) })]
        Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Support.ContainerGroupIPAddressType Type { get; set; }

    }
    /// IP address for the container group.
    internal partial interface IIPAddressInternal

    {
        /// <summary>
        /// The value representing the security enum. The 'Unsecure' value is the default value if not selected and means the object's
        /// domain name label is not secured against subdomain takeover. The 'TenantReuse' value is the default value if selected
        /// and means the object's domain name label can be reused within the same tenant. The 'SubscriptionReuse' value means the
        /// object's domain name label can be reused within the same subscription. The 'ResourceGroupReuse' value means the object's
        /// domain name label can be reused within the same resource group. The 'NoReuse' value means the object's domain name label
        /// cannot be reused within the same resource group, subscription, or tenant.
        /// </summary>
        Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Support.DnsNameLabelReusePolicy? AutoGeneratedDomainNameLabelScope { get; set; }
        /// <summary>The Dns name label for the IP.</summary>
        string DnsNameLabel { get; set; }
        /// <summary>The FQDN for the IP.</summary>
        string Fqdn { get; set; }
        /// <summary>The IP exposed to the public internet.</summary>
        string IP { get; set; }
        /// <summary>The list of ports exposed on the container group.</summary>
        Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Models.Api20221001Preview.IPort[] Port { get; set; }
        /// <summary>Specifies if the IP is exposed to the public internet or private VNET.</summary>
        Microsoft.Azure.PowerShell.Cmdlets.ContainerInstance.Support.ContainerGroupIPAddressType Type { get; set; }

    }
}