// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.PowerShell.Cmdlets.ConnectedNetwork.Models.Api20210501
{
    using static Microsoft.Azure.PowerShell.Cmdlets.ConnectedNetwork.Runtime.Extensions;

    /// <summary>The network function sku overview.</summary>
    public partial class SkuOverview :
        Microsoft.Azure.PowerShell.Cmdlets.ConnectedNetwork.Models.Api20210501.ISkuOverview,
        Microsoft.Azure.PowerShell.Cmdlets.ConnectedNetwork.Models.Api20210501.ISkuOverviewInternal
    {

        /// <summary>Backing field for <see cref="SkuName" /> property.</summary>
        private string _skuName;

        /// <summary>The vendor sku name.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.ConnectedNetwork.Origin(Microsoft.Azure.PowerShell.Cmdlets.ConnectedNetwork.PropertyOrigin.Owned)]
        public string SkuName { get => this._skuName; set => this._skuName = value; }

        /// <summary>Backing field for <see cref="SkuType" /> property.</summary>
        private Microsoft.Azure.PowerShell.Cmdlets.ConnectedNetwork.Support.SkuType? _skuType;

        /// <summary>The vendor sku type.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.ConnectedNetwork.Origin(Microsoft.Azure.PowerShell.Cmdlets.ConnectedNetwork.PropertyOrigin.Owned)]
        public Microsoft.Azure.PowerShell.Cmdlets.ConnectedNetwork.Support.SkuType? SkuType { get => this._skuType; set => this._skuType = value; }

        /// <summary>Creates an new <see cref="SkuOverview" /> instance.</summary>
        public SkuOverview()
        {

        }
    }
    /// The network function sku overview.
    public partial interface ISkuOverview :
        Microsoft.Azure.PowerShell.Cmdlets.ConnectedNetwork.Runtime.IJsonSerializable
    {
        /// <summary>The vendor sku name.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.ConnectedNetwork.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The vendor sku name.",
        SerializedName = @"skuName",
        PossibleTypes = new [] { typeof(string) })]
        string SkuName { get; set; }
        /// <summary>The vendor sku type.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.ConnectedNetwork.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The vendor sku type.",
        SerializedName = @"skuType",
        PossibleTypes = new [] { typeof(Microsoft.Azure.PowerShell.Cmdlets.ConnectedNetwork.Support.SkuType) })]
        Microsoft.Azure.PowerShell.Cmdlets.ConnectedNetwork.Support.SkuType? SkuType { get; set; }

    }
    /// The network function sku overview.
    internal partial interface ISkuOverviewInternal

    {
        /// <summary>The vendor sku name.</summary>
        string SkuName { get; set; }
        /// <summary>The vendor sku type.</summary>
        Microsoft.Azure.PowerShell.Cmdlets.ConnectedNetwork.Support.SkuType? SkuType { get; set; }

    }
}