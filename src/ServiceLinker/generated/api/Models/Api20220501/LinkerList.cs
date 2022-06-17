// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20220501
{
    using static Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Runtime.Extensions;

    /// <summary>The list of Linker.</summary>
    public partial class LinkerList :
        Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20220501.ILinkerList,
        Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20220501.ILinkerListInternal
    {

        /// <summary>Backing field for <see cref="NextLink" /> property.</summary>
        private string _nextLink;

        /// <summary>The link used to get the next page of Linker list.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Origin(Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.PropertyOrigin.Owned)]
        public string NextLink { get => this._nextLink; set => this._nextLink = value; }

        /// <summary>Backing field for <see cref="Value" /> property.</summary>
        private Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20220501.ILinkerResource[] _value;

        /// <summary>The list of Linkers.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Origin(Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.PropertyOrigin.Owned)]
        public Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20220501.ILinkerResource[] Value { get => this._value; set => this._value = value; }

        /// <summary>Creates an new <see cref="LinkerList" /> instance.</summary>
        public LinkerList()
        {

        }
    }
    /// The list of Linker.
    public partial interface ILinkerList :
        Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Runtime.IJsonSerializable
    {
        /// <summary>The link used to get the next page of Linker list.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The link used to get the next page of Linker list.",
        SerializedName = @"nextLink",
        PossibleTypes = new [] { typeof(string) })]
        string NextLink { get; set; }
        /// <summary>The list of Linkers.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The list of Linkers.",
        SerializedName = @"value",
        PossibleTypes = new [] { typeof(Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20220501.ILinkerResource) })]
        Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20220501.ILinkerResource[] Value { get; set; }

    }
    /// The list of Linker.
    internal partial interface ILinkerListInternal

    {
        /// <summary>The link used to get the next page of Linker list.</summary>
        string NextLink { get; set; }
        /// <summary>The list of Linkers.</summary>
        Microsoft.Azure.PowerShell.Cmdlets.ServiceLinker.Models.Api20220501.ILinkerResource[] Value { get; set; }

    }
}