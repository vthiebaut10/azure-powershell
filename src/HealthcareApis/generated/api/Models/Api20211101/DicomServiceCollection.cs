// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Models.Api20211101
{
    using static Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Runtime.Extensions;

    /// <summary>The collection of Dicom Services.</summary>
    public partial class DicomServiceCollection :
        Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Models.Api20211101.IDicomServiceCollection,
        Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Models.Api20211101.IDicomServiceCollectionInternal
    {

        /// <summary>Backing field for <see cref="NextLink" /> property.</summary>
        private string _nextLink;

        /// <summary>The link used to get the next page of Dicom Services.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Origin(Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.PropertyOrigin.Owned)]
        public string NextLink { get => this._nextLink; set => this._nextLink = value; }

        /// <summary>Backing field for <see cref="Value" /> property.</summary>
        private Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Models.Api20211101.IDicomService[] _value;

        /// <summary>The list of Dicom Services.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Origin(Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.PropertyOrigin.Owned)]
        public Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Models.Api20211101.IDicomService[] Value { get => this._value; set => this._value = value; }

        /// <summary>Creates an new <see cref="DicomServiceCollection" /> instance.</summary>
        public DicomServiceCollection()
        {

        }
    }
    /// The collection of Dicom Services.
    public partial interface IDicomServiceCollection :
        Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Runtime.IJsonSerializable
    {
        /// <summary>The link used to get the next page of Dicom Services.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The link used to get the next page of Dicom Services.",
        SerializedName = @"nextLink",
        PossibleTypes = new [] { typeof(string) })]
        string NextLink { get; set; }
        /// <summary>The list of Dicom Services.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The list of Dicom Services.",
        SerializedName = @"value",
        PossibleTypes = new [] { typeof(Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Models.Api20211101.IDicomService) })]
        Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Models.Api20211101.IDicomService[] Value { get; set; }

    }
    /// The collection of Dicom Services.
    internal partial interface IDicomServiceCollectionInternal

    {
        /// <summary>The link used to get the next page of Dicom Services.</summary>
        string NextLink { get; set; }
        /// <summary>The list of Dicom Services.</summary>
        Microsoft.Azure.PowerShell.Cmdlets.HealthcareApis.Models.Api20211101.IDicomService[] Value { get; set; }

    }
}