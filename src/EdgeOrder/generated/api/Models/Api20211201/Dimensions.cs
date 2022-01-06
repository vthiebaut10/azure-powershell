// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201
{
    using static Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Runtime.Extensions;

    /// <summary>Dimensions of a configuration.</summary>
    public partial class Dimensions :
        Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IDimensions,
        Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IDimensionsInternal
    {

        /// <summary>Backing field for <see cref="Depth" /> property.</summary>
        private double? _depth;

        /// <summary>Depth of the device.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Origin(Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.PropertyOrigin.Owned)]
        public double? Depth { get => this._depth; }

        /// <summary>Backing field for <see cref="Height" /> property.</summary>
        private double? _height;

        /// <summary>Height of the device.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Origin(Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.PropertyOrigin.Owned)]
        public double? Height { get => this._height; }

        /// <summary>Backing field for <see cref="Length" /> property.</summary>
        private double? _length;

        /// <summary>Length of the device.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Origin(Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.PropertyOrigin.Owned)]
        public double? Length { get => this._length; }

        /// <summary>Backing field for <see cref="LengthHeightUnit" /> property.</summary>
        private Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Support.LengthHeightUnit? _lengthHeightUnit;

        /// <summary>Unit for the dimensions of length, height and width.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Origin(Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.PropertyOrigin.Owned)]
        public Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Support.LengthHeightUnit? LengthHeightUnit { get => this._lengthHeightUnit; }

        /// <summary>Internal Acessors for Depth</summary>
        double? Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IDimensionsInternal.Depth { get => this._depth; set { {_depth = value;} } }

        /// <summary>Internal Acessors for Height</summary>
        double? Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IDimensionsInternal.Height { get => this._height; set { {_height = value;} } }

        /// <summary>Internal Acessors for Length</summary>
        double? Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IDimensionsInternal.Length { get => this._length; set { {_length = value;} } }

        /// <summary>Internal Acessors for LengthHeightUnit</summary>
        Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Support.LengthHeightUnit? Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IDimensionsInternal.LengthHeightUnit { get => this._lengthHeightUnit; set { {_lengthHeightUnit = value;} } }

        /// <summary>Internal Acessors for Weight</summary>
        double? Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IDimensionsInternal.Weight { get => this._weight; set { {_weight = value;} } }

        /// <summary>Internal Acessors for WeightUnit</summary>
        Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Support.WeightMeasurementUnit? Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IDimensionsInternal.WeightUnit { get => this._weightUnit; set { {_weightUnit = value;} } }

        /// <summary>Internal Acessors for Width</summary>
        double? Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IDimensionsInternal.Width { get => this._width; set { {_width = value;} } }

        /// <summary>Backing field for <see cref="Weight" /> property.</summary>
        private double? _weight;

        /// <summary>Weight of the device.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Origin(Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.PropertyOrigin.Owned)]
        public double? Weight { get => this._weight; }

        /// <summary>Backing field for <see cref="WeightUnit" /> property.</summary>
        private Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Support.WeightMeasurementUnit? _weightUnit;

        /// <summary>Unit for the dimensions of weight.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Origin(Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.PropertyOrigin.Owned)]
        public Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Support.WeightMeasurementUnit? WeightUnit { get => this._weightUnit; }

        /// <summary>Backing field for <see cref="Width" /> property.</summary>
        private double? _width;

        /// <summary>Width of the device.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Origin(Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.PropertyOrigin.Owned)]
        public double? Width { get => this._width; }

        /// <summary>Creates an new <see cref="Dimensions" /> instance.</summary>
        public Dimensions()
        {

        }
    }
    /// Dimensions of a configuration.
    public partial interface IDimensions :
        Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Runtime.IJsonSerializable
    {
        /// <summary>Depth of the device.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"Depth of the device.",
        SerializedName = @"depth",
        PossibleTypes = new [] { typeof(double) })]
        double? Depth { get;  }
        /// <summary>Height of the device.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"Height of the device.",
        SerializedName = @"height",
        PossibleTypes = new [] { typeof(double) })]
        double? Height { get;  }
        /// <summary>Length of the device.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"Length of the device.",
        SerializedName = @"length",
        PossibleTypes = new [] { typeof(double) })]
        double? Length { get;  }
        /// <summary>Unit for the dimensions of length, height and width.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"Unit for the dimensions of length, height and width.",
        SerializedName = @"lengthHeightUnit",
        PossibleTypes = new [] { typeof(Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Support.LengthHeightUnit) })]
        Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Support.LengthHeightUnit? LengthHeightUnit { get;  }
        /// <summary>Weight of the device.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"Weight of the device.",
        SerializedName = @"weight",
        PossibleTypes = new [] { typeof(double) })]
        double? Weight { get;  }
        /// <summary>Unit for the dimensions of weight.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"Unit for the dimensions of weight.",
        SerializedName = @"weightUnit",
        PossibleTypes = new [] { typeof(Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Support.WeightMeasurementUnit) })]
        Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Support.WeightMeasurementUnit? WeightUnit { get;  }
        /// <summary>Width of the device.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"Width of the device.",
        SerializedName = @"width",
        PossibleTypes = new [] { typeof(double) })]
        double? Width { get;  }

    }
    /// Dimensions of a configuration.
    internal partial interface IDimensionsInternal

    {
        /// <summary>Depth of the device.</summary>
        double? Depth { get; set; }
        /// <summary>Height of the device.</summary>
        double? Height { get; set; }
        /// <summary>Length of the device.</summary>
        double? Length { get; set; }
        /// <summary>Unit for the dimensions of length, height and width.</summary>
        Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Support.LengthHeightUnit? LengthHeightUnit { get; set; }
        /// <summary>Weight of the device.</summary>
        double? Weight { get; set; }
        /// <summary>Unit for the dimensions of weight.</summary>
        Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Support.WeightMeasurementUnit? WeightUnit { get; set; }
        /// <summary>Width of the device.</summary>
        double? Width { get; set; }

    }
}