// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.PowerShell.Cmdlets.ConnectedMachine.Support
{

    /// <summary>The status of the hybrid machine agent.</summary>
    public partial struct StatusTypes :
        System.IEquatable<StatusTypes>
    {
        public static Microsoft.Azure.PowerShell.Cmdlets.ConnectedMachine.Support.StatusTypes Connected = @"Connected";

        public static Microsoft.Azure.PowerShell.Cmdlets.ConnectedMachine.Support.StatusTypes Disconnected = @"Disconnected";

        public static Microsoft.Azure.PowerShell.Cmdlets.ConnectedMachine.Support.StatusTypes Error = @"Error";

        /// <summary>the value for an instance of the <see cref="StatusTypes" /> Enum.</summary>
        private string _value { get; set; }

        /// <summary>Conversion from arbitrary object to StatusTypes</summary>
        /// <param name="value">the value to convert to an instance of <see cref="StatusTypes" />.</param>
        internal static object CreateFrom(object value)
        {
            return new StatusTypes(global::System.Convert.ToString(value));
        }

        /// <summary>Compares values of enum type StatusTypes</summary>
        /// <param name="e">the value to compare against this instance.</param>
        /// <returns><c>true</c> if the two instances are equal to the same value</returns>
        public bool Equals(Microsoft.Azure.PowerShell.Cmdlets.ConnectedMachine.Support.StatusTypes e)
        {
            return _value.Equals(e._value);
        }

        /// <summary>Compares values of enum type StatusTypes (override for Object)</summary>
        /// <param name="obj">the value to compare against this instance.</param>
        /// <returns><c>true</c> if the two instances are equal to the same value</returns>
        public override bool Equals(object obj)
        {
            return obj is StatusTypes && Equals((StatusTypes)obj);
        }

        /// <summary>Returns hashCode for enum StatusTypes</summary>
        /// <returns>The hashCode of the value</returns>
        public override int GetHashCode()
        {
            return this._value.GetHashCode();
        }

        /// <summary>Creates an instance of the <see cref="StatusTypes" Enum class./></summary>
        /// <param name="underlyingValue">the value to create an instance for.</param>
        private StatusTypes(string underlyingValue)
        {
            this._value = underlyingValue;
        }

        /// <summary>Returns string representation for StatusTypes</summary>
        /// <returns>A string for this value.</returns>
        public override string ToString()
        {
            return this._value;
        }

        /// <summary>Implicit operator to convert string to StatusTypes</summary>
        /// <param name="value">the value to convert to an instance of <see cref="StatusTypes" />.</param>

        public static implicit operator StatusTypes(string value)
        {
            return new StatusTypes(value);
        }

        /// <summary>Implicit operator to convert StatusTypes to string</summary>
        /// <param name="e">the value to convert to an instance of <see cref="StatusTypes" />.</param>

        public static implicit operator string(Microsoft.Azure.PowerShell.Cmdlets.ConnectedMachine.Support.StatusTypes e)
        {
            return e._value;
        }

        /// <summary>Overriding != operator for enum StatusTypes</summary>
        /// <param name="e1">the value to compare against <see cref="e2" /></param>
        /// <param name="e2">the value to compare against <see cref="e1" /></param>
        /// <returns><c>true</c> if the two instances are not equal to the same value</returns>
        public static bool operator !=(Microsoft.Azure.PowerShell.Cmdlets.ConnectedMachine.Support.StatusTypes e1, Microsoft.Azure.PowerShell.Cmdlets.ConnectedMachine.Support.StatusTypes e2)
        {
            return !e2.Equals(e1);
        }

        /// <summary>Overriding == operator for enum StatusTypes</summary>
        /// <param name="e1">the value to compare against <see cref="e2" /></param>
        /// <param name="e2">the value to compare against <see cref="e1" /></param>
        /// <returns><c>true</c> if the two instances are equal to the same value</returns>
        public static bool operator ==(Microsoft.Azure.PowerShell.Cmdlets.ConnectedMachine.Support.StatusTypes e1, Microsoft.Azure.PowerShell.Cmdlets.ConnectedMachine.Support.StatusTypes e2)
        {
            return e2.Equals(e1);
        }
    }
}