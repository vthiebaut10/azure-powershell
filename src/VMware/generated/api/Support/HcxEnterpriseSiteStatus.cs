// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.PowerShell.Cmdlets.VMware.Support
{

    /// <summary>The status of the HCX Enterprise Site</summary>
    public partial struct HcxEnterpriseSiteStatus :
        System.IEquatable<HcxEnterpriseSiteStatus>
    {
        public static Microsoft.Azure.PowerShell.Cmdlets.VMware.Support.HcxEnterpriseSiteStatus Available = @"Available";

        public static Microsoft.Azure.PowerShell.Cmdlets.VMware.Support.HcxEnterpriseSiteStatus Consumed = @"Consumed";

        public static Microsoft.Azure.PowerShell.Cmdlets.VMware.Support.HcxEnterpriseSiteStatus Deactivated = @"Deactivated";

        public static Microsoft.Azure.PowerShell.Cmdlets.VMware.Support.HcxEnterpriseSiteStatus Deleted = @"Deleted";

        /// <summary>the value for an instance of the <see cref="HcxEnterpriseSiteStatus" /> Enum.</summary>
        private string _value { get; set; }

        /// <summary>Conversion from arbitrary object to HcxEnterpriseSiteStatus</summary>
        /// <param name="value">the value to convert to an instance of <see cref="HcxEnterpriseSiteStatus" />.</param>
        internal static object CreateFrom(object value)
        {
            return new HcxEnterpriseSiteStatus(global::System.Convert.ToString(value));
        }

        /// <summary>Compares values of enum type HcxEnterpriseSiteStatus</summary>
        /// <param name="e">the value to compare against this instance.</param>
        /// <returns><c>true</c> if the two instances are equal to the same value</returns>
        public bool Equals(Microsoft.Azure.PowerShell.Cmdlets.VMware.Support.HcxEnterpriseSiteStatus e)
        {
            return _value.Equals(e._value);
        }

        /// <summary>Compares values of enum type HcxEnterpriseSiteStatus (override for Object)</summary>
        /// <param name="obj">the value to compare against this instance.</param>
        /// <returns><c>true</c> if the two instances are equal to the same value</returns>
        public override bool Equals(object obj)
        {
            return obj is HcxEnterpriseSiteStatus && Equals((HcxEnterpriseSiteStatus)obj);
        }

        /// <summary>Returns hashCode for enum HcxEnterpriseSiteStatus</summary>
        /// <returns>The hashCode of the value</returns>
        public override int GetHashCode()
        {
            return this._value.GetHashCode();
        }

        /// <summary>Creates an instance of the <see cref="HcxEnterpriseSiteStatus"/> Enum class.</summary>
        /// <param name="underlyingValue">the value to create an instance for.</param>
        private HcxEnterpriseSiteStatus(string underlyingValue)
        {
            this._value = underlyingValue;
        }

        /// <summary>Returns string representation for HcxEnterpriseSiteStatus</summary>
        /// <returns>A string for this value.</returns>
        public override string ToString()
        {
            return this._value;
        }

        /// <summary>Implicit operator to convert string to HcxEnterpriseSiteStatus</summary>
        /// <param name="value">the value to convert to an instance of <see cref="HcxEnterpriseSiteStatus" />.</param>

        public static implicit operator HcxEnterpriseSiteStatus(string value)
        {
            return new HcxEnterpriseSiteStatus(value);
        }

        /// <summary>Implicit operator to convert HcxEnterpriseSiteStatus to string</summary>
        /// <param name="e">the value to convert to an instance of <see cref="HcxEnterpriseSiteStatus" />.</param>

        public static implicit operator string(Microsoft.Azure.PowerShell.Cmdlets.VMware.Support.HcxEnterpriseSiteStatus e)
        {
            return e._value;
        }

        /// <summary>Overriding != operator for enum HcxEnterpriseSiteStatus</summary>
        /// <param name="e1">the value to compare against <paramref name="e2" /></param>
        /// <param name="e2">the value to compare against <paramref name="e1" /></param>
        /// <returns><c>true</c> if the two instances are not equal to the same value</returns>
        public static bool operator !=(Microsoft.Azure.PowerShell.Cmdlets.VMware.Support.HcxEnterpriseSiteStatus e1, Microsoft.Azure.PowerShell.Cmdlets.VMware.Support.HcxEnterpriseSiteStatus e2)
        {
            return !e2.Equals(e1);
        }

        /// <summary>Overriding == operator for enum HcxEnterpriseSiteStatus</summary>
        /// <param name="e1">the value to compare against <paramref name="e2" /></param>
        /// <param name="e2">the value to compare against <paramref name="e1" /></param>
        /// <returns><c>true</c> if the two instances are equal to the same value</returns>
        public static bool operator ==(Microsoft.Azure.PowerShell.Cmdlets.VMware.Support.HcxEnterpriseSiteStatus e1, Microsoft.Azure.PowerShell.Cmdlets.VMware.Support.HcxEnterpriseSiteStatus e2)
        {
            return e2.Equals(e1);
        }
    }
}