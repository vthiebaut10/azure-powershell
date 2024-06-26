// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.PowerShell.Cmdlets.Alb.Models
{
    using static Microsoft.Azure.PowerShell.Cmdlets.Alb.Runtime.Extensions;

    /// <summary>Traffic Controller Properties.</summary>
    public partial class TrafficControllerProperties :
        Microsoft.Azure.PowerShell.Cmdlets.Alb.Models.ITrafficControllerProperties,
        Microsoft.Azure.PowerShell.Cmdlets.Alb.Models.ITrafficControllerPropertiesInternal
    {

        /// <summary>Backing field for <see cref="Association" /> property.</summary>
        private System.Collections.Generic.List<Microsoft.Azure.PowerShell.Cmdlets.Alb.Models.IResourceId> _association;

        /// <summary>Associations References List</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Alb.Origin(Microsoft.Azure.PowerShell.Cmdlets.Alb.PropertyOrigin.Owned)]
        public System.Collections.Generic.List<Microsoft.Azure.PowerShell.Cmdlets.Alb.Models.IResourceId> Association { get => this._association; }

        /// <summary>Backing field for <see cref="ConfigurationEndpoint" /> property.</summary>
        private System.Collections.Generic.List<string> _configurationEndpoint;

        /// <summary>Configuration Endpoints.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Alb.Origin(Microsoft.Azure.PowerShell.Cmdlets.Alb.PropertyOrigin.Owned)]
        public System.Collections.Generic.List<string> ConfigurationEndpoint { get => this._configurationEndpoint; }

        /// <summary>Backing field for <see cref="Frontend" /> property.</summary>
        private System.Collections.Generic.List<Microsoft.Azure.PowerShell.Cmdlets.Alb.Models.IResourceId> _frontend;

        /// <summary>Frontends References List</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Alb.Origin(Microsoft.Azure.PowerShell.Cmdlets.Alb.PropertyOrigin.Owned)]
        public System.Collections.Generic.List<Microsoft.Azure.PowerShell.Cmdlets.Alb.Models.IResourceId> Frontend { get => this._frontend; }

        /// <summary>Internal Acessors for Association</summary>
        System.Collections.Generic.List<Microsoft.Azure.PowerShell.Cmdlets.Alb.Models.IResourceId> Microsoft.Azure.PowerShell.Cmdlets.Alb.Models.ITrafficControllerPropertiesInternal.Association { get => this._association; set { {_association = value;} } }

        /// <summary>Internal Acessors for ConfigurationEndpoint</summary>
        System.Collections.Generic.List<string> Microsoft.Azure.PowerShell.Cmdlets.Alb.Models.ITrafficControllerPropertiesInternal.ConfigurationEndpoint { get => this._configurationEndpoint; set { {_configurationEndpoint = value;} } }

        /// <summary>Internal Acessors for Frontend</summary>
        System.Collections.Generic.List<Microsoft.Azure.PowerShell.Cmdlets.Alb.Models.IResourceId> Microsoft.Azure.PowerShell.Cmdlets.Alb.Models.ITrafficControllerPropertiesInternal.Frontend { get => this._frontend; set { {_frontend = value;} } }

        /// <summary>Internal Acessors for ProvisioningState</summary>
        string Microsoft.Azure.PowerShell.Cmdlets.Alb.Models.ITrafficControllerPropertiesInternal.ProvisioningState { get => this._provisioningState; set { {_provisioningState = value;} } }

        /// <summary>Backing field for <see cref="ProvisioningState" /> property.</summary>
        private string _provisioningState;

        /// <summary>The status of the last operation.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Alb.Origin(Microsoft.Azure.PowerShell.Cmdlets.Alb.PropertyOrigin.Owned)]
        public string ProvisioningState { get => this._provisioningState; }

        /// <summary>Creates an new <see cref="TrafficControllerProperties" /> instance.</summary>
        public TrafficControllerProperties()
        {

        }
    }
    /// Traffic Controller Properties.
    public partial interface ITrafficControllerProperties :
        Microsoft.Azure.PowerShell.Cmdlets.Alb.Runtime.IJsonSerializable
    {
        /// <summary>Associations References List</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Alb.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Read = true,
        Create = false,
        Update = false,
        Description = @"Associations References List",
        SerializedName = @"associations",
        PossibleTypes = new [] { typeof(Microsoft.Azure.PowerShell.Cmdlets.Alb.Models.IResourceId) })]
        System.Collections.Generic.List<Microsoft.Azure.PowerShell.Cmdlets.Alb.Models.IResourceId> Association { get;  }
        /// <summary>Configuration Endpoints.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Alb.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Read = true,
        Create = false,
        Update = false,
        Description = @"Configuration Endpoints.",
        SerializedName = @"configurationEndpoints",
        PossibleTypes = new [] { typeof(string) })]
        System.Collections.Generic.List<string> ConfigurationEndpoint { get;  }
        /// <summary>Frontends References List</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Alb.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Read = true,
        Create = false,
        Update = false,
        Description = @"Frontends References List",
        SerializedName = @"frontends",
        PossibleTypes = new [] { typeof(Microsoft.Azure.PowerShell.Cmdlets.Alb.Models.IResourceId) })]
        System.Collections.Generic.List<Microsoft.Azure.PowerShell.Cmdlets.Alb.Models.IResourceId> Frontend { get;  }
        /// <summary>The status of the last operation.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.Alb.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Read = true,
        Create = false,
        Update = false,
        Description = @"The status of the last operation.",
        SerializedName = @"provisioningState",
        PossibleTypes = new [] { typeof(string) })]
        [global::Microsoft.Azure.PowerShell.Cmdlets.Alb.PSArgumentCompleterAttribute("Provisioning", "Updating", "Deleting", "Accepted", "Succeeded", "Failed", "Canceled")]
        string ProvisioningState { get;  }

    }
    /// Traffic Controller Properties.
    internal partial interface ITrafficControllerPropertiesInternal

    {
        /// <summary>Associations References List</summary>
        System.Collections.Generic.List<Microsoft.Azure.PowerShell.Cmdlets.Alb.Models.IResourceId> Association { get; set; }
        /// <summary>Configuration Endpoints.</summary>
        System.Collections.Generic.List<string> ConfigurationEndpoint { get; set; }
        /// <summary>Frontends References List</summary>
        System.Collections.Generic.List<Microsoft.Azure.PowerShell.Cmdlets.Alb.Models.IResourceId> Frontend { get; set; }
        /// <summary>The status of the last operation.</summary>
        [global::Microsoft.Azure.PowerShell.Cmdlets.Alb.PSArgumentCompleterAttribute("Provisioning", "Updating", "Deleting", "Accepted", "Succeeded", "Failed", "Canceled")]
        string ProvisioningState { get; set; }

    }
}