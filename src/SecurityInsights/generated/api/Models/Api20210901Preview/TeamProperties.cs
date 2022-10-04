// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview
{
    using static Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Extensions;

    /// <summary>Describes team properties</summary>
    public partial class TeamProperties :
        Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.ITeamProperties,
        Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.ITeamPropertiesInternal
    {

        /// <summary>Backing field for <see cref="GroupId" /> property.</summary>
        private string[] _groupId;

        /// <summary>List of group IDs to add their members to the team</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Origin(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.PropertyOrigin.Owned)]
        public string[] GroupId { get => this._groupId; set => this._groupId = value; }

        /// <summary>Backing field for <see cref="MemberId" /> property.</summary>
        private string[] _memberId;

        /// <summary>List of member IDs to add to the team</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Origin(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.PropertyOrigin.Owned)]
        public string[] MemberId { get => this._memberId; set => this._memberId = value; }

        /// <summary>Backing field for <see cref="TeamDescription" /> property.</summary>
        private string _teamDescription;

        /// <summary>The description of the team</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Origin(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.PropertyOrigin.Owned)]
        public string TeamDescription { get => this._teamDescription; set => this._teamDescription = value; }

        /// <summary>Backing field for <see cref="TeamName" /> property.</summary>
        private string _teamName;

        /// <summary>The name of the team</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Origin(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.PropertyOrigin.Owned)]
        public string TeamName { get => this._teamName; set => this._teamName = value; }

        /// <summary>Creates an new <see cref="TeamProperties" /> instance.</summary>
        public TeamProperties()
        {

        }
    }
    /// Describes team properties
    public partial interface ITeamProperties :
        Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.IJsonSerializable
    {
        /// <summary>List of group IDs to add their members to the team</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"List of group IDs to add their members to the team",
        SerializedName = @"groupIds",
        PossibleTypes = new [] { typeof(string) })]
        string[] GroupId { get; set; }
        /// <summary>List of member IDs to add to the team</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"List of member IDs to add to the team",
        SerializedName = @"memberIds",
        PossibleTypes = new [] { typeof(string) })]
        string[] MemberId { get; set; }
        /// <summary>The description of the team</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The description of the team",
        SerializedName = @"teamDescription",
        PossibleTypes = new [] { typeof(string) })]
        string TeamDescription { get; set; }
        /// <summary>The name of the team</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Info(
        Required = true,
        ReadOnly = false,
        Description = @"The name of the team",
        SerializedName = @"teamName",
        PossibleTypes = new [] { typeof(string) })]
        string TeamName { get; set; }

    }
    /// Describes team properties
    internal partial interface ITeamPropertiesInternal

    {
        /// <summary>List of group IDs to add their members to the team</summary>
        string[] GroupId { get; set; }
        /// <summary>List of member IDs to add to the team</summary>
        string[] MemberId { get; set; }
        /// <summary>The description of the team</summary>
        string TeamDescription { get; set; }
        /// <summary>The name of the team</summary>
        string TeamName { get; set; }

    }
}