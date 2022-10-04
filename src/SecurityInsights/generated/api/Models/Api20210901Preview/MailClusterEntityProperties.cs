// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview
{
    using static Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Extensions;

    /// <summary>Mail cluster entity property bag.</summary>
    public partial class MailClusterEntityProperties :
        Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMailClusterEntityProperties,
        Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMailClusterEntityPropertiesInternal,
        Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.IValidates
    {
        /// <summary>
        /// Backing field for Inherited model <see cref= "Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IEntityCommonProperties"
        /// />
        /// </summary>
        private Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IEntityCommonProperties __entityCommonProperties = new Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.EntityCommonProperties();

        /// <summary>
        /// A bag of custom fields that should be part of the entity and will be presented to the user.
        /// </summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Origin(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.PropertyOrigin.Inherited)]
        public Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IEntityCommonPropertiesAdditionalData AdditionalData { get => ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IEntityCommonPropertiesInternal)__entityCommonProperties).AdditionalData; }

        /// <summary>Backing field for <see cref="ClusterGroup" /> property.</summary>
        private string _clusterGroup;

        /// <summary>The cluster group</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Origin(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.PropertyOrigin.Owned)]
        public string ClusterGroup { get => this._clusterGroup; }

        /// <summary>Backing field for <see cref="ClusterQueryEndTime" /> property.</summary>
        private global::System.DateTime? _clusterQueryEndTime;

        /// <summary>The cluster query end time</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Origin(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.PropertyOrigin.Owned)]
        public global::System.DateTime? ClusterQueryEndTime { get => this._clusterQueryEndTime; }

        /// <summary>Backing field for <see cref="ClusterQueryStartTime" /> property.</summary>
        private global::System.DateTime? _clusterQueryStartTime;

        /// <summary>The cluster query start time</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Origin(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.PropertyOrigin.Owned)]
        public global::System.DateTime? ClusterQueryStartTime { get => this._clusterQueryStartTime; }

        /// <summary>Backing field for <see cref="ClusterSourceIdentifier" /> property.</summary>
        private string _clusterSourceIdentifier;

        /// <summary>The id of the cluster source</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Origin(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.PropertyOrigin.Owned)]
        public string ClusterSourceIdentifier { get => this._clusterSourceIdentifier; }

        /// <summary>Backing field for <see cref="ClusterSourceType" /> property.</summary>
        private string _clusterSourceType;

        /// <summary>The type of the cluster source</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Origin(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.PropertyOrigin.Owned)]
        public string ClusterSourceType { get => this._clusterSourceType; }

        /// <summary>Backing field for <see cref="CountByDeliveryStatus" /> property.</summary>
        private Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.IAny _countByDeliveryStatus;

        /// <summary>Count of mail messages by DeliveryStatus string representation</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Origin(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.PropertyOrigin.Owned)]
        public Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.IAny CountByDeliveryStatus { get => (this._countByDeliveryStatus = this._countByDeliveryStatus ?? new Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Any()); }

        /// <summary>Backing field for <see cref="CountByProtectionStatus" /> property.</summary>
        private Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.IAny _countByProtectionStatus;

        /// <summary>Count of mail messages by ProtectionStatus string representation</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Origin(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.PropertyOrigin.Owned)]
        public Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.IAny CountByProtectionStatus { get => (this._countByProtectionStatus = this._countByProtectionStatus ?? new Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Any()); }

        /// <summary>Backing field for <see cref="CountByThreatType" /> property.</summary>
        private Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.IAny _countByThreatType;

        /// <summary>Count of mail messages by ThreatType string representation</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Origin(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.PropertyOrigin.Owned)]
        public Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.IAny CountByThreatType { get => (this._countByThreatType = this._countByThreatType ?? new Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Any()); }

        /// <summary>
        /// The graph item display name which is a short humanly readable description of the graph item instance. This property is
        /// optional and might be system generated.
        /// </summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Origin(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.PropertyOrigin.Inherited)]
        public string FriendlyName { get => ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IEntityCommonPropertiesInternal)__entityCommonProperties).FriendlyName; }

        /// <summary>Backing field for <see cref="IsVolumeAnomaly" /> property.</summary>
        private bool? _isVolumeAnomaly;

        /// <summary>Is this a volume anomaly mail cluster</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Origin(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.PropertyOrigin.Owned)]
        public bool? IsVolumeAnomaly { get => this._isVolumeAnomaly; }

        /// <summary>Backing field for <see cref="MailCount" /> property.</summary>
        private int? _mailCount;

        /// <summary>The number of mail messages that are part of the mail cluster</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Origin(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.PropertyOrigin.Owned)]
        public int? MailCount { get => this._mailCount; }

        /// <summary>Internal Acessors for AdditionalData</summary>
        Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IEntityCommonPropertiesAdditionalData Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IEntityCommonPropertiesInternal.AdditionalData { get => ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IEntityCommonPropertiesInternal)__entityCommonProperties).AdditionalData; set => ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IEntityCommonPropertiesInternal)__entityCommonProperties).AdditionalData = value; }

        /// <summary>Internal Acessors for FriendlyName</summary>
        string Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IEntityCommonPropertiesInternal.FriendlyName { get => ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IEntityCommonPropertiesInternal)__entityCommonProperties).FriendlyName; set => ((Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IEntityCommonPropertiesInternal)__entityCommonProperties).FriendlyName = value; }

        /// <summary>Internal Acessors for ClusterGroup</summary>
        string Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMailClusterEntityPropertiesInternal.ClusterGroup { get => this._clusterGroup; set { {_clusterGroup = value;} } }

        /// <summary>Internal Acessors for ClusterQueryEndTime</summary>
        global::System.DateTime? Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMailClusterEntityPropertiesInternal.ClusterQueryEndTime { get => this._clusterQueryEndTime; set { {_clusterQueryEndTime = value;} } }

        /// <summary>Internal Acessors for ClusterQueryStartTime</summary>
        global::System.DateTime? Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMailClusterEntityPropertiesInternal.ClusterQueryStartTime { get => this._clusterQueryStartTime; set { {_clusterQueryStartTime = value;} } }

        /// <summary>Internal Acessors for ClusterSourceIdentifier</summary>
        string Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMailClusterEntityPropertiesInternal.ClusterSourceIdentifier { get => this._clusterSourceIdentifier; set { {_clusterSourceIdentifier = value;} } }

        /// <summary>Internal Acessors for ClusterSourceType</summary>
        string Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMailClusterEntityPropertiesInternal.ClusterSourceType { get => this._clusterSourceType; set { {_clusterSourceType = value;} } }

        /// <summary>Internal Acessors for CountByDeliveryStatus</summary>
        Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.IAny Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMailClusterEntityPropertiesInternal.CountByDeliveryStatus { get => (this._countByDeliveryStatus = this._countByDeliveryStatus ?? new Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Any()); set { {_countByDeliveryStatus = value;} } }

        /// <summary>Internal Acessors for CountByProtectionStatus</summary>
        Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.IAny Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMailClusterEntityPropertiesInternal.CountByProtectionStatus { get => (this._countByProtectionStatus = this._countByProtectionStatus ?? new Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Any()); set { {_countByProtectionStatus = value;} } }

        /// <summary>Internal Acessors for CountByThreatType</summary>
        Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.IAny Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMailClusterEntityPropertiesInternal.CountByThreatType { get => (this._countByThreatType = this._countByThreatType ?? new Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Any()); set { {_countByThreatType = value;} } }

        /// <summary>Internal Acessors for IsVolumeAnomaly</summary>
        bool? Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMailClusterEntityPropertiesInternal.IsVolumeAnomaly { get => this._isVolumeAnomaly; set { {_isVolumeAnomaly = value;} } }

        /// <summary>Internal Acessors for MailCount</summary>
        int? Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMailClusterEntityPropertiesInternal.MailCount { get => this._mailCount; set { {_mailCount = value;} } }

        /// <summary>Internal Acessors for NetworkMessageId</summary>
        string[] Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMailClusterEntityPropertiesInternal.NetworkMessageId { get => this._networkMessageId; set { {_networkMessageId = value;} } }

        /// <summary>Internal Acessors for Query</summary>
        string Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMailClusterEntityPropertiesInternal.Query { get => this._query; set { {_query = value;} } }

        /// <summary>Internal Acessors for QueryTime</summary>
        global::System.DateTime? Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMailClusterEntityPropertiesInternal.QueryTime { get => this._queryTime; set { {_queryTime = value;} } }

        /// <summary>Internal Acessors for Source</summary>
        string Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMailClusterEntityPropertiesInternal.Source { get => this._source; set { {_source = value;} } }

        /// <summary>Internal Acessors for Threat</summary>
        string[] Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IMailClusterEntityPropertiesInternal.Threat { get => this._threat; set { {_threat = value;} } }

        /// <summary>Backing field for <see cref="NetworkMessageId" /> property.</summary>
        private string[] _networkMessageId;

        /// <summary>The mail message IDs that are part of the mail cluster</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Origin(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.PropertyOrigin.Owned)]
        public string[] NetworkMessageId { get => this._networkMessageId; }

        /// <summary>Backing field for <see cref="Query" /> property.</summary>
        private string _query;

        /// <summary>The query that was used to identify the messages of the mail cluster</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Origin(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.PropertyOrigin.Owned)]
        public string Query { get => this._query; }

        /// <summary>Backing field for <see cref="QueryTime" /> property.</summary>
        private global::System.DateTime? _queryTime;

        /// <summary>The query time</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Origin(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.PropertyOrigin.Owned)]
        public global::System.DateTime? QueryTime { get => this._queryTime; }

        /// <summary>Backing field for <see cref="Source" /> property.</summary>
        private string _source;

        /// <summary>The source of the mail cluster (default is 'O365 ATP')</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Origin(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.PropertyOrigin.Owned)]
        public string Source { get => this._source; }

        /// <summary>Backing field for <see cref="Threat" /> property.</summary>
        private string[] _threat;

        /// <summary>The threats of mail messages that are part of the mail cluster</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Origin(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.PropertyOrigin.Owned)]
        public string[] Threat { get => this._threat; }

        /// <summary>Creates an new <see cref="MailClusterEntityProperties" /> instance.</summary>
        public MailClusterEntityProperties()
        {

        }

        /// <summary>Validates that this object meets the validation criteria.</summary>
        /// <param name="eventListener">an <see cref="Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.IEventListener" /> instance that will receive validation
        /// events.</param>
        /// <returns>
        /// A <see cref = "global::System.Threading.Tasks.Task" /> that will be complete when validation is completed.
        /// </returns>
        public async global::System.Threading.Tasks.Task Validate(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.IEventListener eventListener)
        {
            await eventListener.AssertNotNull(nameof(__entityCommonProperties), __entityCommonProperties);
            await eventListener.AssertObjectIsValid(nameof(__entityCommonProperties), __entityCommonProperties);
        }
    }
    /// Mail cluster entity property bag.
    public partial interface IMailClusterEntityProperties :
        Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.IJsonSerializable,
        Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IEntityCommonProperties
    {
        /// <summary>The cluster group</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"The cluster group",
        SerializedName = @"clusterGroup",
        PossibleTypes = new [] { typeof(string) })]
        string ClusterGroup { get;  }
        /// <summary>The cluster query end time</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"The cluster query end time",
        SerializedName = @"clusterQueryEndTime",
        PossibleTypes = new [] { typeof(global::System.DateTime) })]
        global::System.DateTime? ClusterQueryEndTime { get;  }
        /// <summary>The cluster query start time</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"The cluster query start time",
        SerializedName = @"clusterQueryStartTime",
        PossibleTypes = new [] { typeof(global::System.DateTime) })]
        global::System.DateTime? ClusterQueryStartTime { get;  }
        /// <summary>The id of the cluster source</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"The id of the cluster source",
        SerializedName = @"clusterSourceIdentifier",
        PossibleTypes = new [] { typeof(string) })]
        string ClusterSourceIdentifier { get;  }
        /// <summary>The type of the cluster source</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"The type of the cluster source",
        SerializedName = @"clusterSourceType",
        PossibleTypes = new [] { typeof(string) })]
        string ClusterSourceType { get;  }
        /// <summary>Count of mail messages by DeliveryStatus string representation</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"Count of mail messages by DeliveryStatus string representation",
        SerializedName = @"countByDeliveryStatus",
        PossibleTypes = new [] { typeof(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.IAny) })]
        Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.IAny CountByDeliveryStatus { get;  }
        /// <summary>Count of mail messages by ProtectionStatus string representation</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"Count of mail messages by ProtectionStatus string representation",
        SerializedName = @"countByProtectionStatus",
        PossibleTypes = new [] { typeof(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.IAny) })]
        Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.IAny CountByProtectionStatus { get;  }
        /// <summary>Count of mail messages by ThreatType string representation</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"Count of mail messages by ThreatType string representation",
        SerializedName = @"countByThreatType",
        PossibleTypes = new [] { typeof(Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.IAny) })]
        Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.IAny CountByThreatType { get;  }
        /// <summary>Is this a volume anomaly mail cluster</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"Is this a volume anomaly mail cluster",
        SerializedName = @"isVolumeAnomaly",
        PossibleTypes = new [] { typeof(bool) })]
        bool? IsVolumeAnomaly { get;  }
        /// <summary>The number of mail messages that are part of the mail cluster</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"The number of mail messages that are part of the mail cluster",
        SerializedName = @"mailCount",
        PossibleTypes = new [] { typeof(int) })]
        int? MailCount { get;  }
        /// <summary>The mail message IDs that are part of the mail cluster</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"The mail message IDs that are part of the mail cluster",
        SerializedName = @"networkMessageIds",
        PossibleTypes = new [] { typeof(string) })]
        string[] NetworkMessageId { get;  }
        /// <summary>The query that was used to identify the messages of the mail cluster</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"The query that was used to identify the messages of the mail cluster",
        SerializedName = @"query",
        PossibleTypes = new [] { typeof(string) })]
        string Query { get;  }
        /// <summary>The query time</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"The query time",
        SerializedName = @"queryTime",
        PossibleTypes = new [] { typeof(global::System.DateTime) })]
        global::System.DateTime? QueryTime { get;  }
        /// <summary>The source of the mail cluster (default is 'O365 ATP')</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"The source of the mail cluster (default is 'O365 ATP')",
        SerializedName = @"source",
        PossibleTypes = new [] { typeof(string) })]
        string Source { get;  }
        /// <summary>The threats of mail messages that are part of the mail cluster</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Runtime.Info(
        Required = false,
        ReadOnly = true,
        Description = @"The threats of mail messages that are part of the mail cluster",
        SerializedName = @"threats",
        PossibleTypes = new [] { typeof(string) })]
        string[] Threat { get;  }

    }
    /// Mail cluster entity property bag.
    internal partial interface IMailClusterEntityPropertiesInternal :
        Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.Api20210901Preview.IEntityCommonPropertiesInternal
    {
        /// <summary>The cluster group</summary>
        string ClusterGroup { get; set; }
        /// <summary>The cluster query end time</summary>
        global::System.DateTime? ClusterQueryEndTime { get; set; }
        /// <summary>The cluster query start time</summary>
        global::System.DateTime? ClusterQueryStartTime { get; set; }
        /// <summary>The id of the cluster source</summary>
        string ClusterSourceIdentifier { get; set; }
        /// <summary>The type of the cluster source</summary>
        string ClusterSourceType { get; set; }
        /// <summary>Count of mail messages by DeliveryStatus string representation</summary>
        Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.IAny CountByDeliveryStatus { get; set; }
        /// <summary>Count of mail messages by ProtectionStatus string representation</summary>
        Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.IAny CountByProtectionStatus { get; set; }
        /// <summary>Count of mail messages by ThreatType string representation</summary>
        Microsoft.Azure.PowerShell.Cmdlets.SecurityInsights.Models.IAny CountByThreatType { get; set; }
        /// <summary>Is this a volume anomaly mail cluster</summary>
        bool? IsVolumeAnomaly { get; set; }
        /// <summary>The number of mail messages that are part of the mail cluster</summary>
        int? MailCount { get; set; }
        /// <summary>The mail message IDs that are part of the mail cluster</summary>
        string[] NetworkMessageId { get; set; }
        /// <summary>The query that was used to identify the messages of the mail cluster</summary>
        string Query { get; set; }
        /// <summary>The query time</summary>
        global::System.DateTime? QueryTime { get; set; }
        /// <summary>The source of the mail cluster (default is 'O365 ATP')</summary>
        string Source { get; set; }
        /// <summary>The threats of mail messages that are part of the mail cluster</summary>
        string[] Threat { get; set; }

    }
}