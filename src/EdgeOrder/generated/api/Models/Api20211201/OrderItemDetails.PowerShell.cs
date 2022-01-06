// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201
{
    using Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Runtime.PowerShell;

    /// <summary>Order item details</summary>
    [System.ComponentModel.TypeConverter(typeof(OrderItemDetailsTypeConverter))]
    public partial class OrderItemDetails
    {

        /// <summary>
        /// <c>AfterDeserializeDictionary</c> will be called after the deserialization has finished, allowing customization of the
        /// object before it is returned. Implement this method in a partial class to enable this behavior
        /// </summary>
        /// <param name="content">The global::System.Collections.IDictionary content that should be used.</param>

        partial void AfterDeserializeDictionary(global::System.Collections.IDictionary content);

        /// <summary>
        /// <c>AfterDeserializePSObject</c> will be called after the deserialization has finished, allowing customization of the object
        /// before it is returned. Implement this method in a partial class to enable this behavior
        /// </summary>
        /// <param name="content">The global::System.Management.Automation.PSObject content that should be used.</param>

        partial void AfterDeserializePSObject(global::System.Management.Automation.PSObject content);

        /// <summary>
        /// <c>BeforeDeserializeDictionary</c> will be called before the deserialization has commenced, allowing complete customization
        /// of the object before it is deserialized.
        /// If you wish to disable the default deserialization entirely, return <c>true</c> in the <see "returnNow" /> output parameter.
        /// Implement this method in a partial class to enable this behavior.
        /// </summary>
        /// <param name="content">The global::System.Collections.IDictionary content that should be used.</param>
        /// <param name="returnNow">Determines if the rest of the serialization should be processed, or if the method should return
        /// instantly.</param>

        partial void BeforeDeserializeDictionary(global::System.Collections.IDictionary content, ref bool returnNow);

        /// <summary>
        /// <c>BeforeDeserializePSObject</c> will be called before the deserialization has commenced, allowing complete customization
        /// of the object before it is deserialized.
        /// If you wish to disable the default deserialization entirely, return <c>true</c> in the <see "returnNow" /> output parameter.
        /// Implement this method in a partial class to enable this behavior.
        /// </summary>
        /// <param name="content">The global::System.Management.Automation.PSObject content that should be used.</param>
        /// <param name="returnNow">Determines if the rest of the serialization should be processed, or if the method should return
        /// instantly.</param>

        partial void BeforeDeserializePSObject(global::System.Management.Automation.PSObject content, ref bool returnNow);

        /// <summary>
        /// Deserializes a <see cref="global::System.Collections.IDictionary" /> into an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.OrderItemDetails"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Collections.IDictionary content that should be used.</param>
        /// <returns>
        /// an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetails" />.
        /// </returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetails DeserializeFromDictionary(global::System.Collections.IDictionary content)
        {
            return new OrderItemDetails(content);
        }

        /// <summary>
        /// Deserializes a <see cref="global::System.Management.Automation.PSObject" /> into an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.OrderItemDetails"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Management.Automation.PSObject content that should be used.</param>
        /// <returns>
        /// an instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetails" />.
        /// </returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetails DeserializeFromPSObject(global::System.Management.Automation.PSObject content)
        {
            return new OrderItemDetails(content);
        }

        /// <summary>
        /// Creates a new instance of <see cref="OrderItemDetails" />, deserializing the content from a json string.
        /// </summary>
        /// <param name="jsonText">a string containing a JSON serialized instance of this model.</param>
        /// <returns>an instance of the <see cref="className" /> model class.</returns>
        public static Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetails FromJsonString(string jsonText) => FromJson(Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Runtime.Json.JsonNode.Parse(jsonText));

        /// <summary>
        /// Deserializes a <see cref="global::System.Collections.IDictionary" /> into a new instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.OrderItemDetails"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Collections.IDictionary content that should be used.</param>
        internal OrderItemDetails(global::System.Collections.IDictionary content)
        {
            bool returnNow = false;
            BeforeDeserializeDictionary(content, ref returnNow);
            if (returnNow)
            {
                return;
            }
            // actually deserialize
            if (content.Contains("ProductDetail"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).ProductDetail = (Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IProductDetails) content.GetValueForProperty("ProductDetail",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).ProductDetail, Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.ProductDetailsTypeConverter.ConvertFrom);
            }
            if (content.Contains("OrderItemType"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).OrderItemType = (Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Support.OrderItemType) content.GetValueForProperty("OrderItemType",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).OrderItemType, Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Support.OrderItemType.CreateFrom);
            }
            if (content.Contains("CurrentStage"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).CurrentStage = (Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IStageDetails) content.GetValueForProperty("CurrentStage",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).CurrentStage, Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.StageDetailsTypeConverter.ConvertFrom);
            }
            if (content.Contains("OrderItemStageHistory"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).OrderItemStageHistory = (Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IStageDetails[]) content.GetValueForProperty("OrderItemStageHistory",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).OrderItemStageHistory, __y => TypeConverterExtensions.SelectToArray<Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IStageDetails>(__y, Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.StageDetailsTypeConverter.ConvertFrom));
            }
            if (content.Contains("Preference"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).Preference = (Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IPreferences) content.GetValueForProperty("Preference",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).Preference, Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.PreferencesTypeConverter.ConvertFrom);
            }
            if (content.Contains("ForwardShippingDetail"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).ForwardShippingDetail = (Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IForwardShippingDetails) content.GetValueForProperty("ForwardShippingDetail",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).ForwardShippingDetail, Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.ForwardShippingDetailsTypeConverter.ConvertFrom);
            }
            if (content.Contains("ReverseShippingDetail"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).ReverseShippingDetail = (Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IReverseShippingDetails) content.GetValueForProperty("ReverseShippingDetail",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).ReverseShippingDetail, Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.ReverseShippingDetailsTypeConverter.ConvertFrom);
            }
            if (content.Contains("NotificationEmailList"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).NotificationEmailList = (string[]) content.GetValueForProperty("NotificationEmailList",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).NotificationEmailList, __y => TypeConverterExtensions.SelectToArray<string>(__y, global::System.Convert.ToString));
            }
            if (content.Contains("CancellationReason"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).CancellationReason = (string) content.GetValueForProperty("CancellationReason",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).CancellationReason, global::System.Convert.ToString);
            }
            if (content.Contains("CancellationStatus"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).CancellationStatus = (Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Support.OrderItemCancellationEnum?) content.GetValueForProperty("CancellationStatus",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).CancellationStatus, Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Support.OrderItemCancellationEnum.CreateFrom);
            }
            if (content.Contains("DeletionStatus"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).DeletionStatus = (Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Support.ActionStatusEnum?) content.GetValueForProperty("DeletionStatus",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).DeletionStatus, Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Support.ActionStatusEnum.CreateFrom);
            }
            if (content.Contains("ReturnReason"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).ReturnReason = (string) content.GetValueForProperty("ReturnReason",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).ReturnReason, global::System.Convert.ToString);
            }
            if (content.Contains("ReturnStatus"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).ReturnStatus = (Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Support.OrderItemReturnEnum?) content.GetValueForProperty("ReturnStatus",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).ReturnStatus, Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Support.OrderItemReturnEnum.CreateFrom);
            }
            if (content.Contains("ManagementRpDetail"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).ManagementRpDetail = (Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IResourceProviderDetails) content.GetValueForProperty("ManagementRpDetail",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).ManagementRpDetail, Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.ResourceProviderDetailsTypeConverter.ConvertFrom);
            }
            if (content.Contains("ManagementRpDetailsList"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).ManagementRpDetailsList = (Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IResourceProviderDetails[]) content.GetValueForProperty("ManagementRpDetailsList",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).ManagementRpDetailsList, __y => TypeConverterExtensions.SelectToArray<Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IResourceProviderDetails>(__y, Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.ResourceProviderDetailsTypeConverter.ConvertFrom));
            }
            if (content.Contains("Error"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).Error = (Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20.IErrorDetail) content.GetValueForProperty("Error",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).Error, Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20.ErrorDetailTypeConverter.ConvertFrom);
            }
            AfterDeserializeDictionary(content);
        }

        /// <summary>
        /// Deserializes a <see cref="global::System.Management.Automation.PSObject" /> into a new instance of <see cref="Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.OrderItemDetails"
        /// />.
        /// </summary>
        /// <param name="content">The global::System.Management.Automation.PSObject content that should be used.</param>
        internal OrderItemDetails(global::System.Management.Automation.PSObject content)
        {
            bool returnNow = false;
            BeforeDeserializePSObject(content, ref returnNow);
            if (returnNow)
            {
                return;
            }
            // actually deserialize
            if (content.Contains("ProductDetail"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).ProductDetail = (Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IProductDetails) content.GetValueForProperty("ProductDetail",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).ProductDetail, Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.ProductDetailsTypeConverter.ConvertFrom);
            }
            if (content.Contains("OrderItemType"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).OrderItemType = (Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Support.OrderItemType) content.GetValueForProperty("OrderItemType",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).OrderItemType, Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Support.OrderItemType.CreateFrom);
            }
            if (content.Contains("CurrentStage"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).CurrentStage = (Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IStageDetails) content.GetValueForProperty("CurrentStage",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).CurrentStage, Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.StageDetailsTypeConverter.ConvertFrom);
            }
            if (content.Contains("OrderItemStageHistory"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).OrderItemStageHistory = (Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IStageDetails[]) content.GetValueForProperty("OrderItemStageHistory",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).OrderItemStageHistory, __y => TypeConverterExtensions.SelectToArray<Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IStageDetails>(__y, Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.StageDetailsTypeConverter.ConvertFrom));
            }
            if (content.Contains("Preference"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).Preference = (Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IPreferences) content.GetValueForProperty("Preference",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).Preference, Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.PreferencesTypeConverter.ConvertFrom);
            }
            if (content.Contains("ForwardShippingDetail"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).ForwardShippingDetail = (Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IForwardShippingDetails) content.GetValueForProperty("ForwardShippingDetail",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).ForwardShippingDetail, Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.ForwardShippingDetailsTypeConverter.ConvertFrom);
            }
            if (content.Contains("ReverseShippingDetail"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).ReverseShippingDetail = (Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IReverseShippingDetails) content.GetValueForProperty("ReverseShippingDetail",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).ReverseShippingDetail, Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.ReverseShippingDetailsTypeConverter.ConvertFrom);
            }
            if (content.Contains("NotificationEmailList"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).NotificationEmailList = (string[]) content.GetValueForProperty("NotificationEmailList",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).NotificationEmailList, __y => TypeConverterExtensions.SelectToArray<string>(__y, global::System.Convert.ToString));
            }
            if (content.Contains("CancellationReason"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).CancellationReason = (string) content.GetValueForProperty("CancellationReason",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).CancellationReason, global::System.Convert.ToString);
            }
            if (content.Contains("CancellationStatus"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).CancellationStatus = (Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Support.OrderItemCancellationEnum?) content.GetValueForProperty("CancellationStatus",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).CancellationStatus, Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Support.OrderItemCancellationEnum.CreateFrom);
            }
            if (content.Contains("DeletionStatus"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).DeletionStatus = (Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Support.ActionStatusEnum?) content.GetValueForProperty("DeletionStatus",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).DeletionStatus, Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Support.ActionStatusEnum.CreateFrom);
            }
            if (content.Contains("ReturnReason"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).ReturnReason = (string) content.GetValueForProperty("ReturnReason",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).ReturnReason, global::System.Convert.ToString);
            }
            if (content.Contains("ReturnStatus"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).ReturnStatus = (Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Support.OrderItemReturnEnum?) content.GetValueForProperty("ReturnStatus",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).ReturnStatus, Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Support.OrderItemReturnEnum.CreateFrom);
            }
            if (content.Contains("ManagementRpDetail"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).ManagementRpDetail = (Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IResourceProviderDetails) content.GetValueForProperty("ManagementRpDetail",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).ManagementRpDetail, Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.ResourceProviderDetailsTypeConverter.ConvertFrom);
            }
            if (content.Contains("ManagementRpDetailsList"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).ManagementRpDetailsList = (Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IResourceProviderDetails[]) content.GetValueForProperty("ManagementRpDetailsList",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).ManagementRpDetailsList, __y => TypeConverterExtensions.SelectToArray<Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IResourceProviderDetails>(__y, Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.ResourceProviderDetailsTypeConverter.ConvertFrom));
            }
            if (content.Contains("Error"))
            {
                ((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).Error = (Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20.IErrorDetail) content.GetValueForProperty("Error",((Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20211201.IOrderItemDetailsInternal)this).Error, Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Models.Api20.ErrorDetailTypeConverter.ConvertFrom);
            }
            AfterDeserializePSObject(content);
        }

        /// <summary>Serializes this instance to a json string.</summary>

        /// <returns>a <see cref="System.String" /> containing this model serialized to JSON text.</returns>
        public string ToJsonString() => ToJson(null, Microsoft.Azure.PowerShell.Cmdlets.EdgeOrder.Runtime.SerializationMode.IncludeAll)?.ToString();
    }
    /// Order item details
    [System.ComponentModel.TypeConverter(typeof(OrderItemDetailsTypeConverter))]
    public partial interface IOrderItemDetails

    {

    }
}