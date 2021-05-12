// <auto-generated>
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>

namespace Microsoft.Azure.Commands.Compute.Helpers.Network
{
    using Microsoft.Rest;
    using Microsoft.Rest.Azure;
    using Models;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// Extension methods for VpnServerConfigurationsOperations.
    /// </summary>
    public static partial class VpnServerConfigurationsOperationsExtensions
    {
            /// <summary>
            /// Retrieves the details of a VpnServerConfiguration.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The resource group name of the VpnServerConfiguration.
            /// </param>
            /// <param name='vpnServerConfigurationName'>
            /// The name of the VpnServerConfiguration being retrieved.
            /// </param>
            public static VpnServerConfiguration Get(this IVpnServerConfigurationsOperations operations, string resourceGroupName, string vpnServerConfigurationName)
            {
                return operations.GetAsync(resourceGroupName, vpnServerConfigurationName).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Retrieves the details of a VpnServerConfiguration.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The resource group name of the VpnServerConfiguration.
            /// </param>
            /// <param name='vpnServerConfigurationName'>
            /// The name of the VpnServerConfiguration being retrieved.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<VpnServerConfiguration> GetAsync(this IVpnServerConfigurationsOperations operations, string resourceGroupName, string vpnServerConfigurationName, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.GetWithHttpMessagesAsync(resourceGroupName, vpnServerConfigurationName, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Creates a VpnServerConfiguration resource if it doesn't exist else updates
            /// the existing VpnServerConfiguration.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The resource group name of the VpnServerConfiguration.
            /// </param>
            /// <param name='vpnServerConfigurationName'>
            /// The name of the VpnServerConfiguration being created or updated.
            /// </param>
            /// <param name='vpnServerConfigurationParameters'>
            /// Parameters supplied to create or update VpnServerConfiguration.
            /// </param>
            public static VpnServerConfiguration CreateOrUpdate(this IVpnServerConfigurationsOperations operations, string resourceGroupName, string vpnServerConfigurationName, VpnServerConfiguration vpnServerConfigurationParameters)
            {
                return operations.CreateOrUpdateAsync(resourceGroupName, vpnServerConfigurationName, vpnServerConfigurationParameters).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Creates a VpnServerConfiguration resource if it doesn't exist else updates
            /// the existing VpnServerConfiguration.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The resource group name of the VpnServerConfiguration.
            /// </param>
            /// <param name='vpnServerConfigurationName'>
            /// The name of the VpnServerConfiguration being created or updated.
            /// </param>
            /// <param name='vpnServerConfigurationParameters'>
            /// Parameters supplied to create or update VpnServerConfiguration.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<VpnServerConfiguration> CreateOrUpdateAsync(this IVpnServerConfigurationsOperations operations, string resourceGroupName, string vpnServerConfigurationName, VpnServerConfiguration vpnServerConfigurationParameters, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.CreateOrUpdateWithHttpMessagesAsync(resourceGroupName, vpnServerConfigurationName, vpnServerConfigurationParameters, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Updates VpnServerConfiguration tags.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The resource group name of the VpnServerConfiguration.
            /// </param>
            /// <param name='vpnServerConfigurationName'>
            /// The name of the VpnServerConfiguration being updated.
            /// </param>
            /// <param name='vpnServerConfigurationParameters'>
            /// Parameters supplied to update VpnServerConfiguration tags.
            /// </param>
            public static VpnServerConfiguration UpdateTags(this IVpnServerConfigurationsOperations operations, string resourceGroupName, string vpnServerConfigurationName, TagsObject vpnServerConfigurationParameters)
            {
                return operations.UpdateTagsAsync(resourceGroupName, vpnServerConfigurationName, vpnServerConfigurationParameters).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Updates VpnServerConfiguration tags.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The resource group name of the VpnServerConfiguration.
            /// </param>
            /// <param name='vpnServerConfigurationName'>
            /// The name of the VpnServerConfiguration being updated.
            /// </param>
            /// <param name='vpnServerConfigurationParameters'>
            /// Parameters supplied to update VpnServerConfiguration tags.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<VpnServerConfiguration> UpdateTagsAsync(this IVpnServerConfigurationsOperations operations, string resourceGroupName, string vpnServerConfigurationName, TagsObject vpnServerConfigurationParameters, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.UpdateTagsWithHttpMessagesAsync(resourceGroupName, vpnServerConfigurationName, vpnServerConfigurationParameters, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Deletes a VpnServerConfiguration.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The resource group name of the VpnServerConfiguration.
            /// </param>
            /// <param name='vpnServerConfigurationName'>
            /// The name of the VpnServerConfiguration being deleted.
            /// </param>
            public static void Delete(this IVpnServerConfigurationsOperations operations, string resourceGroupName, string vpnServerConfigurationName)
            {
                operations.DeleteAsync(resourceGroupName, vpnServerConfigurationName).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Deletes a VpnServerConfiguration.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The resource group name of the VpnServerConfiguration.
            /// </param>
            /// <param name='vpnServerConfigurationName'>
            /// The name of the VpnServerConfiguration being deleted.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task DeleteAsync(this IVpnServerConfigurationsOperations operations, string resourceGroupName, string vpnServerConfigurationName, CancellationToken cancellationToken = default(CancellationToken))
            {
                (await operations.DeleteWithHttpMessagesAsync(resourceGroupName, vpnServerConfigurationName, null, cancellationToken).ConfigureAwait(false)).Dispose();
            }

            /// <summary>
            /// Lists all the vpnServerConfigurations in a resource group.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The resource group name of the VpnServerConfiguration.
            /// </param>
            public static IPage<VpnServerConfiguration> ListByResourceGroup(this IVpnServerConfigurationsOperations operations, string resourceGroupName)
            {
                return operations.ListByResourceGroupAsync(resourceGroupName).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Lists all the vpnServerConfigurations in a resource group.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The resource group name of the VpnServerConfiguration.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<IPage<VpnServerConfiguration>> ListByResourceGroupAsync(this IVpnServerConfigurationsOperations operations, string resourceGroupName, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.ListByResourceGroupWithHttpMessagesAsync(resourceGroupName, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Lists all the VpnServerConfigurations in a subscription.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            public static IPage<VpnServerConfiguration> List(this IVpnServerConfigurationsOperations operations)
            {
                return operations.ListAsync().GetAwaiter().GetResult();
            }

            /// <summary>
            /// Lists all the VpnServerConfigurations in a subscription.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<IPage<VpnServerConfiguration>> ListAsync(this IVpnServerConfigurationsOperations operations, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.ListWithHttpMessagesAsync(null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Creates a VpnServerConfiguration resource if it doesn't exist else updates
            /// the existing VpnServerConfiguration.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The resource group name of the VpnServerConfiguration.
            /// </param>
            /// <param name='vpnServerConfigurationName'>
            /// The name of the VpnServerConfiguration being created or updated.
            /// </param>
            /// <param name='vpnServerConfigurationParameters'>
            /// Parameters supplied to create or update VpnServerConfiguration.
            /// </param>
            public static VpnServerConfiguration BeginCreateOrUpdate(this IVpnServerConfigurationsOperations operations, string resourceGroupName, string vpnServerConfigurationName, VpnServerConfiguration vpnServerConfigurationParameters)
            {
                return operations.BeginCreateOrUpdateAsync(resourceGroupName, vpnServerConfigurationName, vpnServerConfigurationParameters).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Creates a VpnServerConfiguration resource if it doesn't exist else updates
            /// the existing VpnServerConfiguration.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The resource group name of the VpnServerConfiguration.
            /// </param>
            /// <param name='vpnServerConfigurationName'>
            /// The name of the VpnServerConfiguration being created or updated.
            /// </param>
            /// <param name='vpnServerConfigurationParameters'>
            /// Parameters supplied to create or update VpnServerConfiguration.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<VpnServerConfiguration> BeginCreateOrUpdateAsync(this IVpnServerConfigurationsOperations operations, string resourceGroupName, string vpnServerConfigurationName, VpnServerConfiguration vpnServerConfigurationParameters, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.BeginCreateOrUpdateWithHttpMessagesAsync(resourceGroupName, vpnServerConfigurationName, vpnServerConfigurationParameters, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Deletes a VpnServerConfiguration.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The resource group name of the VpnServerConfiguration.
            /// </param>
            /// <param name='vpnServerConfigurationName'>
            /// The name of the VpnServerConfiguration being deleted.
            /// </param>
            public static void BeginDelete(this IVpnServerConfigurationsOperations operations, string resourceGroupName, string vpnServerConfigurationName)
            {
                operations.BeginDeleteAsync(resourceGroupName, vpnServerConfigurationName).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Deletes a VpnServerConfiguration.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The resource group name of the VpnServerConfiguration.
            /// </param>
            /// <param name='vpnServerConfigurationName'>
            /// The name of the VpnServerConfiguration being deleted.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task BeginDeleteAsync(this IVpnServerConfigurationsOperations operations, string resourceGroupName, string vpnServerConfigurationName, CancellationToken cancellationToken = default(CancellationToken))
            {
                (await operations.BeginDeleteWithHttpMessagesAsync(resourceGroupName, vpnServerConfigurationName, null, cancellationToken).ConfigureAwait(false)).Dispose();
            }

            /// <summary>
            /// Lists all the vpnServerConfigurations in a resource group.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='nextPageLink'>
            /// The NextLink from the previous successful call to List operation.
            /// </param>
            public static IPage<VpnServerConfiguration> ListByResourceGroupNext(this IVpnServerConfigurationsOperations operations, string nextPageLink)
            {
                return operations.ListByResourceGroupNextAsync(nextPageLink).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Lists all the vpnServerConfigurations in a resource group.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='nextPageLink'>
            /// The NextLink from the previous successful call to List operation.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<IPage<VpnServerConfiguration>> ListByResourceGroupNextAsync(this IVpnServerConfigurationsOperations operations, string nextPageLink, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.ListByResourceGroupNextWithHttpMessagesAsync(nextPageLink, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Lists all the VpnServerConfigurations in a subscription.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='nextPageLink'>
            /// The NextLink from the previous successful call to List operation.
            /// </param>
            public static IPage<VpnServerConfiguration> ListNext(this IVpnServerConfigurationsOperations operations, string nextPageLink)
            {
                return operations.ListNextAsync(nextPageLink).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Lists all the VpnServerConfigurations in a subscription.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='nextPageLink'>
            /// The NextLink from the previous successful call to List operation.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<IPage<VpnServerConfiguration>> ListNextAsync(this IVpnServerConfigurationsOperations operations, string nextPageLink, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.ListNextWithHttpMessagesAsync(nextPageLink, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

    }
}
