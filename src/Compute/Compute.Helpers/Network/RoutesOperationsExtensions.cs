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
    /// Extension methods for RoutesOperations.
    /// </summary>
    public static partial class RoutesOperationsExtensions
    {
            /// <summary>
            /// Deletes the specified route from a route table.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='routeTableName'>
            /// The name of the route table.
            /// </param>
            /// <param name='routeName'>
            /// The name of the route.
            /// </param>
            public static void Delete(this IRoutesOperations operations, string resourceGroupName, string routeTableName, string routeName)
            {
                operations.DeleteAsync(resourceGroupName, routeTableName, routeName).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Deletes the specified route from a route table.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='routeTableName'>
            /// The name of the route table.
            /// </param>
            /// <param name='routeName'>
            /// The name of the route.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task DeleteAsync(this IRoutesOperations operations, string resourceGroupName, string routeTableName, string routeName, CancellationToken cancellationToken = default(CancellationToken))
            {
                (await operations.DeleteWithHttpMessagesAsync(resourceGroupName, routeTableName, routeName, null, cancellationToken).ConfigureAwait(false)).Dispose();
            }

            /// <summary>
            /// Gets the specified route from a route table.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='routeTableName'>
            /// The name of the route table.
            /// </param>
            /// <param name='routeName'>
            /// The name of the route.
            /// </param>
            public static Route Get(this IRoutesOperations operations, string resourceGroupName, string routeTableName, string routeName)
            {
                return operations.GetAsync(resourceGroupName, routeTableName, routeName).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Gets the specified route from a route table.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='routeTableName'>
            /// The name of the route table.
            /// </param>
            /// <param name='routeName'>
            /// The name of the route.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<Route> GetAsync(this IRoutesOperations operations, string resourceGroupName, string routeTableName, string routeName, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.GetWithHttpMessagesAsync(resourceGroupName, routeTableName, routeName, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Creates or updates a route in the specified route table.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='routeTableName'>
            /// The name of the route table.
            /// </param>
            /// <param name='routeName'>
            /// The name of the route.
            /// </param>
            /// <param name='routeParameters'>
            /// Parameters supplied to the create or update route operation.
            /// </param>
            public static Route CreateOrUpdate(this IRoutesOperations operations, string resourceGroupName, string routeTableName, string routeName, Route routeParameters)
            {
                return operations.CreateOrUpdateAsync(resourceGroupName, routeTableName, routeName, routeParameters).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Creates or updates a route in the specified route table.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='routeTableName'>
            /// The name of the route table.
            /// </param>
            /// <param name='routeName'>
            /// The name of the route.
            /// </param>
            /// <param name='routeParameters'>
            /// Parameters supplied to the create or update route operation.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<Route> CreateOrUpdateAsync(this IRoutesOperations operations, string resourceGroupName, string routeTableName, string routeName, Route routeParameters, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.CreateOrUpdateWithHttpMessagesAsync(resourceGroupName, routeTableName, routeName, routeParameters, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Gets all routes in a route table.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='routeTableName'>
            /// The name of the route table.
            /// </param>
            public static IPage<Route> List(this IRoutesOperations operations, string resourceGroupName, string routeTableName)
            {
                return operations.ListAsync(resourceGroupName, routeTableName).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Gets all routes in a route table.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='routeTableName'>
            /// The name of the route table.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<IPage<Route>> ListAsync(this IRoutesOperations operations, string resourceGroupName, string routeTableName, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.ListWithHttpMessagesAsync(resourceGroupName, routeTableName, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Deletes the specified route from a route table.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='routeTableName'>
            /// The name of the route table.
            /// </param>
            /// <param name='routeName'>
            /// The name of the route.
            /// </param>
            public static void BeginDelete(this IRoutesOperations operations, string resourceGroupName, string routeTableName, string routeName)
            {
                operations.BeginDeleteAsync(resourceGroupName, routeTableName, routeName).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Deletes the specified route from a route table.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='routeTableName'>
            /// The name of the route table.
            /// </param>
            /// <param name='routeName'>
            /// The name of the route.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task BeginDeleteAsync(this IRoutesOperations operations, string resourceGroupName, string routeTableName, string routeName, CancellationToken cancellationToken = default(CancellationToken))
            {
                (await operations.BeginDeleteWithHttpMessagesAsync(resourceGroupName, routeTableName, routeName, null, cancellationToken).ConfigureAwait(false)).Dispose();
            }

            /// <summary>
            /// Creates or updates a route in the specified route table.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='routeTableName'>
            /// The name of the route table.
            /// </param>
            /// <param name='routeName'>
            /// The name of the route.
            /// </param>
            /// <param name='routeParameters'>
            /// Parameters supplied to the create or update route operation.
            /// </param>
            public static Route BeginCreateOrUpdate(this IRoutesOperations operations, string resourceGroupName, string routeTableName, string routeName, Route routeParameters)
            {
                return operations.BeginCreateOrUpdateAsync(resourceGroupName, routeTableName, routeName, routeParameters).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Creates or updates a route in the specified route table.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='routeTableName'>
            /// The name of the route table.
            /// </param>
            /// <param name='routeName'>
            /// The name of the route.
            /// </param>
            /// <param name='routeParameters'>
            /// Parameters supplied to the create or update route operation.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<Route> BeginCreateOrUpdateAsync(this IRoutesOperations operations, string resourceGroupName, string routeTableName, string routeName, Route routeParameters, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.BeginCreateOrUpdateWithHttpMessagesAsync(resourceGroupName, routeTableName, routeName, routeParameters, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Gets all routes in a route table.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='nextPageLink'>
            /// The NextLink from the previous successful call to List operation.
            /// </param>
            public static IPage<Route> ListNext(this IRoutesOperations operations, string nextPageLink)
            {
                return operations.ListNextAsync(nextPageLink).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Gets all routes in a route table.
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
            public static async Task<IPage<Route>> ListNextAsync(this IRoutesOperations operations, string nextPageLink, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.ListNextWithHttpMessagesAsync(nextPageLink, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

    }
}
