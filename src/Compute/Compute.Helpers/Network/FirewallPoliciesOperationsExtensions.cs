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
    /// Extension methods for FirewallPoliciesOperations.
    /// </summary>
    public static partial class FirewallPoliciesOperationsExtensions
    {
            /// <summary>
            /// Deletes the specified Firewall Policy.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='firewallPolicyName'>
            /// The name of the Firewall Policy.
            /// </param>
            public static void Delete(this IFirewallPoliciesOperations operations, string resourceGroupName, string firewallPolicyName)
            {
                operations.DeleteAsync(resourceGroupName, firewallPolicyName).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Deletes the specified Firewall Policy.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='firewallPolicyName'>
            /// The name of the Firewall Policy.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task DeleteAsync(this IFirewallPoliciesOperations operations, string resourceGroupName, string firewallPolicyName, CancellationToken cancellationToken = default(CancellationToken))
            {
                (await operations.DeleteWithHttpMessagesAsync(resourceGroupName, firewallPolicyName, null, cancellationToken).ConfigureAwait(false)).Dispose();
            }

            /// <summary>
            /// Gets the specified Firewall Policy.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='firewallPolicyName'>
            /// The name of the Firewall Policy.
            /// </param>
            /// <param name='expand'>
            /// Expands referenced resources.
            /// </param>
            public static FirewallPolicy Get(this IFirewallPoliciesOperations operations, string resourceGroupName, string firewallPolicyName, string expand = default(string))
            {
                return operations.GetAsync(resourceGroupName, firewallPolicyName, expand).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Gets the specified Firewall Policy.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='firewallPolicyName'>
            /// The name of the Firewall Policy.
            /// </param>
            /// <param name='expand'>
            /// Expands referenced resources.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<FirewallPolicy> GetAsync(this IFirewallPoliciesOperations operations, string resourceGroupName, string firewallPolicyName, string expand = default(string), CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.GetWithHttpMessagesAsync(resourceGroupName, firewallPolicyName, expand, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Creates or updates the specified Firewall Policy.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='firewallPolicyName'>
            /// The name of the Firewall Policy.
            /// </param>
            /// <param name='parameters'>
            /// Parameters supplied to the create or update Firewall Policy operation.
            /// </param>
            public static FirewallPolicy CreateOrUpdate(this IFirewallPoliciesOperations operations, string resourceGroupName, string firewallPolicyName, FirewallPolicy parameters)
            {
                return operations.CreateOrUpdateAsync(resourceGroupName, firewallPolicyName, parameters).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Creates or updates the specified Firewall Policy.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='firewallPolicyName'>
            /// The name of the Firewall Policy.
            /// </param>
            /// <param name='parameters'>
            /// Parameters supplied to the create or update Firewall Policy operation.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<FirewallPolicy> CreateOrUpdateAsync(this IFirewallPoliciesOperations operations, string resourceGroupName, string firewallPolicyName, FirewallPolicy parameters, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.CreateOrUpdateWithHttpMessagesAsync(resourceGroupName, firewallPolicyName, parameters, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Lists all Firewall Policies in a resource group.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            public static IPage<FirewallPolicy> List(this IFirewallPoliciesOperations operations, string resourceGroupName)
            {
                return operations.ListAsync(resourceGroupName).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Lists all Firewall Policies in a resource group.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<IPage<FirewallPolicy>> ListAsync(this IFirewallPoliciesOperations operations, string resourceGroupName, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.ListWithHttpMessagesAsync(resourceGroupName, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Gets all the Firewall Policies in a subscription.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            public static IPage<FirewallPolicy> ListAll(this IFirewallPoliciesOperations operations)
            {
                return operations.ListAllAsync().GetAwaiter().GetResult();
            }

            /// <summary>
            /// Gets all the Firewall Policies in a subscription.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<IPage<FirewallPolicy>> ListAllAsync(this IFirewallPoliciesOperations operations, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.ListAllWithHttpMessagesAsync(null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Deletes the specified Firewall Policy.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='firewallPolicyName'>
            /// The name of the Firewall Policy.
            /// </param>
            public static void BeginDelete(this IFirewallPoliciesOperations operations, string resourceGroupName, string firewallPolicyName)
            {
                operations.BeginDeleteAsync(resourceGroupName, firewallPolicyName).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Deletes the specified Firewall Policy.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='firewallPolicyName'>
            /// The name of the Firewall Policy.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task BeginDeleteAsync(this IFirewallPoliciesOperations operations, string resourceGroupName, string firewallPolicyName, CancellationToken cancellationToken = default(CancellationToken))
            {
                (await operations.BeginDeleteWithHttpMessagesAsync(resourceGroupName, firewallPolicyName, null, cancellationToken).ConfigureAwait(false)).Dispose();
            }

            /// <summary>
            /// Creates or updates the specified Firewall Policy.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='firewallPolicyName'>
            /// The name of the Firewall Policy.
            /// </param>
            /// <param name='parameters'>
            /// Parameters supplied to the create or update Firewall Policy operation.
            /// </param>
            public static FirewallPolicy BeginCreateOrUpdate(this IFirewallPoliciesOperations operations, string resourceGroupName, string firewallPolicyName, FirewallPolicy parameters)
            {
                return operations.BeginCreateOrUpdateAsync(resourceGroupName, firewallPolicyName, parameters).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Creates or updates the specified Firewall Policy.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group.
            /// </param>
            /// <param name='firewallPolicyName'>
            /// The name of the Firewall Policy.
            /// </param>
            /// <param name='parameters'>
            /// Parameters supplied to the create or update Firewall Policy operation.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async Task<FirewallPolicy> BeginCreateOrUpdateAsync(this IFirewallPoliciesOperations operations, string resourceGroupName, string firewallPolicyName, FirewallPolicy parameters, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.BeginCreateOrUpdateWithHttpMessagesAsync(resourceGroupName, firewallPolicyName, parameters, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Lists all Firewall Policies in a resource group.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='nextPageLink'>
            /// The NextLink from the previous successful call to List operation.
            /// </param>
            public static IPage<FirewallPolicy> ListNext(this IFirewallPoliciesOperations operations, string nextPageLink)
            {
                return operations.ListNextAsync(nextPageLink).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Lists all Firewall Policies in a resource group.
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
            public static async Task<IPage<FirewallPolicy>> ListNextAsync(this IFirewallPoliciesOperations operations, string nextPageLink, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.ListNextWithHttpMessagesAsync(nextPageLink, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

            /// <summary>
            /// Gets all the Firewall Policies in a subscription.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='nextPageLink'>
            /// The NextLink from the previous successful call to List operation.
            /// </param>
            public static IPage<FirewallPolicy> ListAllNext(this IFirewallPoliciesOperations operations, string nextPageLink)
            {
                return operations.ListAllNextAsync(nextPageLink).GetAwaiter().GetResult();
            }

            /// <summary>
            /// Gets all the Firewall Policies in a subscription.
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
            public static async Task<IPage<FirewallPolicy>> ListAllNextAsync(this IFirewallPoliciesOperations operations, string nextPageLink, CancellationToken cancellationToken = default(CancellationToken))
            {
                using (var _result = await operations.ListAllNextWithHttpMessagesAsync(nextPageLink, null, cancellationToken).ConfigureAwait(false))
                {
                    return _result.Body;
                }
            }

    }
}
