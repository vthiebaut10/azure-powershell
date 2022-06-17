using System;
using System.Collections.Generic;
using System.Text;
using Azure;
using Azure.Core;
using Azure.ResourceManager;
using Azure.ResourceManager.HybridConnectivity;
using Azure.ResourceManager.HybridConnectivity.Models;
using Azure.ResourceManager.Resources;

using Microsoft.Azure.Commands.Common.Authentication;
using Microsoft.Azure.Commands.Common.Authentication.Abstractions;

namespace Microsoft.Azure.Commands.Ssh.Models
{
    public class Track2HybridConnectivityManagementClient
    {
        private ArmClient _armClient;
        private string _subscription;
        private IClientFactory _clientFactory;

        public Track2HybridConnectivityManagementClient(IClientFactory clientFactory, IAzureContext context)
        {
            _clientFactory = clientFactory;
            _armClient = _clientFactory.CreateArmClient(context, AzureEnvironment.Endpoint.ActiveDirectoryServiceEndpointResourceId);
            _subscription = context.Subscription.Id;
        }

        private ResourceGroupResource GetResourceGroup(string resourceGroupName) =>
              _armClient.GetResourceGroupResource(ResourceGroupResource.CreateResourceIdentifier(_subscription, resourceGroupName));

        public string GetRelayInformation()
        {
            EndpointResource myEndpoint = _armClient.GetEndpointResource(EndpointResource.CreateResourceIdentifier("/subscriptions/f09f6cd8-ae8a-4974-893d-e0e76fc13091/resourceGroups/azpwsh_test/providers/Microsoft.HybridCompute/machines/azpwsh-ssharc-u20", "default"));
            var myCred = myEndpoint.GetCredentials();
            return "";
        }

    }
}
