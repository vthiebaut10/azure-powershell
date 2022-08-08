using Azure.ResourceManager.HybridConnectivity;
using Azure.ResourceManager.HybridConnectivity.Models;
using Azure.ResourceManager;
using Azure.ResourceManager.Resources;
using Microsoft.Azure.Commands.Common.Authentication;
using Microsoft.Azure.Commands.Common.Authentication.Abstractions;

namespace Microsoft.Azure.PowerShell.Cmdlets.Ssh.Common
{
    internal class Track2HybridConnectivityManagementClient
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

        public TargetResourceEndpointAccess GetRelayInformationString(string resourceGroup, string resourceName, string endpoint)
        {
            return GetRelayInformationString($"/subscriptions/{_subscription}/resourceGroups/{resourceGroup}/providers/Microsoft.HybridCompute/machines/{resourceName}", endpoint);
        }

        public TargetResourceEndpointAccess GetRelayInformationString(string ResourceId, string endpoint)
        {
            EndpointResource myEndpoint = _armClient.GetEndpointResource(EndpointResource.CreateResourceIdentifier(ResourceId, endpoint));
            var myCred = myEndpoint.GetCredentials(3600);
            return myCred.Value;
        }

        // how to create an endpoint?


    }
}
