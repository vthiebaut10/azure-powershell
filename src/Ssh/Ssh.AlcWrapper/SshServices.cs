// ----------------------------------------------------------------------------------
//
// Copyright Microsoft Corporation
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------------

using Microsoft.Azure.Management.Compute;
using Microsoft.Azure.Management.Compute.Models;
using Microsoft.Azure.Management.Network;
using Microsoft.Azure.Management.HybridCompute;
using Microsoft.Azure.Management.HybridCompute.Models;
using Microsoft.Azure.Management.Internal.Resources.Utilities.Models;
using Microsoft.Azure.Commands.Common.Authentication;
using Microsoft.Azure.Commands.Common.Authentication.Abstractions;
using Microsoft.Azure.Commands.Common.Exceptions;
using System.Linq;
using Microsoft.Rest.Azure;
using Newtonsoft.Json.Linq;

namespace Microsoft.Azure.Commands.Ssh
{
    /// <summary>
    /// Client to make API calls to Azure Compute Resource Provider.
    /// </summary>
    public class ComputeClient
    {
        public IComputeManagementClient ComputeManagementClient { get; private set; }

        public ComputeClient(IAzureContext context)
            : this(AzureSession.Instance.ClientFactory.CreateArmClient<ComputeManagementClient>(
                context, AzureEnvironment.Endpoint.ResourceManager))
        {
        }

        public ComputeClient(IComputeManagementClient computeManagementClient)
        {
            this.ComputeManagementClient = computeManagementClient;
        }
    }

    /// <summary>
    /// Client to make API calls to Azure Compute Resource Provider.
    /// </summary>
    public class NetworkClient
    {
        public INetworkManagementClient NetworkManagementClient { get; private set; }

        public NetworkClient(IAzureContext context)
            : this(AzureSession.Instance.ClientFactory.CreateArmClient<NetworkManagementClient>(
                context, AzureEnvironment.Endpoint.ResourceManager))
        {
        }

        public NetworkClient(INetworkManagementClient networkManagementClient)
        {
            this.NetworkManagementClient = networkManagementClient;
        }
    }

    /// <summary>
    /// Client to make API calls to Azure Hybrid Compute Resource Provider.
    /// </summary>
    public class HybridComputeClient
    {
        public IHybridComputeManagementClient HybridComputeManagementClient { get; private set; }

        public HybridComputeClient(IAzureContext context)
            : this(AzureSession.Instance.ClientFactory.CreateArmClient<HybridComputeManagementClient>(
                context, AzureEnvironment.Endpoint.ResourceManager))
        {
        }

        public HybridComputeClient(IHybridComputeManagementClient hybridComputeManagementClient)
        {
            this.HybridComputeManagementClient = hybridComputeManagementClient;
        }
    }

    /// <summary>
    /// Class that provides utility methods that rely on external Azure Services.
    /// </summary>
    public class SshAzureUtils
    {
        private ComputeClient computeClient;
        private NetworkClient networkClient;
        private HybridComputeClient hybridClient;
        private IAzureContext context;

        public SshAzureUtils(IAzureContext azureContext)
        {
            context = azureContext;
        }

        public ComputeClient ComputeClient
        {
            get
            {
                if (computeClient == null)
                {
                    computeClient = new ComputeClient(context);
                }

                return computeClient;
            }

            set { computeClient = value; }
        }

        public NetworkClient NetworkClient
        {
            get
            {
                if (networkClient == null)
                {
                    networkClient = new NetworkClient(context);
                }
                return networkClient;
            }

            set { networkClient = value; }
        }

        public HybridComputeClient HybridClient
        {
            get
            {
                if (hybridClient == null)
                {
                    hybridClient = new HybridComputeClient(context);
                }
                return hybridClient;
            }

            set { hybridClient = value; }
        }

        public IVirtualMachinesOperations VirtualMachineClient
        {
            get
            {
                return ComputeClient.ComputeManagementClient.VirtualMachines;
            }
        }

        public IMachinesOperations ArcMachineClient
        {
            get
            {
                return HybridClient.HybridComputeManagementClient.Machines;
            }
        }

        public string GetFirstPublicIp(string vmName, string rgName)
        {
            var result = this.VirtualMachineClient.GetWithHttpMessagesAsync(
                rgName, vmName).GetAwaiter().GetResult();

            VirtualMachine vm = result.Body;

            string publicIpAddress = null;

            foreach (var nicReference in vm.NetworkProfile.NetworkInterfaces)
            {
                ResourceIdentifier parsedNicId = new ResourceIdentifier(nicReference.Id);
                string nicRg = parsedNicId.ResourceGroupName;
                string nicName = parsedNicId.ResourceName;

                var nic = this.NetworkClient.NetworkManagementClient.NetworkInterfaces.GetWithHttpMessagesAsync(
                    nicRg, nicName).GetAwaiter().GetResult();

                var publicIps = nic.Body.IpConfigurations.Where(ipconfig => ipconfig.PublicIPAddress != null).Select(ipconfig => ipconfig.PublicIPAddress);
                foreach (var ip in publicIps)
                {
                    ResourceIdentifier parsedIpId = new ResourceIdentifier(ip.Id);
                    var ipRg = parsedIpId.ResourceGroupName;
                    var ipName = parsedIpId.ResourceName;
                    var ipAddress = this.NetworkClient.NetworkManagementClient.PublicIPAddresses.GetWithHttpMessagesAsync(
                        ipRg, ipName).GetAwaiter().GetResult().Body;

                    publicIpAddress = ipAddress.IpAddress;

                    if (!string.IsNullOrEmpty(publicIpAddress))
                    {
                        break;
                    }
                }

                if (!string.IsNullOrEmpty(publicIpAddress))
                {
                    break;
                }
            }
            return publicIpAddress;
        }

        public string DecideResourceType(string vmName, string rgName, string ResourceType)
        {
            string hybridExceptionMessage;
            string computeExceptionMessage;

            if (ResourceType != null)
            {
                if (ResourceType.Equals("Microsoft.HybridCompute/machines"))
                {
                    if (CheckIfArcServer(vmName, rgName, out hybridExceptionMessage))
                    {
                        return "Microsoft.HybridCompute/machines";
                    }
                    else if (hybridExceptionMessage != null)
                    {
                        throw new AzPSCloudException("Failed to get Azure Arc Server. Error: " + hybridExceptionMessage);
                    }
                }
                else if (ResourceType.Equals("Microsoft.Compute/virtualMachines"))
                {
                    if (CheckIfAzureVM(vmName, rgName, out computeExceptionMessage))
                    {
                        return "Microsoft.Compute/virtualMachines";
                    }
                    else if (computeExceptionMessage != null)
                    {
                        throw new AzPSCloudException("Failed to get Azure Arc Server. Error: " + computeExceptionMessage);
                    }
                }
            }
            else
            {
                bool isArc = CheckIfArcServer(vmName, rgName, out hybridExceptionMessage);
                bool isAzVM = CheckIfAzureVM(vmName, rgName, out computeExceptionMessage);

                if (isArc && isAzVM)
                {
                    throw new AzPSCloudException("A arc server and a azure vm with the same name. Please provide -ResourceType argument.");
                }
                else if (!isArc && !isAzVM)
                { 
                    throw new AzPSCloudException("Unable to determine the target machine type as azure vm or arc server. Errors: \n" + hybridExceptionMessage + "\n" + computeExceptionMessage);
                }
                else if (isArc)
                {
                    return "Microsoft.HybridCompute/machines";
                }
                else
                {
                    return "Microsoft.Compute/virtualMachines";
                }
            }
            return null;
        }

        public bool CheckIfAzureVM(string vmName, string rgName, out string azexceptionMessage)
        {
            azexceptionMessage = null;
            try
            {
                var result = this.VirtualMachineClient.GetWithHttpMessagesAsync(
                    rgName, vmName).GetAwaiter().GetResult();
            }
            catch (CloudException exception)
            {
                if (exception.Response.StatusCode == System.Net.HttpStatusCode.NotFound || exception.Response.StatusCode == System.Net.HttpStatusCode.Forbidden)
                {
                    JObject json = JObject.Parse(exception.Response.Content);
                    azexceptionMessage = (string)json["error"]["message"];
                    return false;
                }
                else
                {
                    throw;
                }
            }

            return true;
        }

        public bool CheckIfArcServer(string vmName, string rgName, out string azexceptionMessage)
        {
            azexceptionMessage = null;
            try
            {
                var result = this.ArcMachineClient.GetWithHttpMessagesAsync(rgName, vmName).GetAwaiter().GetResult();
            }
            catch (ErrorResponseException exception)
            {
                if (exception.Response.StatusCode == System.Net.HttpStatusCode.NotFound || exception.Response.StatusCode == System.Net.HttpStatusCode.Forbidden)
                {
                    JObject json = JObject.Parse(exception.Response.Content);
                    azexceptionMessage = (string)json["error"]["message"];
                    return false;
                }
                else
                {
                    throw;
                }
            }

            return true;
        }
    }

}
