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
using System.IO;
using System;
using System.Text.RegularExpressions;
using Microsoft.Azure.Commands.Common.Authentication.Models;
using Microsoft.Azure.Commands.ResourceManager.Common;
using Microsoft.Azure.Commands.Common.Authentication;
using Microsoft.Azure.Commands.Common.Authentication.Abstractions;
using Microsoft.Azure.Commands.Common.Exceptions;
using System.Linq;
using Microsoft.Rest.Azure;
using Microsoft.Rest;

namespace Microsoft.Azure.Commands.Ssh
{
    //As Compute module must not reference to storage SDK, the types of parameters and return values of
    //public APIs within this project should not expose any types defined in storage SDK.

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
                string nicRg = AzureIdUtilities.GetResourceGroup(nicReference.Id);
                string nicName = AzureIdUtilities.GetResourceName(nicReference.Id);

                var nic = this.NetworkClient.NetworkManagementClient.NetworkInterfaces.GetWithHttpMessagesAsync(
                    nicRg, nicName).GetAwaiter().GetResult();

                var publicIps = nic.Body.IpConfigurations.Where(ipconfig => ipconfig.PublicIPAddress != null).Select(ipconfig => ipconfig.PublicIPAddress);
                foreach (var ip in publicIps)
                {
                    var ipRg = AzureIdUtilities.GetResourceGroup(ip.Id);
                    var ipName = AzureIdUtilities.GetResourceName(ip.Id);
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

        public string GetNameFromId(string ResourceId)
        {
            return AzureIdUtilities.GetResourceName(ResourceId);
        }

        public string GetResourceGroupNameFromId(string ResourceId)
        {
            return AzureIdUtilities.GetResourceGroup(ResourceId);
        }
           
        public string GetResourceTypeFromId(string ResourceId)
        {
            return AzureIdUtilities.GetResourceType(ResourceId);
        }

        public string DecideResourceType(string vmName, string rgName, string ResourceType)
        {
            RestException computeException;
            RestException hybridException;

            if (ResourceType != null)
            {
                if (ResourceType.Equals("Microsoft.HybridCompute/machines"))
                {
                    if (CheckIfArcServer(vmName, rgName, out hybridException))
                    {
                        return "Microsoft.HybridCompute/machines";
                    }
                    else if (hybridException != null)
                    {
                         throw hybridException;
                    }
                }
                else if (ResourceType.Equals("Microsoft.Compute/virtualMachines"))
                {
                    if (CheckIfAzureVM(vmName, rgName, out computeException))
                    {
                        return "Microsoft.Compute/virtualMachines";
                    }
                    else if (computeException != null)
                    {
                        throw computeException;
                    }
                }
            }
            else
            {
                bool isArc = CheckIfArcServer(vmName, rgName, out hybridException);
                bool isAzVM = CheckIfAzureVM(vmName, rgName, out computeException);

                if (isArc && isAzVM)
                {
                    throw new AzPSCloudException("A arc server and a azure vm with the same name. Please provide -ResourceType argument.");
                }
                else if (!isArc && !isAzVM)
                { 
                    throw new AzPSCloudException("Unable to determine the target machine type as azure vm or arc server.");
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

        public bool CheckIfAzureVM(string vmName, string rgName, out RestException azexception)
        {
            azexception = null;

            try
            {
                var result = this.VirtualMachineClient.GetWithHttpMessagesAsync(
                    rgName, vmName).GetAwaiter().GetResult();
            }
            catch (CloudException exception)
            {
                if (exception.Response.StatusCode == System.Net.HttpStatusCode.NotFound || exception.Response.StatusCode == System.Net.HttpStatusCode.Forbidden)
                {
                    azexception = exception;
                    return false;
                }
                else
                {
                    throw;
                }
            }

            return true;
        }

        public bool CheckIfArcServer(string vmName, string rgName, out RestException azexception)
        {
            azexception = null;
            try
            {
                var result = this.ArcMachineClient.GetWithHttpMessagesAsync(rgName, vmName).GetAwaiter().GetResult();
            }
            catch (ErrorResponseException exception)
            {
                if (exception.Response.StatusCode == System.Net.HttpStatusCode.NotFound || exception.Response.StatusCode == System.Net.HttpStatusCode.Forbidden)
                {
                    azexception = exception;
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
