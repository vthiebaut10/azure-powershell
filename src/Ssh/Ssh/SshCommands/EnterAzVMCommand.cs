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

using System;
using System.IO;
using System.Management.Automation;
using Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters;
using System.Diagnostics;
using System.Net;


namespace Microsoft.Azure.Commands.Ssh
{
    [Cmdlet("Enter", "AzureVM")]
    public class EnterAzVMCommand : SshBaseCmdlet
    {
        // Define the aguments
        [Parameter(
            Mandatory = true,
            Position = 0,
            ValueFromPipelineByPropertyName = true)]
        [ResourceGroupCompleter]
        [ValidateNotNullOrEmpty]
        public string ResourceGroupName { get; set; }

        [Parameter(
            Mandatory = true,
            Position = 1,
            ValueFromPipeline = true)]
        [ResourceNameCompleter("Microsoft.Compute/virtualMachines", "ResourceGroupName")]
        [ValidateNotNullOrEmpty]
        public string Name { get; set; }

        [Parameter(
        Mandatory = true,
        Position = 2,
        ValueFromPipeline = true)]
        [ValidateNotNullOrEmpty]
        public string LocalUser { get; set; }

        [Parameter(
            Mandatory = false,
            Position = 3,
            ValueFromPipeline = true)]
        [ValidateNotNullOrEmpty]
        public string PublicKeyFile { get; set; }

        [Parameter(
            Mandatory = false,
            Position = 4,
            ValueFromPipeline = true)]
        [ValidateNotNullOrEmpty]
        public string PrivateKeyFile { get; set; }

        public override void ExecuteCmdlet()
        {
            base.ExecuteCmdlet();

            //CheckIfHybridMachine(this.Name, this.ResourceGroupName);

            var utils = new SshUtils(DefaultProfile.DefaultContext);

            string ip = utils.GetFirstPublicIp(Name, ResourceGroupName);

            Console.Write("Ip Address: {0}", ip);
            /*
            var result = this.VirtualMachineClient.GetWithHttpMessagesAsync(
                this.ResourceGroupName, this.Name).GetAwaiter().GetResult();

            string publicIpAddress = GetFirstPublicIp(result.Body);

            if (string.IsNullOrEmpty(publicIpAddress))
            {
                throw new PSArgumentException($"VM {this.Name} does not have a public IP address to SSH to.");
            }

            StartSSHConnection(LocalUser, publicIpAddress, PrivateKeyFile);
            */

            //Find ssh location
            //build arguments

            //WebClient wc = new WebClient();
            //wc.DownloadFile(new System.Uri("https://sshproxysa.blob.core.windows.net/release10-09-21/sshProxy_windows_amd64_1.3.017131.exe"), @"D:\\proxy\\ssh_proxy.exe");


            //string enterArc = "balu@balu-u20 -o ProxyCommand=C:\\Users\\vthiebaut\\.clientsshproxy\\azgsshproxy.exe";

            //Process myprocess = Process.Start("C:\\Program Files\\OpenSSH-V8.6.0.0p1\\OpenSSH-Win64\\ssh.exe", enterVM);

            //myprocess.WaitForExit();
        }
    }
}