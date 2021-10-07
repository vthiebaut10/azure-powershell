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

using Microsoft.Azure.Commands.Common.Authentication.Models;
using Microsoft.Azure.Commands.ResourceManager.Common;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System;
using System.Diagnostics;

namespace Microsoft.Azure.Commands.Ssh
{
    public abstract class SshBaseCmdlet : AzureRMCmdlet
    {
        
        private RMProfileClient profileClient;
    
        public RMProfileClient ProfileClient
        {
            get
            {
                if (profileClient == null)
                {
                    profileClient = new RMProfileClient(DefaultProfile as AzureRmProfile);
                }
                return profileClient;
            }

            set { profileClient = value; }
        }


        public string GetCertificateFileName(string publicKeyFileName)
        {
            string directoryName = Path.GetFullPath(Path.GetDirectoryName(publicKeyFileName));
            string certFileName = Path.GetFileNameWithoutExtension(publicKeyFileName) + ".cer";
            return Path.Combine(directoryName, certFileName);
        }

        public string GetSSHClientPath(string sshCommand)
        {
            string sshPath = sshCommand;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                string commandExecutable = sshCommand + ".exe";
                string systemDir = Environment.SystemDirectory;
                sshPath = Path.Combine(systemDir, "openSSH", commandExecutable);
                if (!File.Exists(sshPath))
                {
                    //Raise Exception
                    Console.WriteLine("Could not find {0}", commandExecutable);
                }

            }
            return sshPath;
        }

        public void StartSSHConnection(string username, string ip, string privateKey)
        {
            string sshPath = GetSSHClientPath("ssh");
            string target = username + "@" + ip;
            string args = target + " -i " + privateKey;

            Process myprocess = Process.Start(sshPath, args);

            myprocess.WaitForExit();
        }
        /*
        public bool CheckIfHybridMachine(string name, string resource_group)
        {
            var vm = this.HybridComputeClient.HybridComputeManagementClient.Machines.GetWithHttpMessagesAsync(resource_group, name);
            Console.WriteLine("Arc name: {0}", vm);
            if (vm == null)
            {
                return false;
            }
            else
            {
                return true;
            }
        }
        */
    }

}
