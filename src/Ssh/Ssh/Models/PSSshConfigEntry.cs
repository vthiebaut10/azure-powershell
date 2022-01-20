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

using System.Text;

namespace Microsoft.Azure.Commands.Ssh.Models
{
    public class PSSshConfigEntry
    {
        public string Host { get; set; }

        public string HostName { get; set; }

        public string User { get; set; }

        public string CertificateFile { get; set; }

        public string IdentityFile { get; set; }

        public string ResourceType { get; set; }

        public string ProxyCommand { get; set; }

        public string Port { get; set; }

        public string ConfigString
        {
            get
            {
                StringBuilder builder = new StringBuilder();
                builder.AppendLine(string.Format("Host {0}", this.Host));
                if (!HostName.Equals(Host))
                {
                    builder.AppendLine(string.Format("\tHostName {0}", this.HostName));
                }
                builder.AppendLine(string.Format("\tUser {0}", this.User));
                if (CertificateFile != null)
                {
                    builder.AppendLine(string.Format("\tCertificateFile {0}", this.CertificateFile));
                }
                if (IdentityFile != null)
                {
                    builder.Append(string.Format("\tIdentityFile {0}", this.IdentityFile));
                }
                if (Port != null)
                {
                    builder.Append(string.Format("\tPort {0}", this.Port));
                }
                if (ProxyCommand != null)
                {
                    builder.Append(string.Format("\tProxyCommand {0}", this.ProxyCommand));
                }

                if (ResourceType.Equals("Microsoft.Compute") && !HostName.Equals(Host))
                {
                    builder.AppendLine(string.Format("\nHost {0}", this.HostName));
                    builder.AppendLine(string.Format("\tUser {0}", this.User));
                        
                    if (CertificateFile != null)
                    {
                        builder.AppendLine(string.Format("\tCertificateFile {0}", this.CertificateFile));
                    }
                    if (IdentityFile != null)
                    {
                        builder.Append(string.Format("\tIdentityFile {0}", this.IdentityFile));
                    }
                    if (Port != null)
                    {
                        builder.Append(string.Format("\tPort {0}", this.Port));
                    }

                }

                return builder.ToString();
            }
        }

        // This case is for Azure VMs that were passed in with name and resource group
        public PSSshConfigEntry(string ip, string vmName, string rgName, string proxyPath, string relayInfoPath, 
            string username, string certFile, string privateKey, string port, string resourceType)
        {
            if (rgName != null && vmName != null) { Host = rgName + "-" + vmName; }
            else { Host = ip; }

            if (resourceType.Equals("Microsoft.HybridCompute")) 
            { 
                HostName = vmName;
                ProxyCommand = "\"" + proxyPath + "\" -r \"" + relayInfoPath + "\"";
                if (port != null)
                {
                    ProxyCommand = ProxyCommand + " -p " + port;
                }
            }
            else
            {
                Port = port;
                if (ip != null) { HostName = ip; }
                else { HostName = "*";  }
            }
            User = username;
            CertificateFile = certFile;
            IdentityFile = privateKey;
            ResourceType = resourceType;
        }
    }
}
