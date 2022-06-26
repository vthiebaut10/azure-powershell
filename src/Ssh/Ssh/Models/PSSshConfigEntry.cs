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
                builder.AppendLine($"Host {this.Host}");
                if (!HostName.Equals(Host))
                {
                    builder.AppendLine($"\tHostName {this.HostName}");
                }
                builder.AppendLine(string.Format("\tUser {0}", this.User));
                this.AppendKeyValuePairToStringBuilderIfNotValueNull("CertificateFile", this.CertificateFile, builder);
                this.AppendKeyValuePairToStringBuilderIfNotValueNull("IdentityFile", this.IdentityFile, builder);
                this.AppendKeyValuePairToStringBuilderIfNotValueNull("Port", this.Port, builder);
                this.AppendKeyValuePairToStringBuilderIfNotValueNull("ProxyCommand", this.ProxyCommand, builder);

                if (ResourceType.Equals("Microsoft.Compute/virtualMachines") && !HostName.Equals(Host))
                {
                    builder.AppendLine(string.Format("\nHost {0}", this.HostName));
                    builder.AppendLine(string.Format("\tUser {0}", this.User));
                    this.AppendKeyValuePairToStringBuilderIfNotValueNull("CertificateFile", this.CertificateFile, builder);
                    this.AppendKeyValuePairToStringBuilderIfNotValueNull("IdentityFile", this.IdentityFile, builder);
                    this.AppendKeyValuePairToStringBuilderIfNotValueNull("Port", this.Port, builder);
                }

                return builder.ToString();
            }
        }

        // This is pretty horrible, but it does help me avoid passing a bunch of parameters.
        // Rethink this.
        public PSSshConfigEntry(CreateAzVMSshConfig SshCmdlet)
        {
            if (SshCmdlet.ResourceGroupName != null && SshCmdlet.Name != null) { Host = SshCmdlet.ResourceGroupName + "-" + SshCmdlet.Name; }
            else { Host = SshCmdlet.Ip; }

            if (SshCmdlet.IsArc()) 
            { 
                HostName = SshCmdlet.Name;
                ProxyCommand = "\"" + SshCmdlet.proxyPath + "\" -r \"" + SshCmdlet.RelayInfoPath + "\"";
                if (SshCmdlet.Port != null)
                {
                    ProxyCommand = ProxyCommand + " -p " + SshCmdlet.Port;
                }
            }
            else
            {
                Port = SshCmdlet.Port;
                if (SshCmdlet.Ip != null) { HostName = SshCmdlet.Ip; }
                else { HostName = "*";  }
            }
            User = SshCmdlet.LocalUser;
            CertificateFile = SshCmdlet.CertificateFile;
            IdentityFile = SshCmdlet.PrivateKeyFile;
            ResourceType = SshCmdlet.ResourceType;
        }

        private void AppendKeyValuePairToStringBuilderIfNotValueNull(string key, string value, StringBuilder builder)
        {
            if (value != null)
            {
                builder.AppendLine($"\t{key} {value}");
            }
        }
    }
}
