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
using Microsoft.Azure.Commands.Common.Exceptions;
using System.Diagnostics;
using System.Collections.Generic;
using Microsoft.Azure.PowerShell.Cmdlets.Ssh.Common;
using System.Text.RegularExpressions;


namespace Microsoft.Azure.Commands.Ssh
{
    [Cmdlet(
        VerbsCommon.Enter,
        ResourceManager.Common.AzureRMConstants.AzureRMPrefix + "VM",
        DefaultParameterSetName = InteractiveParameterSet)]
    [OutputType(typeof(bool))]
    [Alias("Enter-AzureVM", "Enter-ArcServer")]
    public class EnterAzVMCommand : SshBaseCmdlet, IDynamicParameters
    {
        [Parameter(
            ParameterSetName = InteractiveParameterSet,
            Mandatory = true,
            ValueFromPipelineByPropertyName = true)]
        [ResourceGroupCompleter]
        [ValidateNotNullOrEmpty]
        public override string ResourceGroupName { get; set; }

        [Parameter(
            ParameterSetName = InteractiveParameterSet,
            Mandatory = true,
            ValueFromPipelineByPropertyName = true)]
        [SshResourceNameCompleter(new string[] { "Microsoft.Compute/virtualMachines", "Microsoft.HybridCompute/machines" }, "ResourceGroupName")]
        [ValidateNotNullOrEmpty]
        public override string Name { get; set; }

        [Parameter(
            ParameterSetName = IpAddressParameterSet,
            Mandatory = true)]
        [ValidateNotNullOrEmpty]
        public override string Ip { get; set; }

        [Parameter(
            ParameterSetName = ResourceIdParameterSet,
            Mandatory = true,
            ValueFromPipeline = true)]
        [ValidateNotNullOrEmpty]
        [SshResourceIdCompleter(new string[] { "Microsoft.HybridCompute/machines", "Microsoft.Compute/virtualMachines" })]
        public override string ResourceId { get; set; }

        [Parameter(ParameterSetName = InteractiveParameterSet)]
        [Parameter(ParameterSetName = IpAddressParameterSet)]
        [Parameter(ParameterSetName = ResourceIdParameterSet)]
        [ValidateNotNullOrEmpty]
        public override string PublicKeyFile { get; set; }

        [Parameter(ParameterSetName = InteractiveParameterSet)]
        [Parameter(ParameterSetName = IpAddressParameterSet)]
        [Parameter(ParameterSetName = ResourceIdParameterSet)]
        [ValidateNotNullOrEmpty]
        public override string PrivateKeyFile { get; set; }

        [Parameter(ParameterSetName = InteractiveParameterSet)]
        [Parameter(ParameterSetName = ResourceIdParameterSet)]
        [ValidateNotNullOrEmpty]
        public override SwitchParameter UsePrivateIp { get; set; }

        [Parameter(ParameterSetName = InteractiveParameterSet)]
        [Parameter(ParameterSetName = IpAddressParameterSet)]
        [Parameter(ParameterSetName = ResourceIdParameterSet)]
        [ValidateNotNullOrEmpty]
        public override string LocalUser { get; set; }

        [Parameter(ParameterSetName = InteractiveParameterSet)]
        [Parameter(ParameterSetName = IpAddressParameterSet)]
        [Parameter(ParameterSetName = ResourceIdParameterSet)]
        [ValidateNotNullOrEmpty]
        public override string Port { get; set; }

        [Parameter(ParameterSetName = InteractiveParameterSet)]
        [Parameter(ParameterSetName = IpAddressParameterSet)]
        [Parameter(ParameterSetName = ResourceIdParameterSet)]
        [ValidateNotNullOrEmpty]
        public override string SshClientFolder { get; set; }

        [Parameter(ParameterSetName = InteractiveParameterSet)]
        [PSArgumentCompleter("Microsoft.Compute/virtualMachines", "Microsoft.HybridCompute/machines")]
        [ValidateNotNullOrEmpty]
        public override string ResourceType { get; set; }

        [Parameter(ParameterSetName = InteractiveParameterSet)]
        [Parameter(ParameterSetName = ResourceIdParameterSet)]
        [ValidateNotNullOrEmpty]
        public override string SshProxyFolder { get; set; }

        [Parameter(ParameterSetName = InteractiveParameterSet, ValueFromRemainingArguments = true)]
        [Parameter(ParameterSetName = IpAddressParameterSet, ValueFromRemainingArguments = true)]
        [Parameter(ParameterSetName = ResourceIdParameterSet, ValueFromRemainingArguments = true)]
        [ValidateNotNullOrEmpty]
        public string[] SshArguments { get; set; }

        [Parameter(Mandatory = false)]
        public SwitchParameter PassThru { get; set; }

        public new object GetDynamicParameters()
        {
            if (LocalUser != null)
            {
                certificateDynamicParameter = new SendCertParameter();
                return certificateDynamicParameter;
            }
            return null;
        }
        //private SendCertParameter certificateDynamicParameter;

        public override void ExecuteCmdlet()
        {
            base.ExecuteCmdlet();

            foreach (string a in SshArguments)
            {
                Console.WriteLine(a);
            }
            
            switch (ParameterSetName)
            {
                case IpAddressParameterSet:
                    ResourceType = "Microsoft.Compute/virtualMachines";
                    break;
                case ResourceIdParameterSet:
                    Name = AzureUtils.GetNameFromId(ResourceId);
                    ResourceGroupName = AzureUtils.GetResourceGroupNameFromId(ResourceId);
                    ResourceType = AzureUtils.DecideResourceType(Name, ResourceGroupName, AzureUtils.GetResourceTypeFromId(ResourceId));
                    break;
                case InteractiveParameterSet:
                    ResourceType = AzureUtils.DecideResourceType(Name, ResourceGroupName, ResourceType);
                    break;
            }

            if (!IsArc() && !ParameterSetName.Equals(IpAddressParameterSet))
            {
                GetVmIpAddress();
            }
            if (IsArc())
            {
                proxyPath = GetClientSideProxy();
                GetRelayInformation();
            }

            try
            {
                if (LocalUser == null)
                {
                    PrepareAadCredentials();
                }
                int sshStatus = StartSSHConnection();

                if (this.PassThru.IsPresent)
                {
                    WriteObject(sshStatus == 0);
                }
            }
            finally
            {
                DoCleanup();
            }
        }

        private bool IsDebugMode()
        {
            bool debug;
            bool containsDebug = MyInvocation.BoundParameters.ContainsKey("Debug");
            if (containsDebug)
                debug = ((SwitchParameter)MyInvocation.BoundParameters["Debug"]).ToBool(); 
            else
                debug = (ActionPreference)GetVariableValue("DebugPreference") != ActionPreference.SilentlyContinue;
            return debug;
        }

        private int StartSSHConnection()
        {                                 
            
            
            string sshClient = GetSSHClientPath("ssh");
            string command = GetHost() + " " + BuildArgs();

            Process sshProcess = new Process();
            WriteDebug("Running SSH command: " + sshClient + " " + command);

            if (IsArc())
                sshProcess.StartInfo.EnvironmentVariables["SSHPROXY_RELAY_INFO"] = relayInfo;
            sshProcess.StartInfo.FileName = sshClient;
            sshProcess.StartInfo.Arguments = command;
            if (deleteCert)
                sshProcess.StartInfo.RedirectStandardError = true;
                //sshProcess.StartInfo.RedirectStandardOutput = true;
            sshProcess.StartInfo.UseShellExecute = false;
            sshProcess.Start();

            List<string> errorMessages = new List<string>();
            bool writeLogs = false;
            if (deleteCert)
            {
                var stderr = sshProcess.StandardError;
                
                if (SshArguments != null &&
                    (Array.Exists(SshArguments, x => x == "-v") ||
                    Array.Exists(SshArguments, x => x == "-vv") ||
                    Array.Exists(SshArguments, x => x == "-vvv")) ||
                    IsDebugMode())
                {
                    writeLogs = true;
                }

                string line;
                while ((line = stderr.ReadLine()) != null)
                {
                    if (writeLogs)
                    {
                        Console.WriteLine(line);
                    } 
                    if (line.Contains("debug1: Entering interactive session."))
                    {
                        DoCleanup();
                    }
                    if (!line.Contains("debug1: ") &&
                        !line.Contains("debug2: ") &&
                        !line.Contains("debug3: "))
                    {
                        errorMessages.Add(line);
                    }
                }
            }

            sshProcess.WaitForExit();

            if (sshProcess.ExitCode != 0 && !writeLogs && deleteCert)
            {
                foreach (string errorLine in errorMessages)
                {
                    Console.WriteLine(errorLine);
                }
            }
            return sshProcess.ExitCode;
        }

        private string GetHost()
        {
            if (ResourceType == "Microsoft.HybridCompute/machines" && LocalUser != null && Name != null) 
            {
                return LocalUser + "@" + Name;
            } else if (ResourceType == "Microsoft.Compute/virtualMachines" && LocalUser != null && Ip != null)
            {
                return LocalUser + "@" + Ip;
            }
            throw new AzPSInvalidOperationException("Unable to determine target host.");
        }


        private string BuildArgs()
        {
            List<string> argList = new List<string>();

            if (PrivateKeyFile != null) { argList.Add("-i \"" + PrivateKeyFile + "\""); }

            if (CertificateFile != null) { argList.Add("-o CertificateFile=\"" + CertificateFile + "\""); }

            if (IsArc())
            {
                string pcommand = "ProxyCommand=\"" + proxyPath + "\"";
                if (Port != null)
                {
                    pcommand = "ProxyCommand=\"" + proxyPath + " -p " + Port + "\"";
                }
                argList.Add("-o " + pcommand);
            } else if (Port != null) 
            { 
                argList.Add("-p " + Port);
            }
            
            if (deleteCert || IsDebugMode())
            {
                if (SshArguments == null ||
                   (!Array.Exists(SshArguments, x => x == "-v") &&
                    !Array.Exists(SshArguments, x => x == "-vv") &&
                    !Array.Exists(SshArguments, x => x == "-vvv")))
                {
                    argList.Add("-vvv");
                }
            }
            
            if (SshArguments != null)
            {
                Array.ForEach(SshArguments, item => argList.Add(item));
            }

            return string.Join(" ", argList.ToArray());
        }

        private void DoCleanup()
        {
            if (deleteKeys && PrivateKeyFile != null)
            {
                DeleteFile(PrivateKeyFile, "Couldn't delete Private Key file " + PrivateKeyFile + ".");
            }
            if (deleteKeys && PublicKeyFile != null)
            {
                DeleteFile(PublicKeyFile, "Couldn't delete Public Key file " + PublicKeyFile + ".");
            }
            if (deleteCert && CertificateFile != null)
            {
                DeleteFile(CertificateFile, "Couldn't delete Certificate File " + CertificateFile + ".");
            }
            if (deleteKeys)
            {
                DeleteDirectory(Directory.GetParent(CertificateFile).ToString());
            }
        }
    }
}
