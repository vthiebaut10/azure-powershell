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
using Microsoft.Azure.Commands.Common.Exceptions;
using System.Diagnostics;
using System.Collections.Generic;


namespace Microsoft.Azure.Commands.Ssh
{
    [Cmdlet(
        VerbsCommon.Enter,
        ResourceManager.Common.AzureRMConstants.AzureRMPrefix + "VM",
        DefaultParameterSetName = InteractiveParameterSet)]
    [OutputType(typeof(bool))]
    [Alias("Enter-AzArcServer")]
    public class EnterAzVMCommand : SshBaseCmdlet
    {
        #region Supress Export-AzSshConfig Parameters

        public override string ConfigFilePath
        { 
            get { return null; } 
        }
        public override SwitchParameter Overwrite
        {
            get { return false; }
        }

        public override string KeysDestinationFolder
        {
            get { return null; }
        }
        
        #endregion
      
        public override void ExecuteCmdlet()
        {
            base.ExecuteCmdlet();

            BeforeExecution();

            ProgressRecord record = new ProgressRecord(0, "Prepare for starting SSH connection", "Start Preparing");
            UpdateProgressBar(record, "Start preparing", 0);

            if (!IsArc() && !ParameterSetName.Equals(IpAddressParameterSet))
            {
                GetVmIpAddress();
                UpdateProgressBar(record, "Retrieved the IP address of the target VM", 50);
            }
            if (IsArc())
            {
                proxyPath = GetClientSideProxy();
                UpdateProgressBar(record, "Dowloaded SSH Proxy, saved to " + proxyPath, 25);
                GetRelayInformation();
                UpdateProgressBar(record, "Retrieved Relay Information" + proxyPath, 50);
            }
            try
            {
                if (LocalUser == null)
                {
                    PrepareAadCredentials();
                }
                
                record.RecordType = ProgressRecordType.Completed;
                UpdateProgressBar(record, "Ready to start SSH connection.", 100);

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

        #region Private Methods

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
            // Process is not accepting ArgumentList instead of Arguments. .NET framework too old?
            string command = GetHost() + " " + BuildArgs();

            Process sshProcess = new Process();
            WriteDebug("Running SSH command: " + sshClient + " " + command);

            if (IsArc())
                sshProcess.StartInfo.EnvironmentVariables["SSHPROXY_RELAY_INFO"] = relayInfo;
            sshProcess.StartInfo.FileName = sshClient;
            sshProcess.StartInfo.Arguments = command;
            sshProcess.StartInfo.RedirectStandardError = true;
            sshProcess.StartInfo.UseShellExecute = false;
            sshProcess.Start();

            bool writeLogs = false;
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
                if (writeLogs || (!line.Contains("debug1: ") && !line.Contains("debug2: ") && !line.Contains("debug3: ")))
                {
                    // We have the option of filtering out some of the logs that we don't want printed here.
                    // Console.Error.WriteLine(line);
                    // Logs are written to StdErr on OpenSSH 
                    Host.UI.WriteLine(line);
                } 
                if (line.Contains("debug1: Entering interactive session."))
                {
                    DoCleanup();
                }
                //check for well known errors: azcmagent config not set to listen to port 22, OpenSSH too old error
            }
        
            sshProcess.WaitForExit();

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
            
            if (SshArguments == null ||
               (!Array.Exists(SshArguments, x => x == "-v") &&
                !Array.Exists(SshArguments, x => x == "-vv") &&
                !Array.Exists(SshArguments, x => x == "-vvv")))
            {
                if (IsDebugMode()) 
                    argList.Add("-vvv");
                else
                    argList.Add("-v");
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

        #endregion
    }
}
