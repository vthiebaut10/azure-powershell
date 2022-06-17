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
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.Azure.Commands.Ssh
{
    [Cmdlet("Enter", "AzureVM")]
    public class EnterAzVMCommand : SshBaseCmdlet
    {
        [Parameter(
            ParameterSetName = "NameAndRG",
            Mandatory = true,
            ValueFromPipelineByPropertyName = true)]
        [ResourceGroupCompleter]
        [ValidateNotNullOrEmpty]
        public string ResourceGroupName { get; set; }

        [Parameter(
            ParameterSetName = "NameAndRG",
            Mandatory = true,
            ValueFromPipeline = true)]
        // Can I have this for both AzureVMs and Arc machines?? 
        //[ResourceNameCompleter("Microsoft.Compute/virtualMachines", "ResourceGroupName")]
        [ValidateNotNullOrEmpty]
        public string Name { get; set; }

        [Parameter(
            ParameterSetName = "IpAddress",
            Mandatory = true,
            ValueFromPipeline = true)]
        [ValidateNotNullOrEmpty]
        public string Ip { get; set; }

        [Parameter(ParameterSetName = "NameAndRG")]
        [Parameter(ParameterSetName = "IpAddress")]
        [ValidateNotNullOrEmpty]
        public string PublicKeyFile { get; set; }

        [Parameter(ParameterSetName = "NameAndRG")]
        [Parameter(ParameterSetName = "IpAddress")]
        [ValidateNotNullOrEmpty]
        public string PrivateKeyFile { get; set; }

        [Parameter(ParameterSetName = "NameAndRG")]
        [ValidateNotNullOrEmpty]
        public SwitchParameter UsePrivateIP { get; set; }

        [Parameter(ParameterSetName = "NameAndRG")]
        [Parameter(ParameterSetName = "IpAddress")]
        [ValidateNotNullOrEmpty]
        public string LocalUser { get; set; }

        // IDEA: Only have this be an option when Local User is provided
        [Parameter(ParameterSetName = "NameAndRG")]
        [Parameter(ParameterSetName = "IpAddress")]
        [ValidateNotNullOrEmpty]
        public string CertificateFile { get; set; }

        [Parameter(ParameterSetName = "NameAndRG")]
        [Parameter(ParameterSetName = "IpAddress")]
        [ValidateNotNullOrEmpty]
        public string Port { get; set; }

        [Parameter(ParameterSetName = "NameAndRG")]
        [Parameter(ParameterSetName = "IpAddress")]
        [ValidateNotNullOrEmpty]
        public string SSHClientPath { get; set; }

        // IDEA: Only have this be an option if the cloudshell env var exists
        [Parameter(ParameterSetName = "NameAndRG")]
        [Parameter(ParameterSetName = "IpAddress")]
        [ValidateNotNullOrEmpty]
        public SwitchParameter DeleteCredentials { get; set; }

        [Parameter(ParameterSetName = "NameAndRG")]
        [ValidateSet ("Microsoft.Compute", "Microsoft.HybridCompute")]
        [ValidateNotNullOrEmpty]
        public string ResourceType { get; set; }

        // IDEA: Is there a way to only have this be an option if the target is a arc machine?
        [Parameter(ParameterSetName = "NameAndRG")]
        [ValidateNotNullOrEmpty]
        public string SSHProxyFolder { get; set; }

        // TODO: Found out how would be the best way to take these parameters
        [Parameter(ParameterSetName = "NameAndRG")]
        [Parameter(ParameterSetName = "IpAddress")]
        [ValidateNotNullOrEmpty]
        public string SSHArguments{ get; set; }


        public override void ExecuteCmdlet()
        {
            base.ExecuteCmdlet();

            string a = Track2ConnectivityManagementClient.GetRelayInformation();

            /*
            string cloudshell_envvar = "cloud-shell/1.0";

            // Can I have this be checked by a dynamic parameter?
            if (DeleteCredentials && !cloudshell_envvar.Equals(Environment.GetEnvironmentVariable("AZUREPS_HOST_ENVIRONMENT")))
            {
                throw new AzPSArgumentException("DeleteCredentials can't be used outside of CloudShell environment", nameof(DeleteCredentials));
            }

            // Can I have this be checked by a dynamic parameter?
            if (CertificateFile != null && LocalUser == null)
            {
                throw new AzPSArgumentException("CertificateFile can't be used when a Local User isn't provided", nameof(CertificateFile));
            }

            // decide resource type
            var azureUtils = new SshAzureUtils(DefaultProfile.DefaultContext);
            var resourceType = azureUtils.DecideResourceType(Name, ResourceGroupName, Ip, ResourceType);

            if (resourceType == "Microsoft.Compute" && SSHProxyFolder != null)
            {
                WriteWarning("Target machine is not an Arc Server, -SSHProxyFolder argument will be ignored.");
            }

            // call the function that pepared the credentials and stuff

            string publicKey = PublicKeyFile;
            string privateKey = PrivateKeyFile;
            string username = LocalUser;
            string certFile = CertificateFile;
            string ip = Ip;

            (bool deleteKeys, bool deleteCert, string proxyPath, string relayInfo) connectionInfo = DoOperation(Name, ResourceGroupName, ref ip, ref publicKey, ref privateKey, ref username, ref certFile, UsePrivateIP, null, SSHProxyFolder, resourceType, azureUtils);
            StartSSHConnection(connectionInfo.relayInfo, connectionInfo.proxyPath, ip, username, certFile, privateKey, publicKey, resourceType, connectionInfo.deleteKeys, connectionInfo.deleteCert);           
            */
        }

        private void StartSSHConnection(string relayInfo, string proxyPath, string ip, string username, string certFile, string privateKeyFile,
            string publicKeyFile, string resourceType, bool deleteKeys, bool deleteCert)
        {
            if (SSHClientPath == null)
            {
                SSHClientPath = GetSSHClientPath("ssh");
            }

            string args = "";
            // Figure out the args later

            string host;

            Process sshProcess = new Process();
            sshProcess.StartInfo.FileName = SSHClientPath;

            if (resourceType == "Microsoft.HybridCompute")
            {
                sshProcess.StartInfo.EnvironmentVariables["SSHPROXY_RELAY_INFO"] = relayInfo;
                sshProcess.StartInfo.UseShellExecute = false;
                
                string pcommand = "ProxyCommand=\"" + proxyPath + "\"";
                
                if (Port != null)
                {
                    pcommand = "ProxyCommand=\"" + proxyPath + " -p " + Port + "\"";
                }

                args = args + "-o " + pcommand + " " + BuildArgs(certFile, privateKeyFile, null);
                host = GetHost(username, Name);
            }
            else
            {
                host = GetHost(username, ip);
                args = BuildArgs(certFile, privateKeyFile, Port);
            }

            if (certFile == null && privateKeyFile == null) { DeleteCredentials = false;  }

            //start cleanup
            (string logFile, string logArgs, Task cleanupTask, CancellationTokenSource tokenSource) cleanupVariables = 
                StartCleanup(certFile, privateKeyFile, publicKeyFile, deleteKeys || DeleteCredentials, deleteCert || DeleteCredentials);

            Console.WriteLine(Thread.CurrentThread.Name);

            string command = host + " " + cleanupVariables.logArgs + " " + args;
            sshProcess.StartInfo.Arguments = command;

            WriteDebug("Running SSH command: " + SSHClientPath + " " + command);

            sshProcess.Start();
            sshProcess.WaitForExit();

            TerminateCleanup(deleteKeys, deleteCert, cleanupVariables.cleanupTask, cleanupVariables.tokenSource, certFile, privateKeyFile, publicKeyFile, cleanupVariables.logFile);
        }


        private (string, string, Task, CancellationTokenSource) StartCleanup (string certFile, string privKeyFile, string pubKeyFile, bool deleteKeys, bool deleteCert)
        {
            string logFile = null;
            string args = "";
            Task cleanupTask = null;
            CancellationTokenSource tokenSource = null;

            if (deleteKeys || DeleteCredentials || deleteCert)
            {
                //check if -vvv or -E is preset in the args list. We are not dealing with that now
                string logDir = null;
                if (certFile != null) { logDir = Path.GetDirectoryName(certFile);  }
                else { logDir = Path.GetDirectoryName(privKeyFile); }

                string logFileName = "ssh_client_log_" + Process.GetCurrentProcess().Id;
                logFile = Path.Combine(logDir, logFileName);

                args = "-E " + logFile + " -v";

                tokenSource = new CancellationTokenSource();
                CancellationToken token = tokenSource.Token;

                cleanupTask = new Task(() => DoCleanup(deleteKeys, deleteCert, certFile, privKeyFile, pubKeyFile, token, logFile, true));
                cleanupTask.Start();
            }

            return (logFile, args, cleanupTask, tokenSource);
        }

        private void DoCleanup(bool deleteKeys, bool deleteCert, string certFile, string privateKey, string publicKey, CancellationToken token, string logFile = null, bool wait = false)
        {
            Console.WriteLine(Thread.CurrentThread.Name);

            if (logFile != null)
            {
                bool match = false;
                DateTime startTime = DateTime.UtcNow;
                TimeSpan waitDuration = TimeSpan.FromMinutes(2);

                while (!match && DateTime.UtcNow - startTime < waitDuration)
                {
                    if (token != null) { token.ThrowIfCancellationRequested();  }
                    Thread.Sleep(1000);
                    try
                    {
                        string log = File.ReadAllText(logFile);
                        match = log.Contains("debug1: Authentication succeeded");
                    }
                    catch
                    {
                        if (token != null) { token.ThrowIfCancellationRequested(); }
                        Thread.Sleep(500);
                    }
                }
            }
            else if (wait)
            {
                DateTime startTime = DateTime.UtcNow;
                TimeSpan waitDuration = TimeSpan.FromMinutes(2);
                while (DateTime.UtcNow - startTime < waitDuration)
                {
                    if (token != null) { token.ThrowIfCancellationRequested(); }
                    Thread.Sleep(2000);
                }
            }

            if (deleteKeys && privateKey != null)
            {
                DeleteFile(privateKey, "Couldn't delete Private Key file " + privateKey + ".");
            }
            if (deleteKeys && publicKey != null)
            {
                DeleteFile(publicKey, "Couldn't delete Public Key file " + publicKey + ".");
            }
            if (deleteCert && certFile != null)
            {
                DeleteFile(certFile, "Couldn't delete Certificate File " + certFile + ".");
            }

        }

        private void TerminateCleanup(bool deleteKeys, bool deleteCert, Task cleanupTask, CancellationTokenSource tokenSource, string certFile, string privateKey, string publicKey, string logFile)
        {
            if (deleteKeys || deleteCert)
            {
                //check if DoCleanup thread is still alive.
                if (!cleanupTask.IsCompleted)
                {
                    Console.WriteLine("TerminateCleanup: Task not completed");
                    tokenSource.Cancel();
                    Console.WriteLine("TerminateCleanup: Is Completed? " + cleanupTask.IsCompleted);
                    DateTime startTime = DateTime.UtcNow;
                    TimeSpan waitDuration = TimeSpan.FromSeconds(30);
                    while (!cleanupTask.IsCompleted && DateTime.UtcNow - startTime < waitDuration)
                    {
                        Console.WriteLine("TerminateCleanup: Waiting for completion");
                        Thread.Sleep(1000);
                    }
                }

                // Make sure all credentials are deleted
                if (deleteKeys && privateKey != null)
                {
                    DeleteFile(privateKey, "Couldn't delete Private Key file " + privateKey + ".");
                }
                if (deleteKeys && publicKey != null)
                {
                    DeleteFile(publicKey, "Couldn't delete Public Key file " + publicKey + ".");
                }
                if (deleteCert && certFile != null)
                {
                    DeleteFile(certFile, "Couldn't delete Certificate File " + certFile + ".");
                }

                //delete log file
                if (logFile != null)
                {
                    DeleteFile(logFile, "Couldn't delete Log File " + logFile + ".");
                }
                //delete credentials folder
                if (deleteKeys)
                {
                    // This is only true if keys were generated, so they must be in a temp folder.
                    string tempDir = Path.GetDirectoryName(certFile);
                    DeleteDirectory(tempDir, "Couldn't delete temporary directory " + tempDir + ".");
                }
            }
        }

        private string BuildArgs(string certFile, string privKeyFile, string port)
        {
            List<string> argList = new List<string>();

            if (privKeyFile != null) { argList.Add("-i " + privKeyFile); }

            if (certFile != null) { argList.Add("-o CertificateFile=\"" + certFile + "\""); }

            if (port != null) { argList.Add("-p " + port); }

            return string.Join(" ", argList.ToArray());
        }

        private string GetHost(string username, string target)
        {
            return username + "@" + target;
        }

    }

}