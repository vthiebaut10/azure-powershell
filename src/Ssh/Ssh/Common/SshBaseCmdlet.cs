﻿// ----------------------------------------------------------------------------------
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
using System.Management.Automation;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System;
using System.Diagnostics;
using System.Net;
using Microsoft.Azure.Commands.Common.Exceptions;
using System.Collections.Generic;

namespace Microsoft.Azure.Commands.Ssh
{
    
    public abstract class SshBaseCmdlet : AzureRMCmdlet
    {
        public const string clientProxyStorageUrl = "https://sshproxysa.blob.core.windows.net";
        public const string clientProxyRelease = "release01-11-21";
        public const string clientProxyVersion = "1.3.017634";

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

        
        public (bool, bool, string, string) DoOperation(string vmName, string rgName, ref string ip, ref string pubKeyFile, ref string privKeyFile, ref string username,
            ref string certFile, string port, bool usePrivIP, string credFolder, string proxyFolder, string resourceType, SshAzureUtils myUtils)
        {

            bool deleteKeys = false;
            bool deleteCert = false;
            string proxyPath = null;
            string relayInfo = null;
            int certLifetimeInMinutes = 3600;

            if (username == null)
            {
                deleteCert = true;
                deleteKeys = CheckOrCreatePublicAndPrivateKeyFile(ref pubKeyFile, ref privKeyFile, credFolder);

                //certFile = GetAndWriteCertificate(pubKeyFile, null);
                certFile = @"C:\Users\vthiebaut\.ssh\az_ssh_config\myRG-vthiebaut-u20\id_rsa.pub-aadcert.pub";
                username = GetSSHCertPrincipals(certFile)[0];

                if (resourceType == "Microsoft.HybridCompute")
                {
                    certLifetimeInMinutes = GetCertLifetime(certFile);
                }
            }

            if (resourceType == "Microsoft.HybridCompute")
            {
                proxyPath = GetClientSideProxy(proxyFolder);
                relayInfo = GetRelayInformation(certLifetimeInMinutes);
            }
            else if (ip == null)
            {
                ip = myUtils.GetFirstPublicIp(vmName, rgName);

                if (ip == null)
                {
                    throw new AzPSResourceNotFoundCloudException("Couldn't determine the IP address of " + vmName + "in the Resource Group " + rgName);
                }
            }

            (bool, bool, string, string) t1 = (deleteKeys, deleteCert, proxyPath, relayInfo);
            return t1;
        }

        private string GetRelayInformation(int certLifetimeInMinutes)
        {
            return "";
        }

        private int GetCertLifetime (string certFile)
        {
            return 3600;
        }

        /*private void GetModulusExponent(string publicKeyFile)
        {
            string publicKeyText = File.ReadAllText(publicKeyFile);

        }*/

        public string[] GetSSHCertInfo(string certFile)
        {
            string sshKeygenPath = GetSSHClientPath("ssh-keygen");
            string args = "-L -f " + certFile;
            WriteDebug("Runnung ssh-keygen command: " + sshKeygenPath + " " + args);
            Process keygen = new Process();
            keygen.StartInfo.FileName = sshKeygenPath;
            keygen.StartInfo.Arguments = args;
            keygen.StartInfo.UseShellExecute = false;
            keygen.StartInfo.RedirectStandardOutput = true;
            keygen.Start();
            string output = keygen.StandardOutput.ReadToEnd();
            keygen.WaitForExit();

            string[] certInfo = output.Split('\n');

            return certInfo;
        }

        public List<string> GetSSHCertPrincipals(string certFile)
        {
            string[] certInfo = GetSSHCertInfo(certFile);
            List<string> principals = new List<string>();
            bool inPrincipals = false;

            foreach (string line in certInfo)
            {
                if (line.Contains(":"))
                {
                    inPrincipals = false;
                }
                if (line.Contains("Principals: "))
                {
                    inPrincipals = true;
                    continue;
                }
                if (inPrincipals)
                {
                    principals.Add(line.Trim());
                }
            }

            return principals;

        }
        
        private string GetAndWriteCertificate(string pubKeyFile, string certFile)
        {
            string keyDir = Path.GetDirectoryName(pubKeyFile);
            return Path.Combine(keyDir, "id_rsa.pub-aadcert.pub");
        }

        public string GetClientSideProxy(string proxyFolder)
        {
            string proxyPath = null;
            string oldProxyPattern = null;
            string requestUrl = null;

            GetProxyUrlAndFilename(ref proxyPath, ref oldProxyPattern, ref requestUrl, proxyFolder);

            Console.WriteLine(requestUrl);
            Console.WriteLine(proxyPath);
            Console.WriteLine(oldProxyPattern);

            if (!File.Exists(proxyPath))
            {
                string proxyDir = Path.GetDirectoryName(proxyPath);
                Console.WriteLine(proxyDir);

                if (!Directory.Exists(proxyDir))
                {
                    Directory.CreateDirectory(proxyDir);
                }
                else
                {
                    var files = Directory.GetFiles(proxyDir, oldProxyPattern);
                    foreach (string file in files)
                    {
                        try
                        {
                            File.Delete(file);
                        }
                        catch (Exception exception)
                        {
                            WriteWarning("Couldn't delete old version of the Proxy File: " + file + ". Error: " + exception.Message);
                        }
                    }
                }

                try
                {
                    WebClient wc = new WebClient();
                    wc.DownloadFile(new Uri(requestUrl), proxyPath);
                }
                catch (Exception exception)
                {
                    string errorMessage = "Failed to download client proxy executable from " + requestUrl + ". Error: " + exception.Message;
                    throw new AzPSApplicationException(errorMessage);
                }
            }
            return proxyPath;
        }

        private void GetProxyUrlAndFilename(ref string proxyPath, ref string oldProxyPattern, ref string requestUrl, string proxyFolder)
        {
            string os;
            string architecture;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                os = "windows";
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                os = "linux";
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                os = "darwin";
            }
            else
            {
                throw new AzPSApplicationException("Operating System not supported");
            }

            if (Environment.Is64BitProcess)
            {
                architecture = "amd64";
            }
            else
            {
                architecture = "386";
            }

            string proxyName = "sshProxy_" + os + "_" + architecture;
            requestUrl = clientProxyStorageUrl + "/" + clientProxyRelease + "/" + proxyName + "_" + clientProxyVersion;

            string installPath = proxyName + "_" + clientProxyVersion.Replace('.', '_');
            oldProxyPattern = proxyName + "*";

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                requestUrl = requestUrl + ".exe";
                installPath = installPath + ".exe";
                oldProxyPattern = oldProxyPattern + ".exe";
            }
            if (proxyFolder == null)
            {
                proxyPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), Path.Combine(".clientsshproxy", installPath));
            }
            else
            {
                proxyPath = Path.Combine(proxyFolder, installPath);
            }

        }

        public void CreateSSHKeyfile(string privateKeyFile)
        {
            string args = "-f " + privateKeyFile + " -t rsa -q -N \" \"";
            Process keygen = Process.Start(GetSSHClientPath("ssh-keygen"), args);
            keygen.WaitForExit();
        }

        private bool CheckOrCreatePublicAndPrivateKeyFile(ref string publicKeyFile, ref string privateKeyFile, string credentialsFolder)
        {
            bool deleteKeys = false;

            if (publicKeyFile == null && privateKeyFile == null)
            {
                // We only want to delete generated keys.
                deleteKeys = true;

                if (credentialsFolder == null)
                {
                    // create a temp folder
                    // see about this radom name.
                    credentialsFolder = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
                    Directory.CreateDirectory(credentialsFolder);
                }
                else
                {
                    Directory.CreateDirectory(credentialsFolder);
                }

                publicKeyFile = Path.Combine(credentialsFolder, "id_rsa.pub");
                privateKeyFile = Path.Combine(credentialsFolder, "id_rsa");
                this.CreateSSHKeyfile(privateKeyFile);

            }

            if (publicKeyFile == null)
            {
                if (privateKeyFile != null)
                {
                    publicKeyFile = privateKeyFile + ".pub";
                }
                else
                {
                    throw new AzPSArgumentNullException("Public key file not specified.", "PublicKeyFile");
                }
            }

            if (!File.Exists(publicKeyFile))
            {
                throw new AzPSFileNotFoundException("Public key file not found", publicKeyFile);
            }

            // The private key is not required as the user may be using a keypair stored in ssh-agent
            if (privateKeyFile != null && !File.Exists(privateKeyFile))
            {
                throw new AzPSFileNotFoundException("Private key file not found", privateKeyFile);
            }

            return deleteKeys;
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
                    throw new AzPSFileNotFoundException("Couldn't find ssh.exe", sshPath);
                }

            }
            return sshPath;
        }

        public void DeleteFile(string fileName, string warningMessage = null)
        {
            if (File.Exists(fileName))
            {
                try
                {
                    File.Delete(fileName);
                }
                catch (Exception e)
                {
                    if (warningMessage != null)
                    {
                        WriteWarning(warningMessage + " Error: " + e.Message);
                    }
                    else
                    {
                        throw;
                    }
                }
            }
        }

        public void DeleteDirectory(string dirPath, string warningMessage = null)
        {
            if (Directory.Exists(dirPath))
            {
                try
                {
                    Directory.Delete(dirPath);
                }
                catch (Exception e)
                {
                    if (warningMessage != null)
                    {
                        WriteWarning(warningMessage + " Error: " + e.Message);
                    }
                    else
                    {
                        throw;
                    }
                }
            }
        }


        /*public string GetCertificateFileName(string publicKeyFileName)
        {
            string directoryName = Path.GetFullPath(Path.GetDirectoryName(publicKeyFileName));
            string certFileName = Path.GetFileNameWithoutExtension(publicKeyFileName) + ".cer";
            return Path.Combine(directoryName, certFileName);
        }*/


        /*public void StartSSHConnection(string username, string ip, string privateKey)
        {
            string sshPath = GetSSHClientPath("ssh");
            string target = username + "@" + ip;
            string args = target + " -i " + privateKey;

            Process myprocess = Process.Start(sshPath, args);

            myprocess.WaitForExit();
        }*/
    }

}
