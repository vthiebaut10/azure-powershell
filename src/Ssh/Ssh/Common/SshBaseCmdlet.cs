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
using System.Management.Automation;
using Microsoft.WindowsAzure.Commands.Utilities.Common;
using Microsoft.Azure.Commands.Common.Authentication;
using Microsoft.Azure.Commands.Common.Authentication.ResourceManager;
using System.Text.RegularExpressions;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using System;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Net;
using Microsoft.Azure.Commands.Common.Exceptions;
using System.Collections.Generic;
using Microsoft.Azure.Commands.Common.Authentication.Abstractions;
using Microsoft.Azure.Commands.Common.Authentication.Factories;
using Microsoft.Azure.Commands.Common.Authentication.Abstractions.Models;

namespace Microsoft.Azure.Commands.Ssh
{
    public abstract class SshBaseCmdlet : AzureRMCmdlet
    {
        public const string clientProxyStorageUrl = "https://sshproxysa.blob.core.windows.net";
        public const string clientProxyRelease = "release01-11-21";
        public const string clientProxyVersion = "1.3.017634";

        public const string InteractiveParameterSet = "Interactive";
        public const string ResourceIdParameterSet = "ResourceId";
        public const string IpAddressParameterSet = "IpAddress";

        public enum SupportedResourceTypes { ComputeVirtualMachine, ArcEnabledServer };

        public static readonly string [] supportedResourceTypes = {"Microsoft.Compute/virtualMachines", "Microsoft.HybridCompute/machines" };
        
        protected bool deleteKeys;
        protected bool deleteCert;
        
        public string proxyPath;
        public string relayInfo;
        public string aadCertificate;
        protected SendCertParameter certificateDynamicParameter;
        
        public string CertificateFile
        {
            get
            {
                if (certificateDynamicParameter != null)
                { 
                    return certificateDynamicParameter.CertificateFile;
                }
                return aadCertificate;
            }
            set { aadCertificate = value; }
        }

        /* Common Parameters */
        public abstract string Name { get; set; }
        public abstract string ResourceGroupName { get; set; }
        public abstract string Ip { get; set; }
        public abstract string ResourceId { get; set; }
        public abstract string LocalUser { get; set; }
        public abstract string PublicKeyFile { get; set; }
        public abstract string PrivateKeyFile { get; set; }
        public abstract SwitchParameter UsePrivateIp { get; set; }
        public abstract string Port { get; set; }
        public abstract string SshClientFolder { get; set; }
        public abstract string ResourceType { get; set; }
        public abstract string SshProxyFolder { get; set; }

        private RMProfileClient profileClient;
        private SshAzureUtils azureUtils;

        public SshAzureUtils AzureUtils
        {
            get
            {
                if (azureUtils == null)
                {
                    azureUtils = new SshAzureUtils(DefaultProfile.DefaultContext);
                }

                return azureUtils;
            }

            set { azureUtils = value; }
        }

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

        public  void GetVmIpAddress()
        {
            Ip = AzureUtils.GetFirstPublicIp(Name, ResourceGroupName);
            if (Ip == null)
            {
                string errorMessage = "Couldn't determine the IP address of " + Name + "in the Resource Group " + ResourceGroupName;
                throw new AzPSResourceNotFoundCloudException(errorMessage);
            }
        }

        public void PrepareAadCredentials(string credentialFolder = null)
        {
            deleteCert = true;
            deleteKeys = CheckOrCreatePublicAndPrivateKeyFile(credentialFolder);
            CertificateFile = GetAndWriteCertificate(PublicKeyFile);
            LocalUser = GetSSHCertPrincipals(aadCertificate)[0];
        }

        private string GetAndWriteCertificate(string publicKeyFile)
        {
            SshCredential certificate = GetAccessToken(publicKeyFile);
            string token = certificate.Credential;
            string keyDir = Path.GetDirectoryName(publicKeyFile);
            string certpath = Path.Combine(keyDir, "id_rsa.pub-aadcert.pub");
            string cert_contents = "ssh-rsa-cert-v01@openssh.com " + token;

            File.WriteAllText(certpath, cert_contents);

            return certpath;
        }

        private SshCredential GetAccessToken(string publicKeyFile)
        {
            string publicKeyText = File.ReadAllText(publicKeyFile);
            RSAParser parser = new RSAParser(publicKeyText);
            var context = DefaultProfile.DefaultContext;
            RSAParameters parameters = new RSAParameters
            {
                Exponent = Base64UrlHelper.DecodeToBytes(parser.Exponent),
                Modulus = Base64UrlHelper.DecodeToBytes(parser.Modulus)
            };
            ISshCredentialFactory factory = new SshCredentialFactory();
            AzureSession.Instance.TryGetComponent<ISshCredentialFactory>(nameof(ISshCredentialFactory), out factory);
            var token = factory.GetSshCredential(context, parameters);
            return token;
        }

        private List<string> GetSSHCertPrincipals(string certFile)
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

        private string[] GetSSHCertInfo(string certFile)
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

        protected string GetCertificateExpirationTimes()
        {
            string[] certificateInfo = GetSSHCertInfo(this.CertificateFile);
            foreach (string line in certificateInfo)
            {
                if (line.Contains("Valid:"))
                {
                    var validity = Regex.Split(line.Trim().Replace("Valid: from ", ""), " to ");
                    DateTime endDate = DateTime.Parse(validity[1]);
                    return endDate.ToString();
                }
                
            }
            return null;
        }

        protected void WriteInColor(string toWrite, ConsoleColor color)
        {
            Console.ForegroundColor = color;
            Console.WriteLine(toWrite, Console.ForegroundColor);
            Console.ResetColor();
        }

        private bool CheckOrCreatePublicAndPrivateKeyFile(string credentialFolder=null)
        {
            bool deleteKeys = false;
            if (PublicKeyFile == null && PrivateKeyFile == null)
            {
                deleteKeys = true;
                if (credentialFolder == null)
                {
                    credentialFolder = CreateTempFolder();
                }
                else
                {
                    //create all directories in the path unless they already exist
                    Directory.CreateDirectory(credentialFolder);
                }

                PublicKeyFile = Path.Combine(credentialFolder, "id_rsa.pub");
                PrivateKeyFile = Path.Combine(credentialFolder, "id_rsa");
                CreateSSHKeyfile(PrivateKeyFile);
            }

            if (PublicKeyFile == null)
            {
                if (PrivateKeyFile != null)
                {
                    PublicKeyFile = PrivateKeyFile + ".pub";
                }
                else
                {
                    throw new AzPSArgumentNullException("Public key file not specified.", "PublicKeyFile");
                }
            }

            if (!File.Exists(PublicKeyFile))
            {
                throw new AzPSFileNotFoundException("Public key file not found", PublicKeyFile);
            }

            // The private key is not required as the user may be using a keypair stored in ssh-agent
            if (PrivateKeyFile != null && !File.Exists(PrivateKeyFile))
            {
                throw new AzPSFileNotFoundException("Private key file not found", PrivateKeyFile);
            }

            return deleteKeys;
        }

        private void CreateSSHKeyfile(string privateKeyFile)
        {
            string args = "-f " + privateKeyFile + " -t rsa -q -N \"\"";
            Process keygen = Process.Start(GetSSHClientPath("ssh-keygen"), args);
            keygen.WaitForExit();
        }

        protected string GetSSHClientPath(string sshCommand)
        {
            string sshPath;
            string commandExecutable = sshCommand;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                commandExecutable += ".exe";
            }
            if (SshClientFolder != null)
            {
                sshPath = Path.Combine(SshClientFolder, commandExecutable);
                if (File.Exists(sshPath))
                {
                    WriteDebug("Attempting to run " + commandExecutable + " from path " + sshPath + ".");
                    return sshPath;
                }
                WriteWarning("Could not find " + sshPath + ". " + "Attempting to get pre-installed OpenSSH bits.");
            }

            sshPath = commandExecutable;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                string systemDir = Environment.SystemDirectory;
                sshPath = Path.Combine(systemDir, "openSSH", commandExecutable);
                if (!File.Exists(sshPath))
                {
                    throw new AzPSFileNotFoundException("Couldn't find " + sshPath, sshPath);
                }
            }
            return sshPath;
        }

        public string CreateTempFolder()
        {
            //mix in some numbers as well?
            //worry about the length of the name?
            //should we be using get random filename
            string prefix = "aadsshcert";
            var dirnameBuilder = new StringBuilder();
            Random random = new Random();
            string dirname;
            do
            {
                dirnameBuilder.Clear();
                dirnameBuilder.Append(prefix);
                for (int i = 0; i < 8; i++)
                {
                    char randChar = (char)random.Next('a', 'a' + 26);
                    dirnameBuilder.Append(randChar);
                }
                dirname = Path.Combine(Path.GetTempPath(), dirnameBuilder.ToString());
            } while (Directory.Exists(dirname));

            Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), dirnameBuilder.ToString()));

            return dirname;
        }

        private string GetRelayInformation(int certLifetimeInMinutes)
        {
            return "";
        }

        public string GetClientSideProxy()
        {
            string proxyPath = null;
            string oldProxyPattern = null;
            string requestUrl = null;

            GetProxyUrlAndFilename(ref proxyPath, ref oldProxyPattern, ref requestUrl);

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

        private void GetProxyUrlAndFilename(ref string proxyPath, ref string oldProxyPattern, ref string requestUrl)
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
                throw new AzPSApplicationException("Operating System not supported.");
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
            if (SshProxyFolder == null)
            {
                proxyPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), Path.Combine(".clientsshproxy", installPath));
            }
            else
            {
                proxyPath = Path.Combine(SshProxyFolder, installPath);
            }

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

        public bool IsArc()
        {
            if (ResourceType.Equals("Microsoft.HybridCompute/machines"))
            {
                return true;
            }
            return false;
        }
    }

}

public class SendCertParameter
{
    [Parameter(ParameterSetName = "Interactive")]
    [Parameter(ParameterSetName = "IpAddress")]
    [Parameter(ParameterSetName = "ResourceId")]
    [ValidateNotNullOrEmpty]
    public string CertificateFile { get; set; }
}
