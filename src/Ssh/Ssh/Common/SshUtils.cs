using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.IO;
using Microsoft.Azure.Commands.Common.Exceptions;


namespace Microsoft.Azure.Commands.Ssh
{
    public class SshUtils
    {
        // make these public properties so that they are inherited
        /*private string vmName;
        private string rgName;
        private string ip;
        private string publicKeyFile;
        private string privateKeyFile;
        private string username;
        private string certificateFile;
        private string port;
        private bool usePrivateIp;
        private string credentialsFolder;
        private string proxyFolder;
        private string resourceType;


        public void DoOperation()
        {
            bool deleteKeys = false;
            bool deleteCert = false;
            string proxyPath = null;
            string relayInfo = null;
            int certLifetimeInMinutes = 3600;
           
            if (username == null)
            {
                deleteCert = true;
                deleteKeys = CheckOrCreatePublicAndPrivateKeyFile(ref publicKeyFile, ref privateKeyFile, credentialsFolder);

                certificateFile = GetAndWriteCertificate(ref username);
                if (resourceType == "Microsoft.HybridCompute")
                {
                    certLifetimeInMinutes = 3600;
                }
            }

            if (resourceType == "Microsoft.HybridCompute")
            {
                proxyPath = GetClientSideProxy();
                relayInfo = GetRelayInformation(certLifetimeInMinutes);
            }
            else if (ip == null)
            {
                ip = GetSSHIp(); 
            }


        }

        private string GetSSHIp()
        {
            return "ip address";
        }

        private string GetRelayInformation(int certificateLifetime)
        {
            return "This will call ssh services";
        }

        private string GetClientSideProxy()
        {
            return "C:\\Users\\vthiebaut\\.clientsshproxy\\sshProxy_windows_amd64_1_3_017634.exe";
        }

        private string GetAndWriteCertificate(ref string username)
        {
            return "C:\\Users\vthiebaut\\.ssh\\id_rsa.pub-aadcert.pub";
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

        public void CreateSSHKeyfile(string privateKeyFile)
        {
            string args = "-f " + privateKeyFile + " -t rsa -q -N \" \"";
            Process keygen = Process.Start(this.GetSSHClientPath("ssh-keygen"), args);
            keygen.WaitForExit();
        }
        */
    }

    public class ConnectionUtils : SshUtils
    {
        //Class that implements interactive ssh session
        // Do ssh connection
        // Do cleanup
    }

    public class ConfigUtils : SshUtils
    {
        //class that implements creation of config file
    }
}
