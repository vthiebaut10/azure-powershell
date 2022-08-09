using System;
using System.IO;
using Microsoft.Azure.Commands.Ssh.Models;
using System.Management.Automation;
using Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters;
using Microsoft.Azure.Commands.Common.Exceptions;
using Microsoft.Azure.PowerShell.Cmdlets.Ssh.Common;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Security.AccessControl;
using System.Text;

namespace Microsoft.Azure.Commands.Ssh
{   
    [Cmdlet("Export",
        ResourceManager.Common.AzureRMConstants.AzureRMPrefix + "SshConfig")]
    //[OutputType(typeof(PSSshConfigEntry))]
    [OutputType(typeof(bool))]
    public sealed class ExportAzSshConfig : SshBaseCmdlet
    {
        #region Supress Enter-AzVM Parameters
        public override string[] SshArguments
        {
            get
            {
                return null;
            }
        }
        #endregion

        #region Properties
        internal string RelayInfoPath { get; set; }
        #endregion

        public override void ExecuteCmdlet()
        {
            base.ExecuteCmdlet();

            BeforeExecution();

            ConfigFilePath = Path.GetFullPath(ConfigFilePath);

            ProgressRecord record = new ProgressRecord(0, "Creating SSH Config", "Start Preparing");
            UpdateProgressBar(record, "Start Preparing", 0);

            if (!IsArc() && !ParameterSetName.Equals(IpAddressParameterSet))
            {
                GetVmIpAddress();
                UpdateProgressBar(record, "Retrieved target IP address", 50);
            }
            if (IsArc())
            {
                proxyPath = GetClientSideProxy();
                UpdateProgressBar(record, "Downloaded proxy to " + proxyPath, 25);
                GetRelayInformation();
                UpdateProgressBar(record, "Completed retrieving relay information", 50);
                CreateRelayInfoFile();
                UpdateProgressBar(record, "Created file containing relay information", 65);
            }
            if (LocalUser == null)
            {
                PrepareAadCredentials(GetKeysDestinationFolder());
                UpdateProgressBar(record, "Generated Certificate File", 90);
                // This is not exactly a warning. But I couldn't make WriteInformation or WriteObject work.
                WriteWarning($"Generated AAD Certificate {CertificateFile} is valid until {GetCertificateExpirationTimes()} in local time.");
            }

            PSSshConfigEntry entry = 
                new PSSshConfigEntry(this);

            StreamWriter configSW = new StreamWriter(ConfigFilePath, !Overwrite);
            configSW.WriteLine(entry.ConfigString);
            configSW.Close();

            record.RecordType = ProgressRecordType.Completed;
            UpdateProgressBar(record, "Successfully wrote config file", 100);
        }

        #region Private Methods

        private void CreateRelayInfoFile()
        {
            string relayInfoDir = GetKeysDestinationFolder();
            Directory.CreateDirectory(relayInfoDir);

            string relayInfoFilename = ResourceGroupName + "-" + Name + "-relay_info";
            RelayInfoPath = Path.Combine(relayInfoDir, relayInfoFilename);
            DeleteFile(RelayInfoPath);
            StreamWriter relaySW = new StreamWriter(RelayInfoPath);
            relaySW.WriteLine(relayInfo);
            relaySW.Close();

            // This is not exactly a warning. But I couldn't make WriteInformation or WriteObject work.
            WriteWarning($"Generated relay information file {RelayInfoPath} is valid until {relayInfoExpiration} in local time.");
        }

        private string GetKeysDestinationFolder()
        {
            if (KeysDestinationFolder == null)
            {
                string configFolder = Path.GetDirectoryName(ConfigFilePath);
                string keysFolderName = Ip;
                if (ResourceGroupName != null && Name != null)
                {
                    keysFolderName = ResourceGroupName + "-" + Name;
                }

                if (keysFolderName.Equals("*"))
                {
                    // If the user provides -Ip *, that would not be a valid name for Windows. Treat it as a special case.
                    keysFolderName = "all_ips";
                }
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    //Make sure that the folder name doesn't have illegal characters
                    string regexString = "[" + Regex.Escape(new string(Path.GetInvalidFileNameChars())) + "]";
                    Regex containsInvalidCharacter = new Regex(regexString);
                    if (containsInvalidCharacter.IsMatch(keysFolderName))
                    {
                        throw new AzPSInvalidOperationException("Unable to create default keys destination folder. Resource contain invalid characters. Please provide -KeysDestinationFolder.");
                    }
                }

                return Path.Combine(configFolder, "az_ssh_config", keysFolderName);
            }
            return KeysDestinationFolder;
        }

        #endregion
    }
}
