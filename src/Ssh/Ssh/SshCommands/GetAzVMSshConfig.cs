using System;
using System.IO;
using Microsoft.Azure.Commands.Ssh.Models;
using System.Management.Automation;
using Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters;
using Microsoft.Azure.Commands.Common.Exceptions;


namespace Microsoft.Azure.Commands.Ssh
{
    [Cmdlet("Get", "AzureVMSSHConfig")]
    //[OutputType(typeof(PSSshConfigEntry))]
    public class GetAzVMSshConfig : SshBaseCmdlet
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
        [ValidateNotNullOrEmpty]
        public string Name { get; set; }

        [Parameter(
            ParameterSetName = "IpAddress",
            Mandatory = true,
            ValueFromPipeline = true)]
        [ValidateNotNullOrEmpty]
        public string Ip { get; set; }

        [Parameter(
            ParameterSetName = "NameAndRG",
            Mandatory = true)]
        [Parameter(
            ParameterSetName = "IpAddress",
            Mandatory = true)]
        [ValidateNotNullOrEmpty]
        public string ConfigFilePath { get; set; }

        [Parameter(ParameterSetName = "NameAndRG")]
        [Parameter(ParameterSetName = "IpAddress")]
        [ValidateNotNullOrEmpty]
        public SwitchParameter Overwrite { get; set; }

        [Parameter(ParameterSetName = "NameAndRG")]
        [Parameter(ParameterSetName = "IpAddress")]
        [ValidateNotNullOrEmpty]
        public string KeysDestinationFolder { get; set; }

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
        [ValidateSet("Microsoft.Compute", "Microsoft.HybridCompute")]
        [ValidateNotNullOrEmpty]
        public string ResourceType { get; set; }

        // IDEA: Is there a way to only have this be an option if the target is a arc machine?
        [Parameter(ParameterSetName = "NameAndRG")]
        [ValidateNotNullOrEmpty]
        public string SSHProxyFolder { get; set; }

        public override void ExecuteCmdlet()
        {
            base.ExecuteCmdlet();

            // Can I have this be checked by a dynamic parameter?
            if (CertificateFile != null && LocalUser == null)
            {
                throw new AzPSArgumentException("CertificateFile can't be used when a Local User isn't provided", nameof(CertificateFile));
            }

            if ((PublicKeyFile != null || PrivateKeyFile != null) && KeysDestinationFolder != null)
            {
                throw new AzPSArgumentException("-KeysDestinationFolder can't be used in conjunction with -PublicKeyFile or -PrivateKeyFile", nameof(KeysDestinationFolder));
            }

            string absConfigPath = Path.GetFullPath(ConfigFilePath);

            if (KeysDestinationFolder == null)
            {
                string configFolder = Path.GetDirectoryName(absConfigPath);
                if (!Directory.Exists(configFolder))
                {
                    throw new AzPSArgumentException("Config file destination folder " + configFolder + " does not exist.", nameof(ConfigFilePath));
                }
                string keysFolderName = Ip;
                if (ResourceGroupName != null && Name != null)
                {
                    keysFolderName = ResourceGroupName + "-" + Name;
                }

                KeysDestinationFolder = Path.Combine(configFolder, "az_ssh_config", keysFolderName);
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

            (bool deleteKeys, bool deleteCert, string proxyPath, string relayInfo) connectionInfo = 
                DoOperation(Name, ResourceGroupName, ref ip, ref publicKey, ref privateKey, ref username,
                ref certFile, UsePrivateIP, KeysDestinationFolder, SSHProxyFolder, resourceType, azureUtils);

            //create relay info
            string relayInfoPath = @"C:\relay";

            PSSshConfigEntry entry = 
                new PSSshConfigEntry(ip, Name, ResourceGroupName, connectionInfo.proxyPath, relayInfoPath,
                username, certFile, privateKey, Port, resourceType);

            File.WriteAllText(ConfigFilePath, entry.ConfigString);
        }
    }
}
