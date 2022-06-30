using System;
using System.IO;
using Microsoft.Azure.Commands.Ssh.Models;
using System.Management.Automation;
using Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters;
using Microsoft.Azure.Commands.Common.Exceptions;
using Microsoft.Azure.PowerShell.Cmdlets.Ssh.Common;

namespace Microsoft.Azure.Commands.Ssh
{   
    [Cmdlet("Create",
        ResourceManager.Common.AzureRMConstants.AzureRMPrefix + "VMSshConfig")]
    [OutputType(typeof(PSSshConfigEntry))]
    public class CreateAzVMSshConfig : SshBaseCmdlet
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

        [Parameter(
            ParameterSetName = InteractiveParameterSet,
            Mandatory = true)]
        [Parameter(
            ParameterSetName = IpAddressParameterSet,
            Mandatory = true)]
        [Parameter(
            ParameterSetName = ResourceIdParameterSet,
            Mandatory = true)]
        [ValidateNotNullOrEmpty]
        public string ConfigFilePath { get; set; }

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
        [Parameter(ParameterSetName = IpAddressParameterSet)]
        [Parameter(ParameterSetName = ResourceIdParameterSet)]
        [ValidateNotNullOrEmpty]
        public SwitchParameter Overwrite { get; set; }

        [Parameter(ParameterSetName = InteractiveParameterSet)]
        [Parameter(ParameterSetName = IpAddressParameterSet)]
        [Parameter(ParameterSetName = ResourceIdParameterSet)]
        [ValidateNotNullOrEmpty]
        public string KeysDestinationFolder { get; set; }

        [Parameter(ParameterSetName = InteractiveParameterSet)]
        [Parameter(ParameterSetName = ResourceIdParameterSet)]
        [ValidateNotNullOrEmpty]
        public override string SshProxyFolder { get; set; }

        public string RelayInfoPath { get; set; }

        public new object GetDynamicParameters()
        {
            if (LocalUser != null)
            {
                certificateDynamicParameter = new SendCertParameter();
                return certificateDynamicParameter;
            }
            return null;
        }

        public override void ExecuteCmdlet()
        {
            base.ExecuteCmdlet();

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

            // Get some help with maybe using this as a dynamic parameter
            if ((PublicKeyFile != null || PrivateKeyFile != null) && KeysDestinationFolder != null)
            {
                throw new AzPSArgumentException("-KeysDestinationFolder can't be used in conjunction with -PublicKeyFile or -PrivateKeyFile", nameof(KeysDestinationFolder));
            }

            ConfigFilePath = Path.GetFullPath(ConfigFilePath);

            if (!IsArc() && !ParameterSetName.Equals(IpAddressParameterSet))
            {
                GetVmIpAddress();
            }
            if (IsArc())
            {
                proxyPath = GetClientSideProxy();
                GetRelayInformation();
                CreateRelayInfoFile();
            }
            if (LocalUser == null)
            {
                PrepareAadCredentials(GetKeysDestinationFolder());
                WriteInColor($"Generated AAD Certificate {CertificateFile} is valid until {GetCertificateExpirationTimes()} in local time.", ConsoleColor.Green);
            }

            PSSshConfigEntry entry = 
                new PSSshConfigEntry(this);

            StreamWriter configSW = new StreamWriter(ConfigFilePath, !Overwrite);
            configSW.WriteLine(entry.ConfigString);
            configSW.Close();
        }


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
            WriteInColor($"Generated relay information file {RelayInfoPath} is valid until {relayInfoExpiration} in local time.", ConsoleColor.Green);
        }

        private string GetKeysDestinationFolder()
        {
            if (KeysDestinationFolder == null)
            {
                string configFolder = Path.GetDirectoryName(ConfigFilePath);
                if (!Directory.Exists(configFolder))
                {
                    throw new AzPSArgumentException("Config file destination folder " + configFolder + " does not exist.", nameof(ConfigFilePath));
                }
                string keysFolderName = Ip;
                if (ResourceGroupName != null && Name != null)
                {
                    keysFolderName = ResourceGroupName + "-" + Name;
                }

                return Path.Combine(configFolder, "az_ssh_config", keysFolderName);
            }
            return KeysDestinationFolder;
        }

    }
}
