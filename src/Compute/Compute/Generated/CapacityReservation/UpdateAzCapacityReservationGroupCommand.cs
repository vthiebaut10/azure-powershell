﻿
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using Microsoft.Azure.Commands.Compute.Automation.Models;
using Microsoft.Azure.Commands.Compute.Models;
using Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters;
using Microsoft.Azure.Management.Compute;
using Microsoft.Azure.Management.Compute.Models;
using Microsoft.WindowsAzure.Commands.Utilities.Common;

namespace Microsoft.Azure.Commands.Compute.Automation
{
    [Cmdlet(VerbsData.Update, ResourceManager.Common.AzureRMConstants.AzureRMPrefix + "CapacityReservationGroup", DefaultParameterSetName = "DefaultParameter", SupportsShouldProcess = true)]
    [OutputType(typeof(PSCapacityReservationGroup))]
    public class UpdateAzureCapacityReservationGroup : ComputeAutomationBaseCmdlet
    {

        private const string DefaultParameterSet = "DefaultParameterSet";
        private const string InputObjectParameterSet = "InputObjectParameterSet";
        private const string ResourceIDParameterSet = "ResourceIDParameterSet";

        [Parameter(
            Mandatory = true,
            ParameterSetName = DefaultParameterSet,
            ValueFromPipelineByPropertyName = true)]
        [ResourceGroupCompleter]
        public string ResourceGroupName { get; set; }

        [Parameter(
            Mandatory = true,
            ParameterSetName = DefaultParameterSet,
            ValueFromPipelineByPropertyName = true)]
        [Alias("CapacityReservationGroupName")]
        [ResourceNameCompleter("Microsoft.Compute/capacityReservationGroups", "ResourceGroupName")]
        public string Name { get; set; }

        [Parameter(
            Mandatory = true,
            ParameterSetName = InputObjectParameterSet,
            ValueFromPipelineByPropertyName = true,
            ValueFromPipeline = true,
            HelpMessage = "PSCapacityReservationGroup object to update.")]
        [ResourceGroupCompleter]
        public PSCapacityReservationGroup CapacityReservationGroup { get; set; }

        [Parameter(
           Mandatory = true,
           ParameterSetName = ResourceIDParameterSet,
           ValueFromPipelineByPropertyName = true,
           HelpMessage = "Resource ID for your Capacity Reservation Group.")]
        [ResourceIdCompleter("Microsoft.Compute/capacityReservationGroups")]
        public string ResourceId { get; set; }

        [Parameter(Mandatory = false,
            HelpMessage = "Run cmdlet in the background")]
        public SwitchParameter AsJob { get; set; }

        [Parameter(
            Mandatory = false,
            ValueFromPipelineByPropertyName = true)]
        public Hashtable Tag { get; set; }

        public override void ExecuteCmdlet()
        {
            base.ExecuteCmdlet();
            ExecuteClientAction(() =>
            {
                string resourceGroupName;
                string name;

                switch (this.ParameterSetName)
                {
                    case ResourceIDParameterSet:
                        resourceGroupName = GetResourceGroupName(this.ResourceId);
                        name = GetResourceName(this.ResourceId, "Microsoft.Compute/capacityReservationGroups");
                        break;
                    case InputObjectParameterSet:
                        resourceGroupName = GetResourceGroupName(this.CapacityReservationGroup.Id);
                        name = GetResourceName(this.CapacityReservationGroup.Id, "Microsoft.Compute/capacityReservationGroups");
                        break;
                    default:
                        resourceGroupName = this.ResourceGroupName;
                        name = this.Name;
                        break;
                }

                CapacityReservationGroup result;

                if (this.IsParameterBound(c => c.Tag))
                {
                    var tags = this.Tag.Cast<DictionaryEntry>().ToDictionary(ht => (string)ht.Key, ht => (string)ht.Value);
                    result = CapacityReservationGroupClient.Update(resourceGroupName, name, tags);
                }
                else
                {
                    result = CapacityReservationGroupClient.Update(resourceGroupName, name);
                }

                var psObject = new PSCapacityReservationGroup();
                ComputeAutomationAutoMapperProfile.Mapper.Map<CapacityReservationGroup, PSCapacityReservationGroup>(result, psObject);
                WriteObject(psObject);
            });
        }
    }
}
