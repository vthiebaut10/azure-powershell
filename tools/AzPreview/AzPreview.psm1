#
# Script module for module 'AzPreview' that is executed when 'AzPreview' is imported in a PowerShell session.
#
# Generated by: Microsoft Corporation
#
# Generated on: 06/22/2021 10:31:37
#

$PSDefaultParameterValues.Clear()
Set-StrictMode -Version Latest

function Test-DotNet
{
    try
    {
        if ((Get-PSDrive 'HKLM' -ErrorAction Ignore) -and (-not (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\' -ErrorAction Stop | Get-ItemPropertyValue -ErrorAction Stop -Name Release | Where-Object { $_ -ge 461808 })))
        {
            throw ".NET Framework versions lower than 4.7.2 are not supported in Az.  Please upgrade to .NET Framework 4.7.2 or higher."
        }
    }
    catch [System.Management.Automation.DriveNotFoundException]
    {
        Write-Verbose ".NET Framework version check failed."
    }
}

if ($true -and ($PSEdition -eq 'Desktop'))
{
    if ($PSVersionTable.PSVersion -lt [Version]'5.1')
    {
        throw "PowerShell versions lower than 5.1 are not supported in Az. Please upgrade to PowerShell 5.1 or higher."
    }

    Test-DotNet
}

if ($true -and ($PSEdition -eq 'Core'))
{
    if ($PSVersionTable.PSVersion -lt [Version]'6.2.4')
    {
        throw "Current Az version doesn't support PowerShell Core versions lower than 6.2.4. Please upgrade to PowerShell Core 6.2.4 or higher."
    }
}

if (Test-Path -Path "$PSScriptRoot\StartupScripts" -ErrorAction Ignore)
{
    Get-ChildItem "$PSScriptRoot\StartupScripts" -ErrorAction Stop | ForEach-Object {
        . $_.FullName
    }
}

if (Get-Module AzureRM.profile -ErrorAction Ignore)
{
    Write-Warning ("AzureRM.Profile already loaded. Az and AzureRM modules cannot be imported in the same session or used in the same script or runbook. If you are running PowerShell in an environment you control you can use the 'Uninstall-AzureRm' cmdlet to remove all AzureRm modules from your machine. " +
        "If you are running in Azure Automation, take care that none of your runbooks import both Az and AzureRM modules. More information can be found here: https://aka.ms/azps-migration-guide.")
    throw ("AzureRM.Profile already loaded. Az and AzureRM modules cannot be imported in the same session or used in the same script or runbook. If you are running PowerShell in an environment you control you can use the 'Uninstall-AzureRm' cmdlet to remove all AzureRm modules from your machine. " +
        "If you are running in Azure Automation, take care that none of your runbooks import both Az and AzureRM modules. More information can be found here: https://aka.ms/azps-migration-guide.")
}

$preloadPath = (Join-Path $PSScriptRoot -ChildPath "PreloadAssemblies")
if($PSEdition -eq 'Desktop' -and (Test-Path $preloadPath -ErrorAction Ignore))
{
    try
    {
        Get-ChildItem -ErrorAction Stop -Path $preloadPath -Filter "*.dll" | ForEach-Object {
            try
            {
                Add-Type -Path $_.FullName -ErrorAction Ignore | Out-Null
            }
            catch {
                Write-Verbose $_
            }
        }
    }
    catch {}
}

$netCorePath = (Join-Path $PSScriptRoot -ChildPath "NetCoreAssemblies")
if($PSEdition -eq 'Core' -and (Test-Path $netCorePath -ErrorAction Ignore))
{
    try
    {
        $loadedAssemblies = ([System.AppDomain]::CurrentDomain.GetAssemblies() | ForEach-Object {New-Object -TypeName System.Reflection.AssemblyName -ArgumentList $_.FullName} )
        Get-ChildItem -ErrorAction Stop -Path $netCorePath -Filter "*.dll" | ForEach-Object {
            $assemblyName = ([System.Reflection.AssemblyName]::GetAssemblyName($_.FullName))
            $matches = ($loadedAssemblies | Where-Object {$_.Name -eq $assemblyName.Name})
            if (-not $matches)
            {
                try
                {
                    Add-Type -Path $_.FullName -ErrorAction Ignore | Out-Null
                }
                catch {
                    Write-Verbose $_
                }
            }
        }
    }
    catch {}
}


$module = Get-Module Az.Accounts 
        if ($module -ne $null -and $module.Version -lt [System.Version]"2.4.0") 
{ 
    Write-Error "This module requires Az.Accounts version 2.4.0. An earlier version of Az.Accounts is imported in the current PowerShell session. Please open a new session before importing this module. This error could indicate that multiple incompatible versions of the Azure PowerShell cmdlets are installed on your system. Please see https://aka.ms/azps-version-error for troubleshooting information." -ErrorAction Stop 
} 
elseif ($module -eq $null) 
{ 
    Import-Module Az.Accounts -MinimumVersion 2.4.0 -Scope Global 
}
Import-Module Az.ADDomainServices -RequiredVersion 0.1.0 -Global
Import-Module Az.Advisor -RequiredVersion 1.1.1 -Global
Import-Module Az.Aks -RequiredVersion 2.1.1 -Global
Import-Module Az.AlertsManagement -RequiredVersion 0.2.0 -Global
Import-Module Az.AnalysisServices -RequiredVersion 1.1.4 -Global
Import-Module Az.ApiManagement -RequiredVersion 2.2.0 -Global
Import-Module Az.AppConfiguration -RequiredVersion 1.0.0 -Global
Import-Module Az.ApplicationInsights -RequiredVersion 1.1.1 -Global
Import-Module Az.Attestation -RequiredVersion 0.1.8 -Global
Import-Module Az.Automation -RequiredVersion 1.7.0 -Global
Import-Module Az.Batch -RequiredVersion 3.1.0 -Global
Import-Module Az.Billing -RequiredVersion 2.0.0 -Global
Import-Module Az.Blockchain -RequiredVersion 0.3.0 -Global
Import-Module Az.Blueprint -RequiredVersion 0.3.0 -Global
Import-Module Az.BotService -RequiredVersion 0.3.0 -Global
Import-Module Az.Cdn -RequiredVersion 1.7.1 -Global
Import-Module Az.CloudService -RequiredVersion 0.3.0 -Global
Import-Module Az.CognitiveServices -RequiredVersion 1.8.0 -Global
Import-Module Az.Communication -RequiredVersion 0.1.0 -Global
Import-Module Az.Compute -RequiredVersion 4.14.0 -Global
Import-Module Az.Confluent -RequiredVersion 0.1.0 -Global
Import-Module Az.ConnectedKubernetes -RequiredVersion 0.2.0 -Global
Import-Module Az.ConnectedMachine -RequiredVersion 0.2.0 -Global
Import-Module Az.ContainerInstance -RequiredVersion 2.1.0 -Global
Import-Module Az.ContainerRegistry -RequiredVersion 2.2.3 -Global
Import-Module Az.CosmosDB -RequiredVersion 1.2.0 -Global
Import-Module Az.CostManagement -RequiredVersion 0.2.0 -Global
Import-Module Az.CustomProviders -RequiredVersion 0.1.0 -Global
Import-Module Az.DataBox -RequiredVersion 0.1.1 -Global
Import-Module Az.DataBoxEdge -RequiredVersion 1.1.0 -Global
Import-Module Az.Databricks -RequiredVersion 1.1.0 -Global
Import-Module Az.DataFactory -RequiredVersion 1.12.1 -Global
Import-Module Az.DataLakeAnalytics -RequiredVersion 1.0.2 -Global
Import-Module Az.DataLakeStore -RequiredVersion 1.3.0 -Global
Import-Module Az.DataMigration -RequiredVersion 0.7.4 -Global
Import-Module Az.DataProtection -RequiredVersion 0.2.0 -Global
Import-Module Az.DataShare -RequiredVersion 1.0.0 -Global
Import-Module Az.DedicatedHsm -RequiredVersion 0.2.0 -Global
Import-Module Az.DeploymentManager -RequiredVersion 1.1.0 -Global
Import-Module Az.DesktopVirtualization -RequiredVersion 3.0.0 -Global
Import-Module Az.DeviceProvisioningServices -RequiredVersion 0.10.0 -Global
Import-Module Az.DevSpaces -RequiredVersion 0.7.3 -Global
Import-Module Az.DevTestLabs -RequiredVersion 1.0.2 -Global
Import-Module Az.DigitalTwins -RequiredVersion 0.1.0 -Global
Import-Module Az.DiskPool -RequiredVersion 0.1.1 -Global
Import-Module Az.Dns -RequiredVersion 1.1.2 -Global
Import-Module Az.EventGrid -RequiredVersion 1.3.0 -Global
Import-Module Az.EventHub -RequiredVersion 1.8.0 -Global
Import-Module Az.FrontDoor -RequiredVersion 1.8.0 -Global
Import-Module Az.Functions -RequiredVersion 3.0.0 -Global
Import-Module Az.GuestConfiguration -RequiredVersion 0.10.8 -Global
Import-Module Az.HanaOnAzure -RequiredVersion 0.3.0 -Global
Import-Module Az.HDInsight -RequiredVersion 4.3.0 -Global
Import-Module Az.HealthBot -RequiredVersion 0.1.0 -Global
Import-Module Az.HealthcareApis -RequiredVersion 1.3.1 -Global
Import-Module Az.HPCCache -RequiredVersion 0.1.1 -Global
Import-Module Az.ImageBuilder -RequiredVersion 0.2.0 -Global
Import-Module Az.ImportExport -RequiredVersion 0.1.0 -Global
Import-Module Az.IotCentral -RequiredVersion 0.9.0 -Global
Import-Module Az.IotHub -RequiredVersion 2.7.3 -Global
Import-Module Az.KeyVault -RequiredVersion 3.4.5 -Global
Import-Module Az.KubernetesConfiguration -RequiredVersion 0.4.0 -Global
Import-Module Az.Kusto -RequiredVersion 2.0.0 -Global
Import-Module Az.LogicApp -RequiredVersion 1.5.0 -Global
Import-Module Az.MachineLearning -RequiredVersion 1.1.3 -Global
Import-Module Az.Maintenance -RequiredVersion 1.1.1 -Global
Import-Module Az.ManagedServiceIdentity -RequiredVersion 0.7.3 -Global
Import-Module Az.ManagedServices -RequiredVersion 2.0.0 -Global
Import-Module Az.ManagementPartner -RequiredVersion 0.7.2 -Global
Import-Module Az.Maps -RequiredVersion 0.7.3 -Global
Import-Module Az.MariaDb -RequiredVersion 0.2.0 -Global
Import-Module Az.Marketplace -RequiredVersion 0.2.0 -Global
Import-Module Az.MarketplaceOrdering -RequiredVersion 1.0.2 -Global
Import-Module Az.Media -RequiredVersion 1.1.1 -Global
Import-Module Az.Migrate -RequiredVersion 1.0.2 -Global
Import-Module Az.MixedReality -RequiredVersion 0.1.4 -Global
Import-Module Az.Monitor -RequiredVersion 2.5.0 -Global
Import-Module Az.MonitoringSolutions -RequiredVersion 0.1.0 -Global
Import-Module Az.MySql -RequiredVersion 0.6.0 -Global
Import-Module Az.NetAppFiles -RequiredVersion 0.6.0 -Global
Import-Module Az.Network -RequiredVersion 4.9.0 -Global
Import-Module Az.NotificationHubs -RequiredVersion 1.1.1 -Global
Import-Module Az.OperationalInsights -RequiredVersion 2.3.0 -Global
Import-Module Az.Peering -RequiredVersion 0.3.0 -Global
Import-Module Az.PolicyInsights -RequiredVersion 1.4.1 -Global
Import-Module Az.Portal -RequiredVersion 0.1.0 -Global
Import-Module Az.PostgreSql -RequiredVersion 0.5.0 -Global
Import-Module Az.PowerBIEmbedded -RequiredVersion 1.1.2 -Global
Import-Module Az.PrivateDns -RequiredVersion 1.0.3 -Global
Import-Module Az.ProviderHub -RequiredVersion 0.1.0 -Global
Import-Module Az.RecoveryServices -RequiredVersion 4.2.0 -Global
Import-Module Az.RedisCache -RequiredVersion 1.4.0 -Global
Import-Module Az.RedisEnterpriseCache -RequiredVersion 1.0.0 -Global
Import-Module Az.Relay -RequiredVersion 1.0.3 -Global
Import-Module Az.Reservations -RequiredVersion 0.9.0 -Global
Import-Module Az.ResourceGraph -RequiredVersion 0.10.0 -Global
Import-Module Az.ResourceMover -RequiredVersion 1.0.0 -Global
Import-Module Az.Resources -RequiredVersion 4.2.0 -Global
Import-Module Az.Search -RequiredVersion 0.8.0 -Global
Import-Module Az.Security -RequiredVersion 0.11.0 -Global
Import-Module Az.SecurityInsights -RequiredVersion 1.0.0 -Global
Import-Module Az.ServiceBus -RequiredVersion 1.5.0 -Global
Import-Module Az.ServiceFabric -RequiredVersion 3.0.0 -Global
Import-Module Az.SignalR -RequiredVersion 1.3.0 -Global
Import-Module Az.SpringCloud -RequiredVersion 0.2.0 -Global
Import-Module Az.Sql -RequiredVersion 3.2.0 -Global
Import-Module Az.SqlVirtualMachine -RequiredVersion 1.1.0 -Global
Import-Module Az.StackEdge -RequiredVersion 0.1.0 -Global
Import-Module Az.StackHCI -RequiredVersion 0.8.0 -Global
Import-Module Az.Storage -RequiredVersion 3.8.0 -Global
Import-Module Az.StorageSync -RequiredVersion 1.5.0 -Global
Import-Module Az.StreamAnalytics -RequiredVersion 2.0.0 -Global
Import-Module Az.Subscription -RequiredVersion 0.8.0 -Global
Import-Module Az.Support -RequiredVersion 1.0.0 -Global
Import-Module Az.Synapse -RequiredVersion 0.12.0 -Global
Import-Module Az.TimeSeriesInsights -RequiredVersion 0.2.0 -Global
Import-Module Az.TrafficManager -RequiredVersion 1.0.4 -Global
Import-Module Az.VMware -RequiredVersion 0.2.0 -Global
Import-Module Az.Websites -RequiredVersion 2.7.0 -Global
Import-Module Az.WindowsIotServices -RequiredVersion 0.1.0 -Global


if (Test-Path -Path "$PSScriptRoot\PostImportScripts" -ErrorAction Ignore)
{
    Get-ChildItem "$PSScriptRoot\PostImportScripts" -ErrorAction Stop | ForEach-Object {
        . $_.FullName
    }
}

$FilteredCommands = @()

if ($Env:ACC_CLOUD -eq $null)
{
    $FilteredCommands | ForEach-Object {

        $existingDefault = $false
        foreach ($key in $global:PSDefaultParameterValues.Keys)
        {
    	    if ($_ -like "$key")
    	        {
        	    $existingDefault = $true
    	        }
	    }

        if (!$existingDefault)
        {
            $global:PSDefaultParameterValues.Add($_,
                {
                    if ((Get-Command Get-AzContext -ErrorAction Ignore) -eq $null)
                    {
                        $context = Get-AzureRmContext
                    }
                    else
                    {
                        $context = Get-AzContext
                    }
                    if (($context -ne $null) -and $context.ExtendedProperties.ContainsKey("Default Resource Group")) {
                        $context.ExtendedProperties["Default Resource Group"]
                    }
                })
        }
    }
}
