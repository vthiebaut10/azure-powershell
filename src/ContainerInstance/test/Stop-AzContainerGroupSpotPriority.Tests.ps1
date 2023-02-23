$loadEnvPath = Join-Path $PSScriptRoot 'loadEnv.ps1'
if (-Not (Test-Path -Path $loadEnvPath)) {
    $loadEnvPath = Join-Path $PSScriptRoot '..\loadEnv.ps1'
}
. ($loadEnvPath)
$TestRecordingFile = Join-Path $PSScriptRoot 'Stop-AzContainerGroupSpotContainer.Recording.json'
$currentPath = $PSScriptRoot
while(-not $mockingPath) {
    $mockingPath = Get-ChildItem -Path $currentPath -Recurse -Include 'HttpPipelineMocking.ps1' -File
    $currentPath = Split-Path -Path $currentPath -Parent
}
. ($mockingPath | Select-Object -First 1).FullName

Describe 'Stop-AzContainerGroupSpotContainer' {
    It 'Stop' {
        Stop-AzContainerGroup -Name $env.spotContainerGroupName -ResourceGroupName $env.resourceGroupName
    }

    It 'StopViaIdentity' {
        $stop = Get-AzContainerGroup -ResourceGroupName $env.resourceGroupName -Name $env.spotContainerGroupName 
        Stop-AzContainerGroup -InputObject $stop
    }
}
