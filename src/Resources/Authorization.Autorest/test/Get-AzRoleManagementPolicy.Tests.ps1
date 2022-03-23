if(($null -eq $TestName) -or ($TestName -contains 'Get-AzRoleManagementPolicy'))
{
  $loadEnvPath = Join-Path $PSScriptRoot 'loadEnv.ps1'
  if (-Not (Test-Path -Path $loadEnvPath)) {
      $loadEnvPath = Join-Path $PSScriptRoot '..\loadEnv.ps1'
  }
  . ($loadEnvPath)
  $TestRecordingFile = Join-Path $PSScriptRoot 'Get-AzRoleManagementPolicy.Recording.json'
  $currentPath = $PSScriptRoot
  while(-not $mockingPath) {
      $mockingPath = Get-ChildItem -Path $currentPath -Recurse -Include 'HttpPipelineMocking.ps1' -File
      $currentPath = Split-Path -Path $currentPath -Parent
  }
  . ($mockingPath | Select-Object -First 1).FullName
}

Describe 'Get-AzRoleManagementPolicy' {
    It 'List' {
        { 
            $scope = "/subscriptions/38ab2ccc-3747-4567-b36b-9478f5602f0d/"
            $policies = Get-AzRoleManagementPolicy -Scope $scope
        } | Should -Not -Throw
    }

    It 'Get' {
        { 
            $scope = "/subscriptions/38ab2ccc-3747-4567-b36b-9478f5602f0d/"
            $policies = Get-AzRoleManagementPolicy -Scope $scope -Name "33b520ea-3544-4abc-8565-3588deb8e68e"
        } | Should -Not -Throw
    }

    It 'GetViaIdentity' -skip {
        { throw [System.NotImplementedException] } | Should -Not -Throw
    }
}
