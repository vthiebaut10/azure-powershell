### Example 1: Create a new Kusto cluster
```powershell
New-AzKustoCluster -ResourceGroupName testrg -Name testnewkustocluster -Location 'East US' -SkuName Standard_D11_v2 -SkuTier Standard -EnableDoubleEncryption -EngineType 'V2'
```

```output
Location Name                Type                     Zone
-------- ----                ----                     ----
East US  testnewkustocluster Microsoft.Kusto/Clusters
```

The above command creates a new Kusto cluster named "testnewkustocluster" in the resource group "testrg".
