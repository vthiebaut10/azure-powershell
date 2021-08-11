# Batch Powershell Data Model Generator

This executable automatically generates the PowerShell data model classes used by the Azure Batch PowerShell cmdlets.

## Usage

```shell
dotnet run <The file path to the Microsoft.Azure.Batch.dll to operate on>
```

## Updating with new models

If the new version of the DLL contains new models, this generator will error out with a message such as "No mapping defined for type Foo". To fix this, update the `OMtoPSClassMappings` dictionary to map fully qualified model names to Powershell-friendly model names. Use the other models in the map as a guide for picking an appropriate name.

Once generation succeeds, you may delete the old models inside `azure-powershell\src\Batch\Batch\Models.Generated` and replace them with the new models from the `GeneratedFiles` directory.
