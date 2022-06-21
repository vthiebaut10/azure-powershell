using System;
using System.Collections.Generic;
using System.Text;
using System.Management.Automation;
using Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters;

namespace Microsoft.Azure.PowerShell.Cmdlets.Ssh.Common
{
    public class SshResourceNameCompleterAttribute : ArgumentCompleterAttribute
    {
        public SshResourceNameCompleterAttribute(string [] resourceTypes, params string [] parentResourceParameterNames): base(CreateScriptBlock(resourceTypes, parentResourceParameterNames))
        {
        }

        public static ScriptBlock CreateScriptBlock(string [] resourceTypes, string [] parentResourceNames)
        {
            string script = "param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameter)\n" +
                "$parentResources = @()\n";
            foreach (var parentResourceName in parentResourceNames)
            {
                script += String.Format("$parentResources += $fakeBoundParameter[\"{0}\"]\n", parentResourceName);
            }
            script += "$resources = @()\n";
            foreach (var resourceType in resourceTypes)
            {
                script += String.Format("$resourceType = \"{0}\"\n", resourceType) +
                "$resources = $resources + [Microsoft.Azure.Commands.ResourceManager.Common.ArgumentCompleters.ResourceNameCompleterAttribute]::FindResources($resourceType, $parentResources)\n";
            }
            script += "$resources | Where-Object { $_ -Like \"$wordToComplete*\" } | Sort-Object | ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }";
            ScriptBlock scriptBlock = ScriptBlock.Create(script);
            return scriptBlock;
        }
    }
}
