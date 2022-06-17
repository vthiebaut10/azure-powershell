// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.PowerShell.Cmdlets.Cdn.Support
{

    /// <summary>Describes operator to be matched</summary>
    [System.ComponentModel.TypeConverter(typeof(Microsoft.Azure.PowerShell.Cmdlets.Cdn.Support.ClientPortOperatorTypeConverter))]
    public partial struct ClientPortOperator :
        System.Management.Automation.IArgumentCompleter
    {

        /// <summary>
        /// Implementations of this function are called by PowerShell to complete arguments.
        /// </summary>
        /// <param name="commandName">The name of the command that needs argument completion.</param>
        /// <param name="parameterName">The name of the parameter that needs argument completion.</param>
        /// <param name="wordToComplete">The (possibly empty) word being completed.</param>
        /// <param name="commandAst">The command ast in case it is needed for completion.</param>
        /// <param name="fakeBoundParameters">This parameter is similar to $PSBoundParameters, except that sometimes PowerShell cannot
        /// or will not attempt to evaluate an argument, in which case you may need to use commandAst.</param>
        /// <returns>
        /// A collection of completion results, most like with ResultType set to ParameterValue.
        /// </returns>
        public global::System.Collections.Generic.IEnumerable<global::System.Management.Automation.CompletionResult> CompleteArgument(global::System.String commandName, global::System.String parameterName, global::System.String wordToComplete, global::System.Management.Automation.Language.CommandAst commandAst, global::System.Collections.IDictionary fakeBoundParameters)
        {
            if (global::System.String.IsNullOrEmpty(wordToComplete) || "Any".StartsWith(wordToComplete, global::System.StringComparison.InvariantCultureIgnoreCase))
            {
                yield return new global::System.Management.Automation.CompletionResult("'Any'", "Any", global::System.Management.Automation.CompletionResultType.ParameterValue, "Any");
            }
            if (global::System.String.IsNullOrEmpty(wordToComplete) || "Equal".StartsWith(wordToComplete, global::System.StringComparison.InvariantCultureIgnoreCase))
            {
                yield return new global::System.Management.Automation.CompletionResult("'Equal'", "Equal", global::System.Management.Automation.CompletionResultType.ParameterValue, "Equal");
            }
            if (global::System.String.IsNullOrEmpty(wordToComplete) || "Contains".StartsWith(wordToComplete, global::System.StringComparison.InvariantCultureIgnoreCase))
            {
                yield return new global::System.Management.Automation.CompletionResult("'Contains'", "Contains", global::System.Management.Automation.CompletionResultType.ParameterValue, "Contains");
            }
            if (global::System.String.IsNullOrEmpty(wordToComplete) || "BeginsWith".StartsWith(wordToComplete, global::System.StringComparison.InvariantCultureIgnoreCase))
            {
                yield return new global::System.Management.Automation.CompletionResult("'BeginsWith'", "BeginsWith", global::System.Management.Automation.CompletionResultType.ParameterValue, "BeginsWith");
            }
            if (global::System.String.IsNullOrEmpty(wordToComplete) || "EndsWith".StartsWith(wordToComplete, global::System.StringComparison.InvariantCultureIgnoreCase))
            {
                yield return new global::System.Management.Automation.CompletionResult("'EndsWith'", "EndsWith", global::System.Management.Automation.CompletionResultType.ParameterValue, "EndsWith");
            }
            if (global::System.String.IsNullOrEmpty(wordToComplete) || "LessThan".StartsWith(wordToComplete, global::System.StringComparison.InvariantCultureIgnoreCase))
            {
                yield return new global::System.Management.Automation.CompletionResult("'LessThan'", "LessThan", global::System.Management.Automation.CompletionResultType.ParameterValue, "LessThan");
            }
            if (global::System.String.IsNullOrEmpty(wordToComplete) || "LessThanOrEqual".StartsWith(wordToComplete, global::System.StringComparison.InvariantCultureIgnoreCase))
            {
                yield return new global::System.Management.Automation.CompletionResult("'LessThanOrEqual'", "LessThanOrEqual", global::System.Management.Automation.CompletionResultType.ParameterValue, "LessThanOrEqual");
            }
            if (global::System.String.IsNullOrEmpty(wordToComplete) || "GreaterThan".StartsWith(wordToComplete, global::System.StringComparison.InvariantCultureIgnoreCase))
            {
                yield return new global::System.Management.Automation.CompletionResult("'GreaterThan'", "GreaterThan", global::System.Management.Automation.CompletionResultType.ParameterValue, "GreaterThan");
            }
            if (global::System.String.IsNullOrEmpty(wordToComplete) || "GreaterThanOrEqual".StartsWith(wordToComplete, global::System.StringComparison.InvariantCultureIgnoreCase))
            {
                yield return new global::System.Management.Automation.CompletionResult("'GreaterThanOrEqual'", "GreaterThanOrEqual", global::System.Management.Automation.CompletionResultType.ParameterValue, "GreaterThanOrEqual");
            }
            if (global::System.String.IsNullOrEmpty(wordToComplete) || "RegEx".StartsWith(wordToComplete, global::System.StringComparison.InvariantCultureIgnoreCase))
            {
                yield return new global::System.Management.Automation.CompletionResult("'RegEx'", "RegEx", global::System.Management.Automation.CompletionResultType.ParameterValue, "RegEx");
            }
        }
    }
}