﻿// ----------------------------------------------------------------------------------
//
// Copyright Microsoft Corporation
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------------

using Microsoft.Azure.Commands.ResourceManager.Common;
using Microsoft.Azure.Commands.Sql.AdvancedThreatProtection.Model;
using System.Management.Automation;

namespace Microsoft.Azure.Commands.Sql.AdvancedThreatProtection.Cmdlet
{
    /// <summary>
    /// Returns the Advanced Threat Protection settings of a specific managed instance.
    /// </summary>
    [Cmdlet("Get", AzureRMConstants.AzureRMPrefix + "SqlInstanceDatabaseAdvancedThreatProtectionSetting", SupportsShouldProcess = true), OutputType(typeof(ManagedDatabaseAdvancedThreatProtectionSettingsModel))]
    public class GetAzureSqlManagedDatabaseAdvancedThreatProtectionSettings : SqlManagedDatabaseAdvancedThreatProtectionSettingsCmdletBase
    {
        /// <summary>
        /// No sending is needed as this is a Get cmdlet
        /// </summary>
        /// <param name="model">The model object with the data to be sent to the REST endpoints</param>
        protected override ManagedDatabaseAdvancedThreatProtectionSettingsModel PersistChanges(ManagedDatabaseAdvancedThreatProtectionSettingsModel model)
        {
            return null;
        }
    }
}
