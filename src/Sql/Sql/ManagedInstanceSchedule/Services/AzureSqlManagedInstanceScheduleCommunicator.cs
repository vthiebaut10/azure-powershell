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

using Microsoft.Azure.Commands.Common.Authentication;
using Microsoft.Azure.Commands.Common.Authentication.Abstractions;
using Microsoft.Azure.Commands.Sql.ManagedInstanceSchedule.Model;
using Microsoft.Azure.Management.Internal.Resources;
using Microsoft.Azure.Management.Sql;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.Azure.Commands.Sql.ManagedInstanceSchedule.Services
{
    public class AzureSqlManagedInstanceScheduleCommunicator
    {
        /// <summary>
        /// The Sql client to be used by this end points communicator
        /// </summary>
        private static SqlManagementClient SqlClient { get; set; }

        /// <summary>
        /// Gets or set the Azure subscription
        /// </summary>
        private static IAzureSubscription Subscription { get; set; }

        /// <summary>
        /// Gets or sets the Azure profile
        /// </summary>
        public IAzureContext Context { get; set; }

        /// <summary>
        /// Creates a communicator for Managed instance
        /// </summary>
        /// <param name="context">The current azure context</param>
        public AzureSqlManagedInstanceScheduleCommunicator(IAzureContext context)
        {
            Context = context;
            if (context?.Subscription != Subscription)
            {
                Subscription = context?.Subscription;
                SqlClient = null;
            }
        }

        public IList<Management.Sql.Models.StartStopManagedInstanceSchedule> ListSchedule(string resourceGroupName, string managedInstanceName)
        {
            return GetCurrentSqlClient().StartStopManagedInstanceSchedules.ListByInstance(resourceGroupName, managedInstanceName).ToList();
        }

        public Management.Sql.Models.StartStopManagedInstanceSchedule SetSchedule(string resourceGroupName,
                                                                                  string managedInstanceName,
                                                                                  AzureSqlManagedInstanceScheduleModel scheduleModel)
        {
            return GetCurrentSqlClient().StartStopManagedInstanceSchedules.CreateOrUpdate(resourceGroupName, managedInstanceName, new Management.Sql.Models.StartStopManagedInstanceSchedule()
            {
                Description = scheduleModel.Description,
                TimeZoneId = scheduleModel.TimeZoneId,
                ScheduleList = scheduleModel.ScheduleList.Select(item => new Management.Sql.Models.ScheduleItem()
                {
                    StartDay = item.StartDay,
                    StartTime = item.StartTime,
                    StopDay = item.StopDay,
                    StopTime = item.StopTime
                }).ToList()
            });
        }

        public void RemoveSchedule(string resourceGroupName, string managedInstanceName)
        {
            GetCurrentSqlClient().StartStopManagedInstanceSchedules.Delete(resourceGroupName, managedInstanceName);
        }


        /// <summary>
        /// Retrieve the SQL Management client for the currently selected subscription, adding the session and request
        /// id tracing headers for the current cmdlet invocation.
        /// </summary>
        /// <returns>The SQL Management client for the currently selected subscription.</returns>
        private SqlManagementClient GetCurrentSqlClient()
        {
            // Get the SQL management client for the current subscription
            if (SqlClient == null)
            {
                SqlClient = AzureSession.Instance.ClientFactory.CreateArmClient<SqlManagementClient>(Context, AzureEnvironment.Endpoint.ResourceManager);
            }
            return SqlClient;
        }
    }
}
