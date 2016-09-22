﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace Microsoft.Azure.Commands.MachineLearning {
    using System;
    
    
    /// <summary>
    ///   A strongly-typed resource class, for looking up localized strings, etc.
    /// </summary>
    // This class was auto-generated by the StronglyTypedResourceBuilder
    // class via a tool like ResGen or Visual Studio.
    // To add or remove a member, edit your .ResX file then rerun ResGen
    // with the /str option, or rebuild your VS project.
    [global::System.CodeDom.Compiler.GeneratedCodeAttribute("System.Resources.Tools.StronglyTypedResourceBuilder", "4.0.0.0")]
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
    [global::System.Runtime.CompilerServices.CompilerGeneratedAttribute()]
    internal class Resources {
        
        private static global::System.Resources.ResourceManager resourceMan;
        
        private static global::System.Globalization.CultureInfo resourceCulture;
        
        [global::System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1811:AvoidUncalledPrivateCode")]
        internal Resources() {
        }
        
        /// <summary>
        ///   Returns the cached ResourceManager instance used by this class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Resources.ResourceManager ResourceManager {
            get {
                if (object.ReferenceEquals(resourceMan, null)) {
                    global::System.Resources.ResourceManager temp = new global::System.Resources.ResourceManager("Microsoft.Azure.Commands.MachineLearning.Resources", typeof(Resources).Assembly);
                    resourceMan = temp;
                }
                return resourceMan;
            }
        }
        
        /// <summary>
        ///   Overrides the current thread's CurrentUICulture property for all
        ///   resource lookups using this strongly typed resource class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Globalization.CultureInfo Culture {
            get {
                return resourceCulture;
            }
            set {
                resourceCulture = value;
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The passed in machine learning web service object does not have a valid ARM resource id. .
        /// </summary>
        internal static string InvalidWebServiceIdOnObject {
            get {
                return ResourceManager.GetString("InvalidWebServiceIdOnObject", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The specified web service definition file path does not exist..
        /// </summary>
        internal static string MissingDefinitionFile {
            get {
                return ResourceManager.GetString("MissingDefinitionFile", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The resource group name is missing..
        /// </summary>
        internal static string MissingResourceGroupName {
            get {
                return ResourceManager.GetString("MissingResourceGroupName", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Are you sure you want to create a new machine learning web service &quot;{0}&quot; ?.
        /// </summary>
        internal static string NewServiceWarning {
            get {
                return ResourceManager.GetString("NewServiceWarning", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Are you sure you want to remove the machine learning web service &quot;{0}&quot; ?.
        /// </summary>
        internal static string RemoveMlServiceWarning {
            get {
                return ResourceManager.GetString("RemoveMlServiceWarning", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Your update will make this web service readonly. This means that the service will no longer be update-able and can only be deleted. Are you sure you want to process this update for web service &quot;{0}&quot; ?.
        /// </summary>
        internal static string UpdateServiceToReadonly {
            get {
                return ResourceManager.GetString("UpdateServiceToReadonly", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Are you sure you want to update the machine learning web service &quot;{0}&quot; ?.
        /// </summary>
        internal static string UpdateServiceWarning {
            get {
                return ResourceManager.GetString("UpdateServiceWarning", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Azure Machine Learning Module Version: &quot;{0}&quot;.
        /// </summary>
        internal static string VersionInfo {
            get {
                return ResourceManager.GetString("VersionInfo", resourceCulture);
            }
        }
    }
}
