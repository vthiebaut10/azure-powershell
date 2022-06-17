using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Net;
using Microsoft.Azure.Commands.Common.Exceptions;
using System.Management.Automation;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace Microsoft.Azure.Commands.Ssh
{
    class SshConnectivityUtils
    {
        public const string clientProxyStorageUrl = "https://sshproxysa.blob.core.windows.net";
        public const string clientProxyRelease = "release01-11-21";
        public const string clientProxyVersion = "1.3.017634";

        public string GetClientSideProxy(string proxyFolder)
        {
            string proxyPath = null;
            string oldProxyPattern = null;
            string requestUrl = null;

            GetProxyUrlAndFilename(ref proxyPath, ref oldProxyPattern, ref requestUrl, proxyFolder);

            Console.WriteLine(requestUrl);
            Console.WriteLine(proxyPath);
            Console.WriteLine(oldProxyPattern);

            if (!File.Exists(proxyPath))
            {

                string proxyDir = Path.GetDirectoryName(proxyPath);
                Console.WriteLine(proxyDir);

                if (!Directory.Exists(proxyDir))
                {
                    Directory.CreateDirectory(proxyDir);
                }
                else
                {
                    var files = Directory.GetFiles(proxyDir, oldProxyPattern);
                    foreach (string file in files)
                    {
                        try
                        {
                            File.Delete(file);
                        }
                        catch (Exception exception)
                        {
                            Console.WriteLine("Somehow throw a warning here?" + exception.Message);
                        }
                            //Log warning if this fails
                    }
                    
                }

                try
                {
                    WebClient wc = new WebClient();
                    wc.DownloadFile(new Uri(requestUrl), proxyPath);
                }
                catch (Exception exception)
                {
                    string errorMessage = "Failed to download client proxy executable from " + requestUrl + ". Error: " + exception.Message;
                    throw new AzPSApplicationException(errorMessage);
                }               


            }


            return proxyPath;
        }

        private void GetProxyUrlAndFilename(ref string proxyPath, ref string oldProxyPattern, ref string requestUrl, string proxyFolder)
        {
            string os;
            string architecture;
            
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                os = "windows";
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                os = "linux";
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                os = "darwin";
            }
            else
            {
                throw new AzPSApplicationException("Operating System not supported");
            }

            if (Environment.Is64BitProcess)
            {
                architecture = "amd64";
            }
            else
            {
                architecture = "386";
            }

            Console.WriteLine(os);
            Console.WriteLine(architecture);

            string proxyName = "sshProxy_" + os + "_" + architecture;
            requestUrl = clientProxyStorageUrl + "/" + clientProxyRelease + "/" + proxyName + "_" + clientProxyVersion;

            string installPath = proxyName + "_" + clientProxyVersion.Replace('.', '_');
            oldProxyPattern = proxyName + "*";

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                requestUrl = requestUrl + ".exe";
                installPath = installPath + ".exe";
                oldProxyPattern = oldProxyPattern + ".exe";
            }

            Console.WriteLine(requestUrl);
            Console.WriteLine(installPath);


            if (proxyFolder == null)
            {
                proxyPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), Path.Combine(".clientsshproxy", installPath));
            }
            else
            {
                proxyPath = Path.Combine(proxyFolder, installPath);
            }

        }
    }
}
