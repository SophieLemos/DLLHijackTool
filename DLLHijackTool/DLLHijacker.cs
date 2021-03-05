using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Security.AccessControl;
using System.Security.Principal;

namespace DLLHijackTool
{
    class DLLHijacker
    {
        public List<string> RetrieveKnownDLLs()
        {
            var knownDLLs = new List<string>();
            var sub = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs");
            foreach (var key in sub.GetValueNames())
            {
                knownDLLs.Add(sub.GetValue(key).ToString().ToLower());
            }
            return knownDLLs;
        }

        public List<string> RetrieveProcessesPath(Process[] processes)
        {
            var processPaths = new List<string>();
            foreach (var proc in processes)
            {
                try
                {
                    processPaths.Add(proc.MainModule.FileName);
                }
                catch (Exception)
                {
                    //Console.WriteLine($"{e.Message} on {proc.ProcessName} - {proc.Id}");
                }
            }
            return processPaths;
        }

        public List<string> GetServicePaths()
        {
            var paths = new List<string>();
            var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Service");
            var collection = searcher.Get();

            foreach (var service in collection)
            {
                var servicePath = service["PathName"] as string;
                if (servicePath.Contains("svchost")) continue;
                servicePath = servicePath.Trim('\"');
                if (servicePath.Contains(".exe"))
                    servicePath = servicePath.Split(".exe")[0] + ".exe";
                paths.Add(servicePath);
            }
            return paths;
        }

        public List<string> RetrieveExecutableDLLs(string path)
        {
            var dllForProcess = new List<string>();
            PeNet.PeFile header;
            try
            {
                header = new PeNet.PeFile(path);
            }
            catch
            {
                return dllForProcess;
            }
            var imports = header.ImportedFunctions;
            if (imports == null) return dllForProcess;
            foreach (var import in header.ImportedFunctions)
            {
                var dll = import.DLL;
                if (!dllForProcess.Contains(dll))
                {
                    dllForProcess.Add(dll);
                }
            }
            return dllForProcess;
        }

        public bool CheckHijack(string path, string dll, string acccountName)
        {
            var pathDirectory = Path.GetDirectoryName(path);
            var inApplicationDir = File.Exists(Path.Combine(pathDirectory, dll));
            var inSystemDirectory = File.Exists(Path.Combine(Environment.SystemDirectory, dll));
            var inWindowsDirectory = File.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), dll));
            bool canWriteApplicationDir = false;
            if (!inApplicationDir)
            {
                var dirInfo = new DirectoryInfo(path);
                var acl = dirInfo.GetAccessControl(AccessControlSections.All);
                var rules = acl.GetAccessRules(true, true, typeof(NTAccount));

                foreach (AuthorizationRule rule in rules)
                {
                    if (rule.IdentityReference.Value.Equals(acccountName, StringComparison.CurrentCultureIgnoreCase))
                    {
                        var filesystemAccessRule = (FileSystemAccessRule)rule;
                        if ((filesystemAccessRule.FileSystemRights & FileSystemRights.WriteData) > 0 && filesystemAccessRule.AccessControlType != AccessControlType.Deny)
                        {
                            canWriteApplicationDir = true;
                        }
                    }
                }
            }

            if (canWriteApplicationDir) return true;
            if (inSystemDirectory || inWindowsDirectory || inApplicationDir) return false;
            return true;
        }

    }
}
