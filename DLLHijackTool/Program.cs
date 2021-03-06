using CommandLine;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
namespace DLLHijackTool
{
    class Program
    {
        static void Main(string[] args)
        {
            Parser.Default.ParseArguments<CommandLineArgs>(args)
                  .WithParsed(args =>
                  {
                      Run(args);
                  });
        }

        private static List<string> _knownDLLs = new List<string>();

        private static void Run(CommandLineArgs args)
        {
            var dllHijacker = new DLLHijacker();

            var processes = Process.GetProcesses();

            var processPaths = dllHijacker.RetrieveProcessesPath(processes);
            var servicePaths = dllHijacker.GetServicePaths();

            Console.WriteLine($"Was able to read {processes.Length} processes");
            Console.WriteLine($"Was able to read {servicePaths.Count} services");

            _knownDLLs = dllHijacker.RetrieveKnownDLLs();

            var mapPathToDll = new Dictionary<string, List<string>>();

            if (!string.IsNullOrEmpty(args.Executable))
            {
                foreach (var path in processPaths)
                {
                    if (Path.GetFileName(path) == args.Executable)
                    {
                        MapDLLs(dllHijacker, mapPathToDll, path);
                    }
                }
            }

            else
            {
                foreach (var path in processPaths)
                {
                    MapDLLs(dllHijacker, mapPathToDll, path);
                }

                foreach (var servicePath in servicePaths)
                {
                    MapDLLs(dllHijacker, mapPathToDll, servicePath);
                }
            }

            foreach (var key in mapPathToDll.Keys)
            {
                foreach (var value in mapPathToDll[key])
                {
                    if (dllHijacker.CheckHijack(key, value, args.AccountName))
                    {
                        Console.Write("DLL ");
                        Console.ForegroundColor = ConsoleColor.Cyan;
                        Console.Write(value);
                        Console.ResetColor();
                        Console.Write($" can be hijacked at ");
                        Console.Write(Path.GetDirectoryName(key));
                        Console.Write(" - ");
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine(Path.GetFileName(key));
                        Console.ResetColor();
                    }
                }
            }
        }

        private static void MapDLLs(DLLHijacker dllHijacker, Dictionary<string, List<string>> mapPathToDll, string path)
        {
            var apiSetStart = "api-ms-win";
            var apiSetStart2 = "ext-ms-win";
            var executableDlls = dllHijacker.RetrieveExecutableDLLs(path);
            var cleanedDlls = new List<string>();
            foreach (var dll in executableDlls)
            {
                if (_knownDLLs.Contains(dll) || dll.StartsWith(apiSetStart) || dll.StartsWith(apiSetStart2)) continue;
                cleanedDlls.Add(dll);
            }
            mapPathToDll[path] = cleanedDlls;
        }
    }
}
