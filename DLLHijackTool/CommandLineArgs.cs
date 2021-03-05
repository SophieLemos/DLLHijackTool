using CommandLine;
using System;
using System.Collections.Generic;
using System.Text;

namespace DLLHijackTool
{
    class CommandLineArgs
    {
        [Option('u', "user", Required = true, HelpText = "User to check for write privileges.")]
        public string AccountName { get; set; }
        [Option('e', "executable", Required = false, HelpText = "Test a single running executable.")]
        public string Executable { get; set; }
    }
}
