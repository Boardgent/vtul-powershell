using System.Diagnostics;

namespace vTul

{
    class Program
    {
        static void Main(string[] args)
        {
            Process process = new Process();
            //Comment line below for Console Version
            process.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            process.StartInfo.FileName = "powershell";
            process.StartInfo.Arguments = @"-version 2.0 -Sta -ExecutionPolicy UnRestricted -File .\vTul.ps1";
            process.Start();
        }
    }
}
