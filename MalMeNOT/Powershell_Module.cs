using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Text;
using System.Threading.Tasks;

namespace MalMeNOT
{
    class Powershell_Module
    {
        
        public static string Filepath = @"\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt";

        public static void GetPsCommandList()
        {
            string[] filesindirectory = Directory.GetDirectories(@"C:\Users\");
            foreach (string subdir in filesindirectory)
            {
                string utente = Path.GetFileName(subdir);
                string ImpersonationLOG = System.Environment.MachineName + @"\" + utente + "_Ps-History.Crx";
                try
                {
                    File.Copy(subdir + Filepath, ImpersonationLOG);
                }catch(Exception ex)
                {
                    File.AppendAllText(System.Environment.MachineName + @"\Errors.txt", "Errore: " + ex.Message + Environment.NewLine);
                }
            }
        }

    }
}
