using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MalMeNOT
{
    class LogsGathering
    {
        public static void GetWinLogs()
        {
            try
            {
                string LogFileDirectory = @"C:\Windows\System32\winevt\Logs";
                string Eventdir = System.Environment.MachineName + @"\" + "EventViewerLogs";
                Directory.CreateDirectory(Eventdir);
                CopyDir.Copy(LogFileDirectory, Eventdir); ;
            }
            catch(Exception ex) { File.AppendAllText(System.Environment.MachineName + @"\Errors.txt", "Errore: " + ex.Message + Environment.NewLine); }
        }
    }
}
