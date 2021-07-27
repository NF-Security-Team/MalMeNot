using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace MalMeNOT
{
    class AutoRunChecks
    {

        //File di log dove vengono inseriti tutti i file che matchano almeno 1 delle regole contenute in questa class 
        public static string SuspiciousLog = System.Environment.MachineName + @"\SuspiciousLog.txt";
        public static string RegLog = System.Environment.MachineName + @"\RegistryAutostartLog.txt";

        public static void GetKeyValues(string KeyVal)
        {            
            if (KeyVal.StartsWith("HKEY_CURRENT_USER")) 
            {
                File.AppendAllText(RegLog, "[" + KeyVal + "]" + Environment.NewLine);
                string TimmedKey = KeyVal.Replace(@"HKEY_CURRENT_USER\", "");
                //opening the subkey  
                RegistryKey InspectedKey = Registry.CurrentUser.OpenSubKey(TimmedKey);
                //if it does exist, retrieve the stored values  
                if (InspectedKey != null)
                {
                    string[] Values = InspectedKey.GetValueNames();
                    foreach(string Row in Values)
                    {
                        File.AppendAllText(RegLog, "--->" + "[" + Row + "] " + InspectedKey.GetValue(Row) + Environment.NewLine);
                        //Console.WriteLine("[" + Row + "]" + InspectedKey.GetValue(Row));
                    }
                    File.AppendAllText(RegLog, Environment.NewLine);
                }     
                //Questa chiave dovrei chiuderla, am funziona lo stesso senza
            }

            if (KeyVal.StartsWith("HKEY_LOCAL_MACHINE"))
            {
                File.AppendAllText(RegLog, "[" + KeyVal + "]" + Environment.NewLine);
                string TimmedKey = KeyVal.Replace(@"HKEY_LOCAL_MACHINE\", "");
                //opening the subkey  
                RegistryKey InspectedKey = Registry.LocalMachine.OpenSubKey(TimmedKey);
                //if it does exist, retrieve the stored values  
                if (InspectedKey != null)
                {
                    string[] Values = InspectedKey.GetValueNames();
                    foreach (string Row in Values)
                    {
                        File.AppendAllText(RegLog, "--->" + "[" + Row + "] " + InspectedKey.GetValue(Row) + Environment.NewLine);
                        //Console.WriteLine("[" + Row + "]" + InspectedKey.GetValue(Row));
                    }
                    File.AppendAllText(RegLog, Environment.NewLine);
                }
                //Questa chiave dovrei chiuderla, am funziona lo stesso senza
            }

            if (KeyVal.StartsWith("HKEY_USERS"))
            {
                File.AppendAllText(RegLog, "[" + KeyVal + "]" + Environment.NewLine);
                string TimmedKey = KeyVal.Replace(@"HKEY_USERS\", "");
                //opening the subkey  
                RegistryKey InspectedKey = Registry.Users.OpenSubKey(TimmedKey);
                //if it does exist, retrieve the stored values  
                if (InspectedKey != null)
                {
                    string[] Values = InspectedKey.GetValueNames();
                    foreach (string Row in Values)
                    {
                        File.AppendAllText(RegLog, "--->" + "[" + Row + "] " + InspectedKey.GetValue(Row) + Environment.NewLine);
                        //Console.WriteLine("[" + Row + "]" + InspectedKey.GetValue(Row));
                    }
                    File.AppendAllText(RegLog, Environment.NewLine);
                }
                //Questa chiave dovrei chiuderla, am funziona lo stesso senza
            }

            if (KeyVal.StartsWith("HKEY_CLASSES_ROOT"))
            {
                File.AppendAllText(RegLog, "[" + KeyVal + "]" + Environment.NewLine);
                string TimmedKey = KeyVal.Replace(@"HKEY_CLASSES_ROOT\", "");
                //opening the subkey  
                RegistryKey InspectedKey = Registry.ClassesRoot.OpenSubKey(TimmedKey);
                //if it does exist, retrieve the stored values  
                if (InspectedKey != null)
                {
                    string[] Values = InspectedKey.GetValueNames();
                    foreach (string Row in Values)
                    {
                        File.AppendAllText(RegLog,"--->" + "[" + Row + "] " + InspectedKey.GetValue(Row) + Environment.NewLine);
                        //Console.WriteLine("[" + Row + "]" + InspectedKey.GetValue(Row));
                    }
                    File.AppendAllText(RegLog, Environment.NewLine);
                }
                //Questa chiave dovrei chiuderla, am funziona lo stesso senza
            }
        }       

        public static void RegKeyLogGenerator()
        {
            
            var lines = File.ReadLines(@"ConfigFiles\AutostartKeys.txt");
            //File Refresh
            if (File.Exists(RegLog))
            {
                File.Delete(RegLog);
            }
            foreach (var line in lines)
            {
                GetKeyValues(line);
            }
        }
        public static void CheckAutorunSet(string Filepath)
        {
            //esegue un check nelle principali location di autostart e verifica se tale file è presente nei tasks o reg keys
            //è necessario eseguire anche una correlazione dei log in base alla quantità di locazioni in cui questo viene invocato.
            //Il rating finale deciderà se il file dovrà essere controllato o meno
        }
    }
}
