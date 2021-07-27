using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace MalMeNOT
{
    class ProcessInspection
    {
        // Creare una classe per process inspection (Powershell, Wscript, CMD)
        public static string ProcessINSPECTIONlog = System.Environment.MachineName + @"\ProcessINSPECTION-log.txt";
        public static string SuspiciousProcessLog = System.Environment.MachineName + @"\SuspiciousProcessLog.txt";
        public static string SuspiciousProcessLogDecoded = System.Environment.MachineName + @"\SuspiciousProcessLogDECODED.txt";

        public static void ProcessInspector(string Keystroke)
        {
            Process[] processlist = Process.GetProcesses();
            bool FirstProc = true;
            foreach (var process in processlist)
            {               
                try
                {
                    File.AppendAllText(ProcessINSPECTIONlog, GetCommandLine(process) + Environment.NewLine);
                    if (
                        //Nomi dei Processi Sospetti
                        process.ProcessName == "cmd" |
                        process.ProcessName == "wscript" |
                        process.ProcessName == "powershell" |
                        process.ProcessName == "wmiprvse"
                      )                       
                    {
                        GetParent(process);
                        File.AppendAllText(SuspiciousProcessLog, GetCommandLine(process) + Environment.NewLine);
                        Base64CodeString(GetCommandLine(process));
                        //DEBUG
                        //Console.WriteLine(process.ProcessName);
                    }
                }
                catch (Win32Exception ex) when ((uint)ex.ErrorCode == 0x80004005)
                {
                    // Intentionally empty - no security access to the process.
                    File.AppendAllText(System.Environment.MachineName + @"\Errors.txt", "Errore: [" + process.ToString() + "] " + ex.Message + Environment.NewLine);
                }
                catch (InvalidOperationException)
                {
                    // Intentionally empty - the process exited before getting details.
                    File.AppendAllText(System.Environment.MachineName + @"\Errors.txt", "Errore: the process exited before getting details [" + process.ToString() + "]" + Environment.NewLine);
                }
                catch (Exception ex)
                {
                    File.AppendAllText(System.Environment.MachineName + @"\Errors.txt", "Errore: " + ex.Message + Environment.NewLine);
                }
                //Crea i dump di tutti i processi
                if (Keystroke == "y" | Keystroke == "Y")
                {
                    System.Threading.Thread.Sleep(3000);//3 sec wait
                    DumpProcess(process.Id);
                    if (FirstProc == true)
                    { System.Threading.Thread.Sleep(2000); MessageBox.Show("Accetta il reoglamento Sysinternals!!"); FirstProc = false; }

                    //Crea il Database di MD5
                    try
                    {
                        VirusChecks.GETMD5(process.MainModule.FileName);
                    }
                    catch (Exception ex)
                    {
                        File.AppendAllText(System.Environment.MachineName + @"\Errors.txt", "Errore: [" + process.ToString() + "] " + ex.Message + Environment.NewLine);
                    }
                }
            }
            if (Keystroke == "y" | Keystroke == "Y") 
            { 
                //Sleep till procdump is closed
                if(ProcessActive("procdump") == true || ProcessActive("procdump64") == true)
                {
                    //System.Threading.Thread.Sleep(2000); // aspetta 2 sec
                    Console.WriteLine("Premi un tasto per continuare...");
                    Console.ReadKey();
                    Console.WriteLine("Procedo con il kill di tutti i processi di dumping...");
                    while(ProcessActive("procdump") == true || ProcessActive("procdump64") == true)
                    {
                        try 
                        {
                            foreach (var process in Process.GetProcessesByName("procdump"))
                            {
                                process.Kill();
                            }
                        }
                        catch(Exception ex)
                        {
                            File.AppendAllText(System.Environment.MachineName + @"\Errors.txt", "Errore: " + ex.Message + Environment.NewLine);
                        }
                        try
                        {
                            foreach (var process in Process.GetProcessesByName("procdump64"))
                            {
                                process.Kill();
                            }
                        }
                        catch(Exception ex)
                        {
                            File.AppendAllText(System.Environment.MachineName + @"\Errors.txt", "Errore: " + ex.Message + Environment.NewLine);
                        }

                    }
                }
           
                Assembly asm = Assembly.GetExecutingAssembly();
                string path = System.IO.Path.GetDirectoryName(asm.Location);      
                DirectoryInfo d = new DirectoryInfo(path);

                foreach (var file in d.GetFiles("*.dmp", SearchOption.AllDirectories))
                {
                    try { File.Move(file.FullName, System.Environment.MachineName + @"\ProcessDumps\" + file.Name); } catch (Exception ex) { File.AppendAllText(System.Environment.MachineName + @"\Errors.txt", "Errore:" + ex.Message + Environment.NewLine); }                
                }
            }
            else
            {
                //Salta step procdump
            }
        }

        private static string GetCommandLine(Process process)
        {
            using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT CommandLine FROM Win32_Process WHERE ProcessId = " + process.Id))
            using (ManagementObjectCollection objects = searcher.Get())
            {
                return objects.Cast<ManagementBaseObject>().SingleOrDefault()?["CommandLine"]?.ToString();
            }

        }
        public static void GetParent(Process proc)
        {
            try
            {
                var myId = proc.Id;
                var query = string.Format("SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {0}", myId);
                var search = new ManagementObjectSearcher("root\\CIMV2", query);
                var results = search.Get().GetEnumerator();
                results.MoveNext();
                var queryObj = results.Current;
                var parentId = (uint)queryObj["ParentProcessId"];
                var parent = Process.GetProcessById((int)parentId);
                File.AppendAllText(SuspiciousProcessLog, proc.ProcessName + " PID [" + proc.Id + "]" + " è stato eseguito da " + parent.ProcessName + " PID [" + parent.Id + "]" + Environment.NewLine);
                //DEBUG
                //Console.WriteLine(proc.ProcessName + " PID [" + proc.Id + "]" + " è stato eseguito da " + parent.ProcessName + " PID [" + parent.Id + "]" + Environment.NewLine);        
            }catch(Exception ex)
            {
                File.AppendAllText(System.Environment.MachineName + @"\Errors.txt", "Errore: " + ex.Message + Environment.NewLine);
            }
        }
        public static void Base64CodeString(string Stringa)
        {
            char[] delims = { '.', '!', '?', ',', '(', ')', '\t', '\n', '\r', ' ', '=', '+' };

            string[] words = Stringa
                .Split(delims, StringSplitOptions.RemoveEmptyEntries);
             
            foreach (string word in words)
            {
                //Debug                
                //Console.WriteLine("La parola è " + word);

                try
                {
                    Convert.FromBase64String(word);
                    string DecodedWord = Base64Checks.Base64Decode(word).Replace("\0", "");
                    File.AppendAllText
                    (
                        SuspiciousProcessLogDecoded, "COMMAND: " + Stringa + "ANALYZED WORD: [" + word + "]" + Environment.NewLine +
                        "RESULT --> " + DecodedWord + Environment.NewLine
                    );
                }
                catch (Exception exception)
                {
                    //MessageBox.Show(exception.Message);
                }
                //Check sulla parola
            }

        }
        public static void DumpProcess(int PID)
        {
            Console.WriteLine("Inizio a prendere i Process Dumps...");
            if(!Directory.Exists(System.Environment.MachineName + @"\ProcessDumps\"))
            {
                Directory.CreateDirectory(System.Environment.MachineName + @"\ProcessDumps\");
            }
            Process.Start(@"Components\procdump.exe", PID.ToString());
            //Process.Start(@"Components\procdump " + PID.ToString());
        }
        public static bool ProcessActive(string ProcessName)
        {
            Process[] pname = Process.GetProcessesByName(ProcessName);
            if (pname.Length == 0)
                return false;
            else
                return true;
        }
    }
}
