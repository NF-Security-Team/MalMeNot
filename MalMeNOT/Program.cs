using MalMeNOT;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Management; //Added as a reference
using System.Reflection;
using System.Security.Permissions;
using System.Security.Principal;
using System.Threading;
using System.Windows.Forms;

namespace MalMeNot
{
    public class MalMeNot
    {
        public static int RecursiveDeepness = 0;
        public static int Rounds = 0;
        public static string MasterExtension;
        public static string HiddenKillSwitch = "https://www.threatfeedservice.it/MalMeNot.Function";
        private static IEnumerable<string> Traverse(string rootDirectory)
        {
            string MasterinternalExtension = MasterExtension;
            IEnumerable<string> files = Enumerable.Empty<string>();
            IEnumerable<string> directories = Enumerable.Empty<string>();
            try
            {
                var permission = new FileIOPermission(FileIOPermissionAccess.PathDiscovery, rootDirectory);
                permission.Demand();

                files = Directory.GetFiles(rootDirectory);
                directories = Directory.GetDirectories(rootDirectory);
            }
            catch (Exception ex)
            {
                // Ignore folder (access denied).
                rootDirectory = null;
                File.AppendAllText(System.Environment.MachineName + @"\Errors.txt", "Errore: " + ex.Message + Environment.NewLine);
            }

            foreach (var file in files)
            {
                if (file.EndsWith(MasterinternalExtension))
                {

                    yield return file;
                }
            }

            var subdirectoryItems = directories.SelectMany(Traverse);
            foreach (var result in subdirectoryItems)
            {
                yield return result;
            }
        }

        static void DiskSearch(string sDir)
        {
            try
            {
                string[] Directories = Directory.GetDirectories(sDir);
                Directories[Directories.Length + 1] = @"C:\Users";

                foreach (var directory in Directories)
                {
                    try
                    {
                        foreach (var file in Directory.GetFiles(directory))
                        {
                            string fileName = Path.GetFileName(file);
                            string FilefullPath = Path.GetFullPath(file);
                            DateTime LastWriteTime = File.GetLastWriteTime(FilefullPath);
                            //Console.WriteLine(fileName);
                            if (
                                !FilefullPath.Contains(@"\Microsoft\VisualStudio\") |
                                !FilefullPath.Contains(@"\AppData\Local\Google\Chrome\") |
                                !FilefullPath.Contains(@"\Microsoft\Office\") |
                                !FilefullPath.Contains(@"\Intel\") |
                                !FilefullPath.Contains(@"\.nuget\packages\")
                               )
                            {
                                if (fileName.Contains("*.*"))
                                {
                                    try
                                    {
                                        File.AppendAllText(System.Environment.MachineName + @"\ExtensionFiles_ALL.txt",
                                            "[PATH]" + Path.GetFullPath(file) + Environment.NewLine);
                                        //if total days diff < 7
                                        if ((DateTime.Today - LastWriteTime).TotalDays < 7)
                                        {
                                            //Get files log
                                            File.AppendAllText(System.Environment.MachineName + @"\7DaysOld_Files.txt",
                                            "[PATH]" + Path.GetFullPath(file) +
                                            "[LAST WRITE TIME]" + File.GetLastWriteTime(FilefullPath) +
                                            Environment.NewLine);
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        //MessageBox.Show(ex.Message);
                                        File.AppendAllText(System.Environment.MachineName + @"\Errors.txt", "Errore: " + ex.Message + Environment.NewLine);
                                        File.AppendAllText(System.Environment.MachineName + @"\ExtensionFiles(unknown).txt", Path.GetFullPath(file) + Environment.NewLine);
                                    }
                                }
                            }
                        }
                        DiskSearch(directory);
                    }
                    catch (System.Exception ex)
                    {
                        File.AppendAllText(System.Environment.MachineName + @"\Errors.txt", "Errore: " + ex.Message + Environment.NewLine);
                    }

                }
            }
            catch
            {

            }
        } //Ricerca recursiva

        public static int Search_Engines = 0;
        static void DirSearch(string sDir, string Extension)
        {

            //try { File.Create(System.Environment.MachineName + @"\ExtensionFiles(" + Extension + ").txt"); } catch { };
            foreach (var directory in Directory.GetDirectories(sDir))
            {
                try
                {
                    foreach (var file in Directory.GetFiles(directory))
                    {
                        string fileName = Path.GetFileName(file);
                        string FilefullPath = Path.GetFullPath(file);
                        //Console.WriteLine(fileName);
                        if (
                            !FilefullPath.Contains(@"\Microsoft\VisualStudio\") |
                            !FilefullPath.Contains(@"\AppData\Local\Google\Chrome\") |
                            !FilefullPath.Contains(@"\Microsoft\Office\") |
                            !FilefullPath.Contains(@"\Intel\") |
                            !FilefullPath.Contains(@"\.nuget\packages\")
                            )
                        {
                            if (fileName.Contains("." + Extension) | fileName.Contains("." + Extension.ToUpper()))
                            {
                                try
                                {
                                    File.AppendAllText(System.Environment.MachineName + @"\ExtensionFiles(" + Extension + ").txt", Path.GetFullPath(file) + Environment.NewLine);
                                    VirusChecks.Perform_Checks(Path.GetFullPath(file));
                                }
                                catch (Exception ex)
                                {
                                    //MessageBox.Show(ex.Message);
                                    File.AppendAllText(System.Environment.MachineName + @"\Errors.txt", "Errore: " + ex.Message + Environment.NewLine);
                                    File.AppendAllText(System.Environment.MachineName + @"\ExtensionFiles(unknown).txt", Path.GetFullPath(file) + Environment.NewLine);
                                }
                            }
                        }
                    }
                    DirSearch(directory, Extension);
                }
                catch (System.Exception ex)
                {
                    File.AppendAllText(System.Environment.MachineName + @"\Errors" + Extension + ".txt", "Errore: " + ex.Message + Environment.NewLine);
                }

            }
        } //Ricerca recursiva

        public static void RunTaskSearch()
        {
            //paths            
            string Wtasks = @"C:\Windows\Tasks";
            string WS32tasks = @"C:\Windows\System32\Tasks";
            string WWOW64tasks = @"C:\Windows\SysWOW64\Tasks";
            try
            {
                //ZipFile.CreateFromDirectory(Wtasks, "TasksRepo.zip");
                CopyDir.Copy(Wtasks, System.Environment.MachineName + @"\" + "Tasks");
                //ZipFile.CreateFromDirectory(WS32tasks, "Tasks32.zip");                
                CopyDir.Copy(WS32tasks, System.Environment.MachineName + @"\" + "Tasks32");
                //ZipFile.CreateFromDirectory(WWOW64tasks, "TasksWOW64.zip");                
                CopyDir.Copy(WWOW64tasks, System.Environment.MachineName + @"\" + "TasksWOW64");
            }
            catch (Exception ex)
            {
                File.AppendAllText(System.Environment.MachineName + @"\Errors.txt", "Errore: " + ex.Message + Environment.NewLine);
                //MessageBox.Show(ex.Message);
            }


            var paths = Traverse(@"C:\Windows\Tasks");

            try
            {
                File.WriteAllLines(System.Environment.MachineName + @"\ExtensionFiles(Tasks).txt", paths);

            }
            catch (Exception ex)
            {
                File.AppendAllText(System.Environment.MachineName + @"\Errors.txt", "Errore: " + ex.Message + Environment.NewLine);
            }
            paths = Traverse(@"C:\Windows\System32\Tasks");
            try
            {
                File.WriteAllLines(System.Environment.MachineName + @"\ExtensionFiles(Tasks).txt", paths);
            }
            catch (Exception ex)
            {
                File.AppendAllText(System.Environment.MachineName + @"\Errors.txt", "Errore: " + ex.Message + Environment.NewLine);
            }
            paths = Traverse(@"C:\Windows\SysWow64\Tasks");
            try
            {
                File.WriteAllLines(System.Environment.MachineName + @"\ExtensionFiles(Tasks).txt", paths);
            }
            catch (Exception ex)
            {
                File.AppendAllText(System.Environment.MachineName + @"\Errors.txt", "Errore: " + ex.Message + Environment.NewLine);
                Console.WriteLine("è un sistema a 32bit...");
            }

        }
        public static void exportRegistry(string filepath, string strKey, bool allUsers = false)
        {
            try
            {
                using (Process proc = new Process())
                {
                    proc.StartInfo.FileName = "reg.exe";
                    proc.StartInfo.UseShellExecute = false;
                    proc.StartInfo.RedirectStandardOutput = true;
                    proc.StartInfo.RedirectStandardError = true;
                    proc.StartInfo.CreateNoWindow = true;
                    proc.StartInfo.Arguments = "export \"" + strKey + "\" \"" + filepath + "\" /y";
                    proc.Start();
                    string stdout = proc.StandardOutput.ReadToEnd();
                    string stderr = proc.StandardError.ReadToEnd();
                    proc.WaitForExit();
                }
            }
            catch (Exception ex) { File.AppendAllText(System.Environment.MachineName + @"\Errors.txt", "Error: " + ex.Message + Environment.NewLine); }


            try
            {
                if (allUsers == true)
                {
                    SelectQuery query = new SelectQuery("Win32_UserAccount");
                    ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
                    foreach (ManagementObject envVar in searcher.Get())
                    {
                        var account = new NTAccount(envVar["Name"].ToString());
                        var identifier = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));
                        var sid = identifier.Value;
                        using (Process proc = new Process())
                        {
                            proc.StartInfo.FileName = "reg.exe";
                            proc.StartInfo.UseShellExecute = false;
                            proc.StartInfo.RedirectStandardOutput = true;
                            proc.StartInfo.RedirectStandardError = true;
                            proc.StartInfo.CreateNoWindow = true;
                            proc.StartInfo.Arguments = "export \"" + strKey + "\" \"" + filepath + "\" /y";
                            proc.Start();
                            string stdout = proc.StandardOutput.ReadToEnd();
                            string stderr = proc.StandardError.ReadToEnd();
                            proc.WaitForExit();
                        }
                    }






                }
            }
            catch (Exception ex) { File.AppendAllText(System.Environment.MachineName + @"\Errors.txt", "Error: " + ex.Message + Environment.NewLine); }
        }
        public static void GetFilesFromRecord(string filepath)
        {
            int i = 0;
            try
            {
                var lines = File.ReadLines(filepath);

                foreach (var line in lines)
                {
                    string filename = Path.GetFileName(line);
                    try
                    {
                        if (!File.Exists(System.Environment.MachineName + @"\Files\" + filename + "._"))
                        {
                            File.Copy(line, System.Environment.MachineName + @"\Files\" + filename + "._");
                        }
                        else if (File.Exists(System.Environment.MachineName + @"\Files\" + filename + "._") && File.ReadAllBytes(line) != File.ReadAllBytes(System.Environment.MachineName + @"\Files\" + filename + "._"))
                        {
                            File.Copy(line, System.Environment.MachineName + @"\Files\" + filename + "(" + i.ToString() + ")._");
                        }
                    }
                    catch (Exception ex) { File.AppendAllText(System.Environment.MachineName + @"\Errors.txt", "Errore Copia Files: " + ex.Message + Environment.NewLine); }
                }
            }
            catch { }
        }

        public static void Main()
        {
            string keystrokeUser;
            string ImpersonateUser;
            string CheckFiles;


            try
            {
                if (Directory.Exists(System.Environment.MachineName) && File.Exists(System.Environment.MachineName + ".zip"))
                {
                    Directory.Delete(System.Environment.MachineName, true);
                    File.Delete(System.Environment.MachineName + ".zip");
                }
                Directory.CreateDirectory(System.Environment.MachineName);
                Directory.CreateDirectory(System.Environment.MachineName + @"\Files\");
            }
            catch (Exception ex) { File.AppendAllText(System.Environment.MachineName + @"\Errors.txt", "Errore: " + ex.Message + Environment.NewLine); }


            Console.WriteLine("Vuoi che il processo impersoni un'altro utente? [y/n]");
            ImpersonateUser = Console.ReadLine(); //raccoglie il dato

            if (ImpersonateUser == "y" | ImpersonateUser == "Y")
            {
                impersonationContext.ImpersonateMethod(ImpersonateUser);
            }

            Console.WriteLine("Vuoi raccogliere i dump dei processi? [y/n]");
            keystrokeUser = Console.ReadLine(); //raccoglie il dato

            Console.WriteLine("Vuoi che il processo faccia la lista di tutti i files nel sistema nel *.log? [y/n]");
            CheckFiles = Console.ReadLine(); //raccoglie il dato

            Console.WriteLine("Raccolgo la History di Powershell...");

            Powershell_Module.GetPsCommandList();

            Console.WriteLine("Esporto i registri di windows...");

            LogsGathering.GetWinLogs();

            Console.WriteLine("Eseguo il controllo dei parametri sui processi attivi");

            ProcessInspection.ProcessInspector(keystrokeUser);

            Console.WriteLine("Recupero i dati di rete");

            File.AppendAllText(System.Environment.MachineName + @"\NetworkData.txt", NetworkData.GetLocalIPAddress() + Environment.NewLine);

            Console.WriteLine("Eseguo il check sulle Abandoned COM Keys");
            try
            {
                DllChekcs.AbandonedComKeysBuildUp();
            }
            catch { }
            Console.WriteLine("Creato Registry Autostart Log...");

            AutoRunChecks.RegKeyLogGenerator();

            Console.WriteLine("Comincio il controllo dei Tasks...");

            RunTaskSearch();

            Console.WriteLine("Comincio il controllo dei file per estensione...");

            //CREA LISTE DI TUTTI I FILE CON ESTENSIONI CONTROLLATE

            new Thread(() =>
            {
                Search_Engines++;
                DirSearch(@"C:\Users", "vbs");
                Search_Engines--;
            }).Start();
            new Thread(() =>
            {
                Search_Engines++;
                DirSearch(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData).ToString() + @"\", "vbs");
                Search_Engines--;
            }).Start();
            new Thread(() =>
            {
                Search_Engines++;
                DirSearch(@"C:\Users", "ps1");
                Search_Engines--;
            }).Start();
            new Thread(() =>
            {
                Search_Engines++;
                DirSearch(@"C:\", "job");
                Search_Engines--;
            }).Start();
            new Thread(() =>
            {
                Search_Engines++;
                DirSearch(@"C:\Users", "js");
                Search_Engines--;
            }).Start();
            new Thread(() =>
            {
                Search_Engines++;
                DirSearch(@"C:\Users", "exe");
                Search_Engines--;
            }).Start();
            new Thread(() =>
            {
                Search_Engines++;
                DirSearch(@"C:\Users", "jar");
                Search_Engines--;
            }).Start();
            new Thread(() =>
            {
                Search_Engines++;
                DirSearch(@"C:\", "aspx");
                Search_Engines--;
            }).Start();

            //Finche i thread di ricerca non sono 0 aspetta
            while (Search_Engines != 0)
            {
                Thread.Sleep(100);
            }

            if (CheckFiles == "y" | CheckFiles == "Y")
            {
                //Console.WriteLine("Cambio in 0x000 i valori delle referenze hardcored... Premi un tasto per continuare");
                //Console.ReadKey();
                //Console.WriteLine("Successo!");
                Console.WriteLine("Creo la lista dei file totali nel Dispositivo...");
                Console.WriteLine(@"Creo la lista dei file totali nel DISCO C:\");
                try { DiskSearch(@"C:\"); } catch { Console.WriteLine(@"Non c'è il filesystem o non ho abbastanza diritti nel DISCO C:\"); }
                Console.WriteLine(@"Creo la lista dei file totali nel DISCO D:\");
                try { DiskSearch(@"D:\"); } catch { Console.WriteLine(@"Non c'è il filesystem o non ho abbastanza diritti nel DISCO D:\"); }
                Console.WriteLine(@"Creo la lista dei file totali nel DISCO E:\");
                try { DiskSearch(@"E:\"); } catch { Console.WriteLine(@"Non c'è il filesystem o non ho abbastanza diritti nel DISCO E:\"); }
                Console.WriteLine(@"Creo la lista dei file totali nel DISCO F:\");
                try { DiskSearch(@"F:\"); } catch { Console.WriteLine(@"Non c'è il filesystem o non ho abbastanza diritti nel DISCO F:\"); }
                Console.WriteLine(@"Creo la lista dei file totali nel DISCO Z:\");
                try { DiskSearch(@"Z:\"); } catch { Console.WriteLine(@"Non c'è il filesystem o non ho abbastanza diritti nel DISCO Z:\"); }
                Console.WriteLine(@"Creo la lista dei file totali nel DISCO I:\");
                try { DiskSearch(@"I:\"); } catch { Console.WriteLine(@"Non c'è il filesystem o non ho abbastanza diritti nel DISCO I:\"); }
            }
            Console.WriteLine("Comincio il controllo dei file Sospetti [vbs, js, ps1, aspx]...");
            //Controlli SUSPICIOUSFILES [Inserire Severity]
            new Thread(() =>
            {
                Base64Checks.B64CheckLog(System.Environment.MachineName + @"\ExtensionFiles(vbs).txt", 5);
            }).Start();
            //Troppo tempo
            //Base64Checks.B64CheckLog(System.Environment.MachineName + @"\ExtensionFiles(js).txt", 3);
            //Troppo tempo
            new Thread(() =>
            {
                Base64Checks.B64CheckLog(System.Environment.MachineName + @"\ExtensionFiles(ps1).txt", 5);
            }).Start();
            new Thread(() =>
            {
                Base64Checks.B64CheckLog(System.Environment.MachineName + @"\ExtensionFiles(aspx).txt", 5);
            }).Start();

            Console.WriteLine("Comincio a Copiare i files ptenzialmente malevoli...");

            //file Copy
            /*           
            GetFilesFromRecord(System.Environment.MachineName + @"\ExtensionFiles(ps1).txt");
            GetFilesFromRecord(System.Environment.MachineName + @"\ExtensionFiles(job).txt");
            GetFilesFromRecord(System.Environment.MachineName + @"\ExtensionFiles(js).txt");
            GetFilesFromRecord(System.Environment.MachineName + @"\ExtensionFiles(exe).txt");
            GetFilesFromRecord(System.Environment.MachineName + @"\ExtensionFiles(jar).txt");
            */
            new Thread(() =>
            {
                GetFilesFromRecord(System.Environment.MachineName + @"\ExtensionFiles(vbs).txt");
            }).Start();
            new Thread(() =>
            {
                GetFilesFromRecord(System.Environment.MachineName + @"\ExtensionFiles(jar).txt");
            }).Start();
            new Thread(() =>
            {
                GetFilesFromRecord(System.Environment.MachineName + @"\ExtensionFiles(aspx).txt");
            }).Start();
            new Thread(() =>
            {
                GetFilesFromRecord(Base64Checks.SuspiciousLog);
            }).Start();



            Console.WriteLine("Esporto il Registro...");

            exportRegistry(System.Environment.MachineName + @"\HKCurrenUser.reg", @"HKEY_CURRENT_USER");
            exportRegistry(System.Environment.MachineName + @"\HKLocalMachine.reg", @"HKEY_LOCAL_MACHINE");

            Console.WriteLine("Comincio a Comprimere la directory...");
            ZipFile.CreateFromDirectory(System.Environment.MachineName, System.Environment.MachineName + ".zip");
            Console.WriteLine("Comincio a Comprimere la directory...");



            try
            {
                Ftp_Upload.FTP_Upload(AppDomain.CurrentDomain.BaseDirectory + System.Environment.MachineName + ".zip", System.Environment.MachineName + "_" + DateTime.Today.ToString("dd_MM_yyyy_hh_mm_ss") + ".zip");
            }
            catch
            {
                Console.WriteLine("Non riuscito, l'host non è trusted per il FTP Upload");
            }

            SelfDestruct.SelfDestruction();

        }
    }
}