using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MalMeNOT
{
    class CopyDir
    {
        public static void Copy(string sourceDirectory, string targetDirectory)
        {
            DirectoryInfo diSource = new DirectoryInfo(sourceDirectory);
            DirectoryInfo diTarget = new DirectoryInfo(targetDirectory);

            CopyAll(diSource, diTarget);
        }

        public static void VirusScan(string FilePath)
        {
            //metodo per scannerizzare i file passati nelle lines
            //Necessario creare timing per 4 samples /minute

        }

        public static void RiskScan(bool activateScan, string path)
        {
            if (activateScan == true)
            {
                var lines = File.ReadLines(path);

                foreach (var line in lines)
                {
                    //string filename = Path.GetFileName(line);
                    //Scan con Virustotal Timed
                    VirusScan(line);
                }
            }
            //sezione mirata a scannerizzare i log e verificare se sono presenti malwares

        }

        public static void ListFiles(string filepath, string Filter, string DirName)
        {
            DirectoryInfo d = new DirectoryInfo(filepath);
            try
            {
                foreach (var file in d.GetFiles(Filter, SearchOption.AllDirectories))
                {

                    File.AppendAllText(System.Environment.MachineName + @"\" + DirName + Filter + ".txt", filepath + " [" + file.Extension + "] Name: " + file.Name);

                }
            }
            catch (Exception ex) { File.AppendAllText(System.Environment.MachineName + @"\Errors.txt", "Errore: " + ex.Message + Environment.NewLine); }

        }

        public static void CopyAll(DirectoryInfo source, DirectoryInfo target)
        {
            Directory.CreateDirectory(target.FullName);

            // Copy each file into the new directory.
            foreach (FileInfo fi in source.GetFiles())
            {
                try
                {
                    //Console.WriteLine(@"Copying {0}\{1}", target.FullName, fi.Name);
                    fi.CopyTo(Path.Combine(target.FullName, fi.Name), true);
                }
                catch (Exception ex) { File.AppendAllText(System.Environment.MachineName + @"\Errors.txt", "Errore: " + ex.Message + Environment.NewLine); }
            }

            // Copy each subdirectory using recursion.
            foreach (DirectoryInfo diSourceSubDir in source.GetDirectories())
            {
                try
                {
                    DirectoryInfo nextTargetSubDir =
                        target.CreateSubdirectory(diSourceSubDir.Name);
                    CopyAll(diSourceSubDir, nextTargetSubDir);
                }
                catch (Exception ex) { File.AppendAllText(System.Environment.MachineName + @"\Errors.txt", "Errore: " + ex.Message + Environment.NewLine); }
            }
        }
    }
}
