using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace MalMeNOT
{
    class Base64Checks
    {

        //File di log dove vengono inseriti tutti i file che matchano almeno 1 delle regole contenute in questa class 
        public static string SuspiciousLog = System.Environment.MachineName + @"\SuspiciousLog.txt";
 

        public static bool Base64Code(string FilePath, int MaxSeverity)
        {
            int ServerityMatches = 0;

            
                char[] delims = { '.', '!', '?', ',', '(', ')', '\t', '\n', '\r', ' ', '=', '+' };

                string[] words = File.ReadAllText(FilePath)
                    .Split(delims, StringSplitOptions.RemoveEmptyEntries);

            foreach (string word in words)
            {
                //Debug                
                //Console.WriteLine("La parola è " + word);
                var lines = File.ReadLines(@"ConfigFiles\Banned64Words.txt");
                if (!lines.Contains(word))
                {
                    try
                    {
                        Convert.FromBase64String(word);
                        File.AppendAllText(System.Environment.MachineName + @"\DecodedSeverity.txt", "File: " + FilePath + "[" + word + "]" + " --> " + Base64Decode(word) + Environment.NewLine);
                        ServerityMatches++;
                        if (ServerityMatches > MaxSeverity)
                        {
                            return true;
                        }
                    }
                    catch (Exception exception)
                    {
                        //MessageBox.Show(exception.Message);
                    }
                    //Check sulla parola
                }
            } 
            return false;
           
        }
       

        //Esegue lo scan del file di log designato da "Logpath" con un certa "Severity" che indica il numero di match per definire un file sospetto
        public static void B64CheckLog(string Logpath, int Severity)
        {
            try
            {
                var lines = File.ReadLines(Logpath);
                foreach (var line in lines)
                {
                    //Esegue una verifica sulla path, se contiene parole conosciute la salta
                    if(!line.Contains(@"Microsoft\VisualStudio\") | !line.Contains(@"\AppData\Local\Google\Chrome\"))
                    {
                        string filename = Path.GetFileName(line);
                        try
                        {                       
                            bool Check = Base64Code(line, Severity);
                            if(Check == true)
                            {
                                File.AppendAllText(SuspiciousLog, line  + Environment.NewLine);
                            }
                        
                        }
                        catch (Exception ex) { File.AppendAllText(System.Environment.MachineName + @"\Errors.txt", "Errore: " + ex.Message + Environment.NewLine); }
                    }
                }
            }
            catch { }
        }

        public static string Base64Decode(string base64EncodedData)
        {
            var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }

    }
}
