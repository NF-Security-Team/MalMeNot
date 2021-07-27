using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace MalMeNOT
{
    class VirusChecks
    {
        
        public static void Perform_Checks(string FilePath)
        {
            //Esegue tutti i checks su i file in args
            if
            (
                Check_RiskPath(FilePath) == true
            )
            {
                File.AppendAllText(Base64Checks.SuspiciousLog, FilePath + Environment.NewLine);
            }
            else
            {
                //do nothing
            }
        }        
        public static bool Check_RiskPath(string FilePath)
        {
            //Se contiene una di queste parle nella path è sospetto
            if
            (
                FilePath.Contains(@"appdata") |
                FilePath.Contains(@"startup") |
                FilePath.Contains(@"esecuzione") |
                FilePath.Contains(@"temp")
            )
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        public static string GETMD5(string FilePath)
        {
            using (var md5 = MD5.Create())
            {
                using (var stream = File.OpenRead(FilePath))
                {
                    var hash = md5.ComputeHash(stream);

                    string contents = File.ReadAllText(@"Databases\MD5-Processes.txt");
                    if (!contents.Contains(BitConverter.ToString(hash).Replace("-", "").ToUpperInvariant()))
                    {
                        File.AppendAllText(@"Databases\MD5-Processes.txt", BitConverter.ToString(hash).Replace("-", "").ToUpperInvariant() + Environment.NewLine);
                    }
                   
                    return BitConverter.ToString(hash).Replace("-", "").ToUpperInvariant();
                }
            }
           
        }

        //Creazione MD5 Database
       
        
        //TODO

    }
}
