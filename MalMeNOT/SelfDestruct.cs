using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace MalMeNOT
{
    class SelfDestruct
    {
        public static void SelfDestruction()
        {
            try
            {
                File.Delete(@"C:\MalMeNot.forcer");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Errore: " + ex.Message);
            }
            ProcessStartInfo Info = new ProcessStartInfo();
            Info.Arguments = "/C choice /C Y /N /D Y /T 3 & Del " +
                           Application.ExecutablePath;
            Info.WindowStyle = ProcessWindowStyle.Hidden;
            Info.CreateNoWindow = true;
            Info.FileName = "cmd.exe";
            Process.Start(Info);
        }

        public static bool Should_i_start(string url)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Timeout = 15000;
            request.Method = "HEAD"; // As per Lasse's comment
            try
            {
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    return response.StatusCode == HttpStatusCode.OK;
                }
            }
            catch (WebException)
            {
                return false;
            }
           
        }
    }
}
