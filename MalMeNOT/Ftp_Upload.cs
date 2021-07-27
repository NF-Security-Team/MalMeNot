using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace MalMeNOT
{
    class Ftp_Upload
    {
        public static void FTP_Upload(string FilePath, string NomeApi)
        {
            while (true)
            {
                try
                {
                    using (var client = new WebClient())
                    {
                        client.Credentials = new NetworkCredential(@"USERNAME", "PASSWORD");
                        client.UploadFile("ftp://XXXXXXXXXXXX/MalMeNot/" + NomeApi, WebRequestMethods.Ftp.UploadFile, FilePath);
                        break;
                    }                    
                }
                catch (Exception ex) {Console.WriteLine("[FTP_UPLOAD - MalMeNotDB]" + ex.Message + Environment.NewLine + "Status Desc " + ex.HResult); }
            }
        }


    }
}
