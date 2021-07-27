using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace MalMeNOT
{
    class ThreatFeedService_Integration
    {
        public static void ThreatFeedLists_Retrieve(string remoteFilename, string localFilename)
        {
            WebClient client = new WebClient();
            string credentials = Convert.ToBase64String(
            Encoding.ASCII.GetBytes("Api_user" + ":" + "XXXXXX")); //User : Passwd
            client.Headers[HttpRequestHeader.Authorization] = string.Format(
                "Basic {0}", credentials);
            client.DownloadFile(remoteFilename, localFilename);

            //TODO: Far scaricare la lista MD5 e confrontrare gli entry con i file sospetti trovati
        }
    }
}
