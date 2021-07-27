using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace MalMeNOT
{
    class NetworkData
    {
        public static string GetLocalIPAddress()
        {
            try
            {
                string Result = "";


                var host = Dns.GetHostEntry(Dns.GetHostName());
                foreach (var ip in host.AddressList)
                {
                    if (ip.AddressFamily == AddressFamily.InterNetwork)
                    {
                        Result = "L'indirizzo IP locale del dispositivo è: " + ip.ToString() + Environment.NewLine;
                    }
                }

                NetworkInterface[] adapters = NetworkInterface.GetAllNetworkInterfaces();
                foreach (NetworkInterface adapter in adapters)
                {
                    IPInterfaceProperties properties = adapter.GetIPProperties();
                    Console.WriteLine(adapter.Description);
                    Result = Result + adapter.Description + Environment.NewLine;
                    Result = Result + "  DNS suffix : " + properties.DnsSuffix + Environment.NewLine;
                    Result = Result + "  DNS enabled : " + properties.IsDnsEnabled + Environment.NewLine;
                    Result = Result + "  Dynamically configured DNS : " + properties.IsDynamicDnsEnabled + Environment.NewLine;
                    Result = Result + "  IPV4 : " + Environment.NewLine + properties.GetIPv4Properties() + Environment.NewLine;
                }

                return Result;

                throw new Exception("No network adapters with an IPv4 address in the system!");
            }catch(Exception ex)
            {
                File.AppendAllText(System.Environment.MachineName + @"\Errors.txt", "Errore: " + ex.Message + Environment.NewLine);
                return "Ci sono stati errori... Verifica nel foglio Errors.txt e contatta Nicolas a (nicolas.fasolo@hotmail.it)";
            }
        }

    }
}
