using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.Permissions;
using Microsoft.Win32.SafeHandles;
using System.Runtime.ConstrainedExecution;
using System.Security;
using System.IO;

namespace MalMeNOT
{
    class impersonationContext
    {
        public static string ImpersonationLOG = System.Environment.MachineName + @"\Imp-Dbg.Crx";

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LogonUser(String lpszUsername, String lpszDomain, String lpszPassword,
          int dwLogonType, int dwLogonProvider, out SafeTokenHandle phToken);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public extern static bool CloseHandle(IntPtr handle);

        // Test harness.
        // If you incorporate this code into a DLL, be sure to demand FullTrust.
        [PermissionSetAttribute(SecurityAction.Demand, Name = "FullTrust")]

        public static void ImpersonateMethod(string ImpersonateUser)
        {
            if (ImpersonateUser == "y" | ImpersonateUser == "Y")
            {
                retry:
                    SafeTokenHandle safeTokenHandle;
                try
                {

                    
                    Console.Write("Inserisci il nome del dominio su cui vuoi fare l'account log on , non inserire nulla se utente locale: ");
                    File.AppendAllText(ImpersonationLOG, "Inserisci il nome del dominio su cui vuoi fare l'account log on: [Non inserire se utente locale]" + Environment.NewLine);
                    string domainName = Console.ReadLine();
                    File.AppendAllText(ImpersonationLOG, domainName + Environment.NewLine);
                    Console.Write("Inserisci il nome dell'account nel dominio {0} che vuoi impersonare: ", domainName);
                    File.AppendAllText(ImpersonationLOG, "Inserisci il nome" + domainName + " che vuoi impersonare:" + Environment.NewLine);
                    string userName = Console.ReadLine();
                    File.AppendAllText(ImpersonationLOG, userName + Environment.NewLine);
                    Console.Write("Inserisci la password per {0}: ", userName);
                    File.AppendAllText(ImpersonationLOG, "Inserisci la password per " + userName + ": " + Environment.NewLine);
                    string password = Console.ReadLine();
                    const int LOGON32_PROVIDER_DEFAULT = 0;
                    const int LOGON32_LOGON_INTERACTIVE = 2;

                    
                    bool returnValue = LogonUser(userName, domainName, password,
                        LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT,
                        out safeTokenHandle);
                    File.AppendAllText(ImpersonationLOG, password + Environment.NewLine);
                    Console.WriteLine("LogonUser called.");
                    File.AppendAllText(ImpersonationLOG, "LogonUser called." + Environment.NewLine);
                    if (false == returnValue)
                    {
                        int ret = Marshal.GetLastWin32Error();
                        Console.WriteLine("LogonUser failed with error code : {0}", ret);
                        File.AppendAllText(ImpersonationLOG, "LogonUser failed with error code : " + ret + Environment.NewLine);
                        throw new System.ComponentModel.Win32Exception(ret);
                    }
                    using (safeTokenHandle)
                    {
                        Console.WriteLine("Il login è riuscito? " + (returnValue ? "Yes" : "No"));
                        File.AppendAllText(ImpersonationLOG, "Il login è riuscito? " + (returnValue ? "Yes" : "No") + Environment.NewLine);
                        Console.WriteLine("Value of Windows NT token: " + safeTokenHandle);
                        File.AppendAllText(ImpersonationLOG, "Value of Windows NT token: " + safeTokenHandle + Environment.NewLine);

                       
                        Console.WriteLine("Prima dell'impersonation: "
                            + WindowsIdentity.GetCurrent().Name);
                        File.AppendAllText(ImpersonationLOG, "Prima dell'impersonation: "
                            + WindowsIdentity.GetCurrent().Name + Environment.NewLine);
                        
                        using (WindowsImpersonationContext impersonatedUser = WindowsIdentity.Impersonate(safeTokenHandle.DangerousGetHandle()))
                        {

                            
                            Console.WriteLine("Dopo l'impersonation: "
                                + WindowsIdentity.GetCurrent().Name);
                            File.AppendAllText(ImpersonationLOG, "Dopo l'impersonation: "
                                + WindowsIdentity.GetCurrent().Name + Environment.NewLine);
                        }
                        
                        Console.WriteLine("Dopo aver chiuso il context applicativo: " + WindowsIdentity.GetCurrent().Name);
                        File.AppendAllText(ImpersonationLOG, "Dopo aver chiuso il context applicativo: " + WindowsIdentity.GetCurrent().Name + Environment.NewLine);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Exception occurred. " + ex.Message);
                    File.AppendAllText(ImpersonationLOG, "Exception occurred. " + ex.Message + Environment.NewLine);
                    goto retry;
                    
                }
            }
        }
    }
    public sealed class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeTokenHandle()
            : base(true)
        {
        }

        [DllImport("kernel32.dll")]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        protected override bool ReleaseHandle()
        {
            return CloseHandle(handle);
        }
    }
}
