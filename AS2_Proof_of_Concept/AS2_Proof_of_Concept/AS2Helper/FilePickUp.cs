using System;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using AS2_Proof_of_Concept.WebAPI.AS2;

namespace AS2_Proof_of_Concept.AS2Helper
{
    public class FilePickUp
    {
        public void PickUpFiles(Uri uri, string path)
        {
            DirectoryInfo dirInfo = new DirectoryInfo(path);

            FileInfo[] fileInfo = dirInfo.GetFiles();

            foreach (var file in fileInfo)
            {
                Console.WriteLine("----------------");
                Console.WriteLine("\nI found this file:\n");
                Console.WriteLine(file.Name);
                Console.WriteLine("Do you want to send this? Y or N");

                string answer = Console.ReadLine();
                if (answer != null && answer.ToUpper() != "Y") continue;

                ProxySettings settings = new ProxySettings
                {
                    Name = string.Empty,
                    Domain = string.Empty,
                    Username = string.Empty,
                    Password = string.Empty
                };

                byte[] fileData = File.ReadAllBytes(file.FullName);

                const string pwd = "MyPartnersKey";
                SecureString securePwd = new SecureString();
                Array.ForEach(pwd.ToArray(), securePwd.AppendChar);
                securePwd.MakeReadOnly();
                X509Certificate2 signingCert = new X509Certificate2(@"‪C:\files\certs\MyPartnersPrivateCert.pfx", securePwd);
                X509Certificate2 recipientCert = new X509Certificate2(@"‪C:\files\certs\MyPublicCert.p7b");

                var send = As2Send.SendFile(uri, file.Name, fileData, "mycompanyAS2", "mendelsontestAS2", settings, 960000, signingCert, recipientCert);
                Console.WriteLine($"\nStatus code: {send}");
            }
            Console.WriteLine("\n\nI couldn't find anymore files in the given directory.");
        }
    }
}
