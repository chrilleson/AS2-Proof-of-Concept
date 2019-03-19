using System;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace AS2_Proof_of_Concept.WebAPI.AS2
{
    public struct ProxySettings
    {
        public string Name;
        public string Username;
        public string Password;
        public string Domain;
    }

    public class As2Send
    {
        public static HttpStatusCode SendFile(Uri uri, string filename, byte[] fileData, string partner, string localStation, ProxySettings proxySettings, int timeoutMs, X509Certificate2 signingCert, X509Certificate2 recipientCert)
        {
            if (string.IsNullOrEmpty(filename)) throw new ArgumentNullException(nameof(filename));

            if (fileData.Length == 0) throw new ArgumentException("filedata");

            byte[] content = fileData;

            //Initialise the request
            HttpWebRequest http = (HttpWebRequest)WebRequest.Create(uri);

            if (!string.IsNullOrEmpty(proxySettings.Name))
            {
                WebProxy proxy = new WebProxy(proxySettings.Name);

                NetworkCredential proxyCredential = new NetworkCredential
                {
                    Domain = proxySettings.Domain,
                    UserName = proxySettings.Username,
                    Password = proxySettings.Password
                };

                proxy.Credentials = proxyCredential;

                http.Proxy = proxy;
            }

            //Define the standard request objects
            http.Method = "POST";

            http.AllowAutoRedirect = true;

            http.KeepAlive = true;

            http.PreAuthenticate = false; //Means there will be two requests sent if Authentication required.
            http.SendChunked = false;

            http.UserAgent = "mendelson AS2 Server 2019 build 364";


            //These Headers are common localStation all transactions
            http.Headers.Add("Mime-Version", "1.0");
            http.Headers.Add("AS2-Version", "1.2");
            http.Headers.Add("AS2-From", partner);
            http.Headers.Add("AS2-To", localStation);
            http.Headers.Add("Subject", filename + " transmission.");
            http.Headers.Add("Date", DateTime.Now.ToString("R"));
            http.Headers.Add("Recipient-adress", "http://testas2.mendelson-e-c.com:8080/as2/HttpReceiver");
            //http.Headers.Add("Receipt-delivery-option", "https://as2proofofconceptwebapplication20190307102507.azurewebsites.net/AS2Listener.ashx");
            http.Headers.Add("Message-ID", "<AS2_" + DateTime.Now.ToString("g") + ">");
            http.Headers.Add("Disposition-notification-to", partner);
            http.Headers.Add("Disposition-notification-options", "signed-receipt-protocol=optional, pkcs7-signature; signed-receipt-micalg=optional, sha256");
            http.Timeout = timeoutMs;

            string contentType = (Path.GetExtension(filename) == ".xml") ? "application/xml" : "application/EDIFACT";

            bool encrypt = !string.IsNullOrEmpty(recipientCert.ToString());
            bool sign = !string.IsNullOrEmpty(signingCert.ToString());

            if (!sign && !encrypt)
            {
                http.Headers.Add("Content-Transfer-Encoding", "binary");
                http.Headers.Add("Content-Disposition", "inline; filename=\"" + filename + "\"");
            }
            if (sign)
            {
                // Wrap the file data with a mime header
                content = As2MimeUtilities.CreateMessage(contentType, "binary", "attachment; filename= " + filename, content);

                content = As2MimeUtilities.Sign(content, signingCert, out contentType);

                http.Headers.Add("EDIINT-Features", "multiple-attachments");

            }
            if (encrypt)
            {
                if (string.IsNullOrEmpty(recipientCert.ToString()))
                {
                    throw new ArgumentNullException(recipientCert.ToString(), "if encryptionAlgorithm is specified then recipientCert must be specified");
                }

                byte[] signedContentTypeHeader = Encoding.ASCII.GetBytes("Content-Type: " + contentType + "\r\n");
                byte[] contentWithContentTypeHeaderAdded = As2MimeUtilities.ConcatBytes(signedContentTypeHeader, content);

                content = As2Encryption.Encrypt(contentWithContentTypeHeaderAdded, recipientCert, EncryptionAlgorithm.Des3);

                contentType = "application/pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"";
            }

            http.ContentType = contentType;
            http.ContentLength = content.Length;

            SendWebRequest(http, content);

            return HandleWebResponse(http);
        }

        private static HttpStatusCode HandleWebResponse(HttpWebRequest http)
        {
            HttpWebResponse response = (HttpWebResponse)http.GetResponse();

            //const string pwd = "MyCert";
            //SecureString securePwd = new SecureString();
            //Array.ForEach(pwd.ToArray(), securePwd.AppendChar);
            //securePwd.MakeReadOnly();
            //X509Certificate2 recipientCert = new X509Certificate2(@"c:\files\certs\MyPrivateCert.pfx", securePwd);

            int length = (int)response.ContentLength;
            byte[] data = new byte[length];
            response.GetResponseStream()?.Read(data, 0, length);

            //SignedCms signedCms = new SignedCms();
            //signedCms.Decode(data);
            //signedCms.CheckSignature(new X509Certificate2Collection(recipientCert), false);

            string mdnResponse = Encoding.ASCII.GetString(data);
            string mdnHeaders = response.Headers.ToString();

            File.WriteAllText(@"c:\files\MDN\" + http.Headers["Subject"] + "MDN", mdnResponse + mdnHeaders);

            return response.StatusCode;
        }

        public static void SendWebRequest(HttpWebRequest http, byte[] fileData)
        {
            Stream oRequestStream = http.GetRequestStream();
            oRequestStream.Write(fileData, 0, fileData.Length);
            oRequestStream.Flush();
            oRequestStream.Close();
        }
    }
}
