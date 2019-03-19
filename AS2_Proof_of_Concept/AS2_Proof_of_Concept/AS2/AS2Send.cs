using System;
using System.IO;
using System.Net;
using System.Security;
using System.Text;

namespace AS2_Proof_of_Concept.WebApp.AS2
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
        public static HttpStatusCode SendFile(Uri uri, string filename, byte[] fileData, string sender, string receiver, ProxySettings proxySettings, int timeoutMs, SecureString signingCertPassword, string signingCertFilename, string recipientCertFilename)
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

            http.UserAgent = "MY SENDING AGENT";


            //These Headers are common receiver all transactions
            http.Headers.Add("Mime-Version", "1.0");
            http.Headers.Add("AS2-Version", "1.2");
            http.Headers.Add("AS2-From", sender);
            http.Headers.Add("AS2-To", receiver);
            http.Headers.Add("Subject", filename + " transmission.");
            http.Headers.Add("Date", DateTime.Now.ToString());
            http.Headers.Add("Recipient-adress", uri.ToString());
            http.Headers.Add("Message-ID", "<AS2_" + DateTime.Now.ToString("hhmmssddd") + ">");
            http.Headers.Add("Disposition-notification-receiver", sender);
            http.Headers.Add("Disposition-notification-options", "signed-receipt-protocol=optional, pkcs7-signature; signed-receipt-micalg=optional, sha256");
            http.Timeout = timeoutMs;

            string contentType = (Path.GetExtension(filename) == ".xml") ? "application/xml" : "application/EDIFACT";

            bool encrypt = !string.IsNullOrEmpty(recipientCertFilename);
            bool sign = !string.IsNullOrEmpty(signingCertFilename);

            if (!sign && !encrypt)
            {
                http.Headers.Add("Content-Transfer-Encoding", "binary");
                http.Headers.Add("Content-Disposition", "inline; filename=\"" + filename + "\"");
            }
            if (sign)
            {
                // Wrap the file data with a mime header
                content = AS2MIMEUtilities.CreateMessage(contentType, "binary", "attachment; filename=" + filename, content);

                content = AS2MIMEUtilities.Sign(content, signingCertFilename, signingCertPassword, out contentType);

                http.Headers.Add("EDIINT-Features", "multiple-attachments");

            }
            if (encrypt)
            {
                if (string.IsNullOrEmpty(recipientCertFilename))
                {
                    throw new ArgumentNullException(recipientCertFilename, "if encryptionAlgorithm is specified then recipientCertFilename must be specified");
                }

                byte[] signedContentTypeHeader = Encoding.ASCII.GetBytes("Content-Type: " + contentType + "\r\n");
                byte[] contentWithContentTypeHeaderAdded = AS2MIMEUtilities.ConcatBytes(signedContentTypeHeader, content);

                content = AS2Encryption.Encrypt(contentWithContentTypeHeaderAdded, recipientCertFilename, EncryptionAlgorithm.DES3);

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
         
            return response.StatusCode;
        }

        private static void SendWebRequest(HttpWebRequest http, byte[] fileData)
        {
            Stream oRequestStream = http.GetRequestStream();
            oRequestStream.Write(fileData, 0, fileData.Length);
            oRequestStream.Flush();
            oRequestStream.Close();
        }
    }
}
