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

            http.UserAgent = "Test Agent";


            //These Headers are common localStation all transactions
            http.Headers.Add("Mime-Version", "1.0");
            http.Headers.Add("AS2-Version", "1.2");
            http.Headers.Add("AS2-From", partner);
            http.Headers.Add("AS2-To", localStation);
            http.Headers.Add("Subject", filename + " transmission.");
            http.Headers.Add("Date", DateTime.Now.ToString("R"));
            http.Headers.Add("Recipient-adress", "https://localhost:44333/api/as2");
            http.Headers.Add("Message-ID", "<AS2_" + DateTime.Now.ToString("g") + ">");
            //  Add for ASYNC MDN  http.Headers.Add("Receipt-delivery-option", "");
            http.Headers.Add("Disposition-notification-to", partner);
            http.Headers.Add("Disposition-notification-options", "signed-receipt-protocol=Required, pkcs7-signature; signed-receipt-micalg=Required, sha-256");
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

            byte[] encodedUnencryptedMessage = As2Encryption.Decrypt(content, recipientCert);
            string decodedMessage =
                Encoding.ASCII.GetString(encodedUnencryptedMessage, 0, encodedUnencryptedMessage.Length);

            http.ContentType = contentType;
            http.ContentLength = content.Length;

            SendWebRequest(http, content);

            return HandleWebResponse(http, decodedMessage);
        }

        private static HttpStatusCode HandleWebResponse(HttpWebRequest http, string decodedMessage)
        {
            try
            {
                HttpWebResponse response = (HttpWebResponse)http.GetResponse();

                int length = (int)response.ContentLength;
                byte[] data = new byte[length];
                response.GetResponseStream()?.Read(data, 0, length);

                string mdnResponse = Encoding.ASCII.GetString(data);
                string mdnHeaders = response.Headers.ToString();

                if (string.IsNullOrEmpty(mdnHeaders) || string.IsNullOrEmpty(mdnResponse))
                    throw new WebException();

                bool mdnVerification = MdnVerification(mdnResponse, decodedMessage, http);

                if (mdnVerification)
                {
                    File.WriteAllText(@"c:\files\MDN\VerifiedMDN\" + http.Headers["Subject"] + "MDN.MDN", mdnResponse);
                    File.WriteAllText(@"c:\files\MDN\VerifiedMDN\" + http.Headers["Subject"] + "Headers.MDN", mdnHeaders);
                }
                else
                {
                    File.WriteAllText(@"c:\files\MDN\" + http.Headers["Subject"] + "MDN.MDN", mdnResponse);
                    File.WriteAllText(@"c:\files\MDN\" + http.Headers["Subject"] + "Headers.MDN", mdnHeaders);
                }

                return response.StatusCode;
            }
            catch (WebException)
            {
                return HttpStatusCode.InternalServerError;
            }

        }

        /****** MDN gets verified 2/3 ways according to
         * https://docs.microsoft.com/en-us/biztalk/core/mdn-messages *
         ******/
        private static bool MdnVerification(string mdnMessage, string decodedMessage, HttpWebRequest http)
        {
            #region MicCheck

            string messageDigest = http.Headers["Disposition-notification-options"]
                .Split(new[] { "; " }, StringSplitOptions.RemoveEmptyEntries)[1]
                .Split(new[] { ", " }, StringSplitOptions.RemoveEmptyEntries)[1];
            string calculatedMic = As2Encryption.CalculateMic(decodedMessage, messageDigest);

            int micStart = mdnMessage.IndexOf("MIC: ", StringComparison.Ordinal);
            micStart += 5;
            int micEnd = mdnMessage.IndexOf(messageDigest, StringComparison.Ordinal);
            micEnd = micEnd - 2;
            int micLength = micEnd - micStart;
            string receivedMic = mdnMessage.Substring(micStart, micLength);
            bool micVerified = receivedMic == calculatedMic;

            #endregion

            #region MessageIdCheck

            string originalMessageId = http.Headers["Message-ID"];

            int messageIdStart = mdnMessage.IndexOf("ID: ", StringComparison.Ordinal);
            messageIdStart += 4;
            int messageIdEnd = mdnMessage.IndexOf("\r\nDisposition: ", StringComparison.Ordinal);
            int messageLength = messageIdEnd - messageIdStart;
            string receivedMessageId = mdnMessage.Substring(messageIdStart, messageLength);
            bool messageIdVerified = receivedMessageId == originalMessageId;

            #endregion

            return micVerified && messageIdVerified;
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
