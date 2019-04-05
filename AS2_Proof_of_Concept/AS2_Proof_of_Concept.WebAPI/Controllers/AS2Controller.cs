using System;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using AS2_Proof_of_Concept.WebAPI.AS2;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AS2_Proof_of_Concept.WebAPI.Controllers
{
    public class As2Controller : Controller
    {
        [HttpGet]
        public void Get()
        {
            Response.WriteAsync($"<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\"><HTML><HEAD><TITLE>Generic AS2 Receiver</TITLE></HEAD><BODY><H1>{Response.StatusCode}</H1><hd>This is to inform you that the AS2 interface is working and is accessible from your location. This is the standard response to all who would send a GET request to this page instead of the POST context.Request defined by the AS2 Draft Specifications.<hd><BODY></HTML>");
        }

        [HttpPost]
        [Consumes("application/pkcs7-mime")]
        public void IncomingMessage()
        {

            const string pwd = "MyPartnersKey";
            SecureString securePwd = new SecureString();
            Array.ForEach(pwd.ToArray(), securePwd.AppendChar);
            securePwd.MakeReadOnly();
            X509Certificate2 decryptionAndSigningCert = new X509Certificate2(@"C:\files\certs\MyPartnersPrivateCert.pfx", securePwd);
            X509Certificate2 verifySignatureCert = new X509Certificate2(@"C:\files\certs\com01\MyPublicCert.cer");

            //const string pwd = "MyPrivateKey";
            //SecureString securePwd = new SecureString();
            //Array.ForEach(pwd.ToArray(), securePwd.AppendChar);
            //securePwd.MakeReadOnly();
            //X509Certificate2 decryptionAndSigningCert = new X509Certificate2(@"C:\files\certs\com01\MyPrivateCert.pfx", securePwd);
            //X509Certificate2 verifySignatureCert = new X509Certificate2(@"C:\files\certs\com01\as2com.edisolutions.se.20190118.cer");

            if (Request.ContentLength == null) return;

            int length = (int)Request.ContentLength;
            byte[] requestBody = new byte[length];
            string filename = Request.Headers["Subject"];
            Request.Body.Read(requestBody, 0, length);

            string as2To = Request.Headers["AS2-To"].ToString();
            string as2From = Request.Headers["AS2-From"].ToString();
            string originalMessageId = Request.Headers["Message-Id"].ToString();


            try
            {
                //Decrypt the message
                byte[] encodedUnencryptedMessage = As2Encryption.Decrypt(requestBody, decryptionAndSigningCert);
                string decodedMessage = Encoding.ASCII.GetString(encodedUnencryptedMessage);
                System.IO.File.WriteAllText(@"c:\files\Dump\" + filename + " RawMessageDecrypted.txt", decodedMessage);

                #region Extracts and Verifies the signature

                // Extracts the signature
                int firstBlankLineInMessage = decodedMessage.IndexOf(Environment.NewLine + Environment.NewLine, StringComparison.Ordinal);
                string firstContentType = decodedMessage.Substring(0, firstBlankLineInMessage);
                string getBoundary = As2MimeUtilities.GetBoundaryFromContentType(firstContentType);
                string receivedSignature = As2MimeUtilities.ExtractSignature(decodedMessage, getBoundary);

                System.IO.File.WriteAllText(@"c:\files\ErrorCheck\" + filename + " ExtractionCheck.txt", receivedSignature);


                //Verifies the signature
                SignedCms signedCms = new SignedCms();
                signedCms.Decode(Convert.FromBase64String(receivedSignature.Split(new[] { "\r\n\r\n" }, StringSplitOptions.RemoveEmptyEntries)[0]));

                signedCms.CheckSignature(new X509Certificate2Collection(verifySignatureCert), false);
                System.IO.File.WriteAllText(@"c:\files\ErrorCheck\" + filename + " SignatureCheck.txt", "Signature check: OK.");

                #endregion

                string payload = Encoding.ASCII.GetString(signedCms.ContentInfo.Content, 0, signedCms.ContentInfo.Content.Length);
                System.IO.File.WriteAllText(@"c:\files\Dump\Verified\" + filename + " Payload.txt", payload);

                #region MDN message

                if (string.IsNullOrEmpty(Request.Headers["Disposition-notification-to"])) return;

                #region CalculateMIC

                string digestAlg = Request.Headers["Disposition-notification-options"].ToString()
                    .Split(new[] { "; " }, StringSplitOptions.RemoveEmptyEntries)[1]
                    .Split(new[] { ", " }, StringSplitOptions.RemoveEmptyEntries)[1];

                string calculatedMic = As2Encryption.CalculateMic(decodedMessage, digestAlg);

                #endregion

                var boundary = As2MimeUtilities.MimeBoundary();

                #region Add Headers to the response

                Response.Headers.Add("Date", DateTime.Now.ToString("R"));
                Response.Headers.Add("MIME-Version", "1.0");
                Response.Headers.Add("AS2-Version", "1.2");
                Response.Headers.Add("Subject", "AS2 MDN");
                Response.Headers.Add("Message-ID", $"<AS2_ {DateTime.Now:g}.{boundary}@{as2From}_{as2To}>");
                Response.Headers.Add("as2-to", as2From);
                Response.Headers.Add("as2-from", as2To);
                Response.Headers.Add("To", "support@edisolutions.se");

                #endregion

                #region Create the MDN

                //Create the content of the MDN message
                string mdnMessage =
                    $"AS2-Version: {Response.Headers["as2-version"]}{Environment.NewLine}"
                    + $"AS2-From: {Response.Headers["as2-from"]}{Environment.NewLine}"
                    + $"AS2-To: {Response.Headers["as2-to"]}{Environment.NewLine}"
                    + $"To: {Response.Headers["To"]}{Environment.NewLine}"
                    + $"Message-Id: {Response.Headers["Message-ID"]}{Environment.NewLine}"
                    + $"Subject: {Response.Headers["Subject"]}{Environment.NewLine}"
                    + "Content-Type: multipart/report; report-type=disposition-notification; "
                    + $"boundary=\"{boundary}\"{Environment.NewLine}{Environment.NewLine}"
                    + $"------=_Part{boundary}{Environment.NewLine}"
                    + $"Content-Type: text/plain{Environment.NewLine}"
                    + $"Content-Transfer-Encoding: 7bit{Environment.NewLine}{Environment.NewLine}"
                    + $"The AS2 message has been received.{Environment.NewLine}"
                    + $"------=_Part{boundary}{Environment.NewLine}"
                    + $"Content-Type: message/disposition-notification{Environment.NewLine}"
                    + $"Content-Transfer-Encoding: 7bit{Environment.NewLine}{Environment.NewLine}"
                    + $"Reporting-UA: ChrisAS2Test{Environment.NewLine}"
                    + $"Original-Recipient: rfc822; {as2To}{Environment.NewLine}"
                    + $"Final-Recipient: rfc822; {as2To}{Environment.NewLine}"
                    + $"Original-Message-ID: {originalMessageId}{Environment.NewLine}"
                    + $"Disposition: automatic-action/MDN-sent-automatically; processed{Environment.NewLine}"
                    + $"Received-Content-MIC: {calculatedMic}, {digestAlg}{Environment.NewLine}{Environment.NewLine}"
                    + $"------=_Part{boundary}--{Environment.NewLine}{Environment.NewLine}";

                byte[] content = Encoding.ASCII.GetBytes(mdnMessage);

                content = As2MimeUtilities.MdnSignature(content, decryptionAndSigningCert, out string contentType);

                string mdnResponse = Encoding.ASCII.GetString(content);
                System.IO.File.WriteAllText(@"c:\files\ErrorCheck\mdnToCom01 MDN.MDN", mdnResponse);

                #endregion

                Response.ContentLength = content.Length;
                Response.ContentType = contentType;
                Response.Body.Write(content, 0, content.Length);

                #endregion
            }
            catch (CryptographicException ex)
            {
                string error = ex.Message + Environment.NewLine + Environment.NewLine + ex.StackTrace;
                System.IO.File.WriteAllText(@"c:\files\ErrorCheck\" + filename + " error.txt", error);

                Response.StatusCode = 500;
            }
        }
    }
}