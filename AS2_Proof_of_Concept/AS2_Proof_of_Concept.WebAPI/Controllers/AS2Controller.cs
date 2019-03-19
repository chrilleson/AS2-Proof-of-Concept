using System;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using AS2_Proof_of_Concept.WebAPI.AS2;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AS2_Proof_of_Concept.WebAPI.Controllers
{
    [Route("api/[controller]")]
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
            const string pwd = "MyCert";
            SecureString securePwd = new SecureString();
            Array.ForEach(pwd.ToArray(), securePwd.AppendChar);
            securePwd.MakeReadOnly();
            X509Certificate2 recipientCert = new X509Certificate2(@"C:\files\certs\MyPrivateCert.pfx", securePwd);
            //X509Certificate2 senderCert = new X509Certificate2(@"C:\files\certs\MyPartnersPublicCert.p7b");

            if (Request.ContentLength == null) return;

            int length = (int)Request.ContentLength;
            byte[] requestBody = new byte[length];
            string filename = Request.Headers["Subject"];
            Request.Body.Read(requestBody, 0, length);

            try
            {
                byte[] encodedUnencryptedMessage = As2Encryption.Decrypt(requestBody);

                /*****      This part extracts the Signature
                 *
                 * string messageWithContentTypeLineAndMimeHeaders = Encoding.ASCII.GetString(encodedUnencryptedMessage);
                //// when encrypted, the Content-Type line is actually stored in the start of the message
                //int firstBlankLineInMessage = messageWithContentTypeLineAndMimeHeaders.IndexOf(Environment.NewLine + Environment.NewLine, StringComparison.Ordinal);
                //string firstContentType = messageWithContentTypeLineAndMimeHeaders.Substring(0, firstBlankLineInMessage);
                //string getBoundary = As2MimeUtilities.GetBoundaryFromContentType(firstContentType);
                //string innerContent = As2MimeUtilities.ExtractPayload(messageWithContentTypeLineAndMimeHeaders, getBoundary);
                //innerContent = innerContent + "\r\n\r\n--" + getBoundary + "--";
                //string signature = As2MimeUtilities.ExtractPayload(innerContent, getBoundary);
                //var receivedSignature =
                //    string.Equals(Encoding.ASCII.GetString(senderCert.GetRawCertData()), signature);
                //if(receivedSignature)
                //    Console.WriteLine("Signature is valid.");
                *****/

                string decodedMessage = Encoding.ASCII.GetString(encodedUnencryptedMessage, 0, encodedUnencryptedMessage.Length);
                System.IO.File.WriteAllText(@"c:\files\Dump\" + filename + "txt", decodedMessage);

                string messageDigest = Request.Headers["Disposition-notification-options"].ToString()
                    .Split(new[] { "; " }, StringSplitOptions.RemoveEmptyEntries)[1]
                    .Split(new[] { ", " }, StringSplitOptions.RemoveEmptyEntries)[1];

                string calculatedMic = CalculateMic(decodedMessage, messageDigest);

                var boundary = As2MimeUtilities.MimeBoundary();
                var mdnMessage = new StringBuilder("Content-Type: multipart/report; report-type=disposition-notification; \r\n\t")
                    .Append("boundary=\"").Append(boundary).Append("\"\r\n\r\n")
                    .Append("--").Append(boundary).Append("\r\n")
                    .Append("Content-Type: text/plain\r\n")
                    .Append("Content-Transfer-Encoding: 7bit\r\n\r\n")
                    .Append("The AS2 message has been received.\r\n")
                    .Append("--").Append(boundary).Append("\r\n")
                    .Append("Content-Type: message/disposition-notification\r\n")
                    .Append("Content-Transfer-Encoding: 7bit\r\n\r\n")
                    .Append("Reporting-UA: Test\r\n")
                    .Append("Original-Recipient: rfc822; ").Append(Request.Headers["AS2-To"]).Append("\r\n")
                    .Append("Final-Recipient: rfc822; ").Append(Request.Headers["AS2-From"]).Append("\r\n")
                    .Append("Original-Message-ID: ").Append(Request.Headers["Message-Id"]).Append("\r\n")
                    .Append("Disposition: automatic-action/MDN-sent-automatically; processed\r\n")
                    .Append("Received-Content-MIC: ").Append(calculatedMic).Append(", ").Append(messageDigest).Append("\r\n\r\n")
                    .Append("--").Append(boundary).Append("--");

                byte[] content = Encoding.ASCII.GetBytes(mdnMessage.ToString());

                content = As2MimeUtilities.Sign(content, recipientCert, out var contentType);

                Response.Headers["Date"] = DateTime.Now.ToString("R");
                Response.Headers["MIME-Version"] = "1.0";
                Response.Headers["AS2-Version"] = "1.2";
                Response.Headers["Subject"] = "AS2 MDN";
                Response.Headers["Message-ID"] = Request.Headers["Message-ID"];
                Response.Headers["AS2-To"] = Request.Headers["AS2-From"];
                Response.Headers["AS2-From"] = Request.Headers["AS2-To"];

                Response.ContentLength = content.Length;
                Response.ContentType = contentType;

                Response.Body.Write(content, 0, content.Length);
            }
            catch (CryptographicException ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        private static string CalculateMic(string content, string micAlg)
        {
            content = content.Contains("\r") ? content : content.Replace("\n", "\r\n");
            switch (micAlg)
            {
                case "sha1":
                case "sha-1":
                    var sha1 = SHA1.Create();
                    return Convert.ToBase64String(sha1.ComputeHash(Encoding.ASCII.GetBytes(content)));
                case "sha256":
                case "sha-256":
                    var sha256 = SHA256.Create();
                    return Convert.ToBase64String(sha256.ComputeHash(Encoding.ASCII.GetBytes(content)));
            }
            return "";
        }
    }
}