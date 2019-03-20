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
            X509Certificate2 senderCert = new X509Certificate2(@"c:\files\certs\MyPartnersPrivateCert.pfx", "MyPartnersKey");

            if (Request.ContentLength == null) return;

            int length = (int)Request.ContentLength;
            byte[] requestBody = new byte[length];
            string filename = Request.Headers["Subject"];
            Request.Body.Read(requestBody, 0, length);

            try
            {
                byte[] encodedUnencryptedMessage = As2Encryption.Decrypt(requestBody, senderCert);

                #region Extracts and Verifies the signature

                string messageWithContentTypeLineAndMimeHeaders = Encoding.ASCII.GetString(encodedUnencryptedMessage);

                // Extracts the signature
                int firstBlankLineInMessage = messageWithContentTypeLineAndMimeHeaders.IndexOf(Environment.NewLine + Environment.NewLine, StringComparison.Ordinal);
                string firstContentType = messageWithContentTypeLineAndMimeHeaders.Substring(0, firstBlankLineInMessage);
                string getBoundary = As2MimeUtilities.GetBoundaryFromContentType(firstContentType);
                string innerContent = As2MimeUtilities.ExtractPayload(messageWithContentTypeLineAndMimeHeaders, getBoundary);
                innerContent = innerContent + "\r\n\r\n--" + getBoundary + "--";
                string receivedSignature = As2MimeUtilities.ExtractPayload(innerContent, getBoundary);
                byte[] bReceivedSignature = Encoding.ASCII.GetBytes(receivedSignature);

                //Verifies the signature
                ContentInfo contentInfo = new ContentInfo(encodedUnencryptedMessage);
                SignedCms signedCms = new SignedCms(contentInfo, true);
                signedCms.Decode(Convert.FromBase64String(receivedSignature.Split(new[] { "\r\n\r\n" }, StringSplitOptions.RemoveEmptyEntries)[0]));
                signedCms.CheckSignature(new X509Certificate2Collection(senderCert), true);

                #endregion

                string decodedMessage = Encoding.ASCII.GetString(signedCms.ContentInfo.Content, 0, signedCms.ContentInfo.Content.Length);

                if (senderCert.GetPublicKey() == bReceivedSignature)
                    System.IO.File.WriteAllText(@"c:\files\Dump\Verified\" + filename + "txt", decodedMessage);
                else
                    System.IO.File.WriteAllText(@"c:\files\Dump\" + filename + "txt", decodedMessage);


                if (!string.IsNullOrEmpty(Request.Headers["Disposition-notification-to"].ToString()))
                {
                    #region CalculateMIC

                    string messageDigest = Request.Headers["Disposition-notification-options"].ToString()
                        .Split(new[] { "; " }, StringSplitOptions.RemoveEmptyEntries)[1]
                        .Split(new[] { ", " }, StringSplitOptions.RemoveEmptyEntries)[1];

                    string calculatedMic = As2Encryption.CalculateMic(decodedMessage, messageDigest);

                    #endregion

                    #region Create the MDN

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
                        .Append("--").Append(boundary).Append("--").Append("\r\n\r\n");

                    byte[] content = Encoding.ASCII.GetBytes(mdnMessage.ToString());

                    content = As2MimeUtilities.Sign(content, recipientCert, out var contentType);

                    #endregion

                    #region Add Headers to MDN

                    Response.Headers["Date"] = DateTime.Now.ToString("R");
                    Response.Headers["MIME-Version"] = "1.0";
                    Response.Headers["AS2-Version"] = "1.2";
                    Response.Headers["Subject"] = "AS2 MDN";
                    Response.Headers["Message-ID"] = Request.Headers["Message-ID"];
                    Response.Headers["AS2-To"] = Request.Headers["AS2-From"];
                    Response.Headers["AS2-From"] = Request.Headers["AS2-To"];

                    #endregion

                    Response.ContentLength = content.Length;
                    Response.ContentType = contentType;

                    Response.Body.Write(content, 0, content.Length);
                    Response.Body.Flush();
                    Response.Body.Dispose();
                }

                Request.Body.Flush();
                Request.Body.Dispose();
            }
            catch (CryptographicException ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
    }
}