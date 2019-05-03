using System;
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
    [ApiController]
    public class WinLibraryController : ControllerBase
    {
        private static readonly X509Certificate2 MyPartnersPrivateCert = new X509Certificate2(@"C:\Users\chris\source\repos\AS2 Proof of Concept\AS2_Proof_of_Concept\AS2_Proof_of_Concept.WebAPI\certs\MyPartnersPrivateCert.pfx", "MyPartnersKey");
        private static readonly X509Certificate2 MyPrivateCert = new X509Certificate2(@"C:\Users\chris\source\repos\AS2 Proof of Concept\AS2_Proof_of_Concept\AS2_Proof_of_Concept.WebAPI\certs\MyPrivateCert.pfx", "MyPrivateKey");

        [HttpGet]
        public void Get()
        {
            Response.WriteAsync($"<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\"><HTML><HEAD><TITLE>Generic AS2 Receiver</TITLE></HEAD><BODY><H1>{Response.StatusCode}</H1><hd>This is to inform you that the AS2 interface is working for WinLibraryController and is accessible from your location. This is the standard response to all who would send a GET request to this page instead of the POST context.Request defined by the AS2 Draft Specifications.<hd><BODY></HTML>");
        }

        [HttpPost]
        [Consumes("application/pkcs7-mime")]
        public void IncomingMessage()
        {

            if (Request.ContentLength == null) return;

            int length = (int)Request.ContentLength;
            byte[] requestBody = new byte[length];
            string filename = Request.Headers["Subject"];
            Request.Body.Read(requestBody, 0, requestBody.Length);

            string as2To = Request.Headers["AS2-To"].ToString();
            string as2From = Request.Headers["AS2-From"].ToString();
            string originalMessageId = Request.Headers["Message-Id"].ToString();

            try
            {
                #region Decrypt message
                
                //Decrypt the message
                byte[] encodedUnencryptedMessage = As2Encryption.Decrypt(requestBody, MyPartnersPrivateCert);
                string decodedMessage = Encoding.ASCII.GetString(encodedUnencryptedMessage);
                System.IO.File.WriteAllText(@"c:\files\Dump\WinLibrary\" + filename + " RawMessageDecrypted.txt", decodedMessage);

                #endregion

                #region Extracts and Verifies the signature

                // Extracts the signature
                int firstBlankLineInMessage =
                    decodedMessage.IndexOf(Environment.NewLine + Environment.NewLine, StringComparison.Ordinal);
                string firstContentType = decodedMessage.Substring(0, firstBlankLineInMessage);
                string getBoundary = As2MimeUtilities.GetBoundaryFromContentType(firstContentType);
                string receivedSignature = As2MimeUtilities.ExtractSignature(decodedMessage, getBoundary);
                System.IO.File.WriteAllText(@"c:\files\ErrorCheck\" + filename + " ExtractionCheck.txt",
                    receivedSignature);

                #endregion

                #region Verifies the signature

                ContentInfo contentInfo = new ContentInfo(encodedUnencryptedMessage);
                SignedCms signedCms = new SignedCms(contentInfo, false);

                signedCms.Decode(Convert.FromBase64String(receivedSignature.Split(new[] { "\r\n\r\n" },
                    StringSplitOptions.RemoveEmptyEntries)[0]));

                signedCms.CheckSignature(new X509Certificate2Collection(MyPrivateCert), false);

                #endregion

                string payload = Encoding.ASCII.GetString(signedCms.ContentInfo.Content, 0,
                    signedCms.ContentInfo.Content.Length);
                System.IO.File.WriteAllText(@"c:\files\Dump\WinLibrary\Verified\" + filename + " Payload.txt", payload);

                #region MDN message

                #region CalculateMIC

                string digestAlg = Request.Headers["Disposition-notification-options"].ToString()
                    .Split(new[] { "; " }, StringSplitOptions.RemoveEmptyEntries)[1]
                    .Split(new[] { ", " }, StringSplitOptions.RemoveEmptyEntries)[1];

                string calculatedMic = As2Encryption.CalculateMic(decodedMessage, digestAlg);

                #endregion

                #region Create the MDN

                Response.Headers.Add("Date", DateTime.Now.ToString("R"));
                Response.Headers.Add("MIME-Version", "1.0");
                Response.Headers.Add("as2-version", "1.2");
                Response.Headers.Add("Subject", "AS2 message");
                Response.Headers.Add("message-id", $"<AS2_{DateTime.Now:g}@{as2From}_{as2To}>");
                Response.Headers.Add("as2-to", "ChrisAS2Station");
                Response.Headers.Add("as2-from", "ChrisAS2Partner");
                Response.Headers.Add("To", "support@edisolutions.se");
                Response.Headers.Add("ediint-features", "multiple-attachments, CEM");

                //Create the content of the MDN message
                var boundary = As2MimeUtilities.MimeBoundary();
                string mdnMessage =
                    $"Content-Type: multipart/report; report-type=disposition-notification; boundary=\"----=_Part{boundary}\"{Environment.NewLine}{Environment.NewLine}"
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

                content = As2MimeUtilities.MdnSignature(content, MyPartnersPrivateCert, out string contentType);

                string mdnResponse = Encoding.ASCII.GetString(content);
                System.IO.File.WriteAllText($"c:\\files\\MDN\\WinLibrary\\{filename} MDN.MDN", mdnResponse);

                Response.ContentLength = content.Length;
                Response.ContentType = contentType;

                Response.Body.Write(content, 0, content.Length);


                #endregion

                #endregion
            }
            catch (CryptographicException ex)
            {
                string error = ex.Message + Environment.NewLine + Environment.NewLine + ex.StackTrace + Environment.NewLine + Environment.NewLine + ex.InnerException?.Message;
                System.IO.File.WriteAllText(@"c:\files\ErrorCheck\" + filename + " error.txt", error);

                Response.StatusCode = 500;
            }
        }
    }
}
