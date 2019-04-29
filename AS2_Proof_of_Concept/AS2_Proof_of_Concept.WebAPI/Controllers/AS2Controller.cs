using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using AS2_Proof_of_Concept.WebAPI.AS2;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MimeKit;
using MimeKit.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using CmsSigner = MimeKit.Cryptography.CmsSigner;

namespace AS2_Proof_of_Concept.WebAPI.Controllers
{
    public class As2Controller : Controller
    {
        private readonly MySecureMimeContext _ctxMySecureMimeContext = new MySecureMimeContext();

        private readonly X509Certificate _myPartnersPrivateCert = new X509Certificate(@"C:\files\certs\MyPartnersPrivateCert.pfx", "MyPartnersKey");
        private readonly X509Certificate2 _myPrivateCert = new X509Certificate2(@"C:\files\certs\com01\MyPrivateCert.pfx", "MyPrivateKey");
        private readonly X509Certificate2 _verifySignatureCertMyCert = new X509Certificate2(@"C:\files\certs\com01\MyPublicCert.cer");
        private readonly X509Certificate2 _verifySignatureCertCom01 = new X509Certificate2(@"c:\files\certs\com01\as2com.edisolutions.se.20190118.cer");

        private void ImportCertificates()
        {
            var bouncyMyPartnersPrivateCert =
                Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(_myPartnersPrivateCert);
            var bouncyMyPrivateCert =
                Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(_myPrivateCert);
            var bouncyVerifySignatureCertMyCert =
                Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(_verifySignatureCertMyCert);
            var bouncyVerifySignatureCertCom01 =
                Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(_verifySignatureCertCom01);

            List<Org.BouncyCastle.X509.X509Certificate> x509Certificates =
                new List<Org.BouncyCastle.X509.X509Certificate>
                {
                    bouncyMyPartnersPrivateCert,
                    bouncyMyPrivateCert,
                    bouncyVerifySignatureCertMyCert,
                    bouncyVerifySignatureCertCom01
                };

            foreach (var x509Certificate in x509Certificates)
            {
                _ctxMySecureMimeContext.Import(x509Certificate);
            }
        }

        [HttpGet]
        public void Get()
        {
            Response.WriteAsync($"<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\"><HTML><HEAD><TITLE>Generic AS2 Receiver</TITLE></HEAD><BODY><H1>{Response.StatusCode}</H1><hd>This is to inform you that the AS2 interface is working and is accessible from your location. This is the standard response to all who would send a GET request to this page instead of the POST context.Request defined by the AS2 Draft Specifications.<hd><BODY></HTML>");
        }

        [HttpPost]
        [Consumes("application/pkcs7-mime")]
        public void IncomingMessage()
        {
            ImportCertificates();

            CryptographyContext.Register(typeof(MySecureMimeContext));

            if (Request.ContentLength == null) return;

            int length = (int)Request.ContentLength;
            byte[] requestBody = new byte[length];
            string filename = Request.Headers["Subject"];
            Request.Body.Read(requestBody, 0, requestBody.Length);

            string as2To = Request.Headers["AS2-To"].ToString();
            string originalMessageId = Request.Headers["Message-Id"].ToString();

            try
            {
                var encrypted = new StringBuilder("Content-Type: ").Append(Request.Headers["Content-Type"]).Append(Environment.NewLine);
                encrypted.Append("Content-disposition: ").Append(Request.Headers["Content-disposition"])
                    .Append(Environment.NewLine);
                encrypted.Append(("Content-Transfer-Encoding: ")).Append(Request.Headers["Content-Transfer-Encoding"])
                    .Append(Environment.NewLine + Environment.NewLine);

                var encryptedBytes = Encoding.ASCII.GetBytes(encrypted.ToString()).Concat(requestBody).ToArray();
                var decrypted = (MimeMessage.Load(new MemoryStream(encryptedBytes)).Body as ApplicationPkcs7Mime)?.Decrypt();

                using (var o = System.IO.File.OpenWrite(@"c:\files\Dump\" + filename + " RawMessageDecrypted.txt"))
                    decrypted?.WriteTo(o);

                var signed = decrypted as MultipartSigned;

                if (signed == null) return;
                foreach (var signature in signed.Verify())
                {
                    bool valid = signature.Verify();

                    if (!valid)
                        throw new DigitalSignatureVerifyException("Invalid signature");

                    using (var o = System.IO.File.OpenWrite(@"c:\files\Dump\Verified\" + filename + " Payload.txt"))
                        ((MimePart)signed[0]).Content.DecodeTo(o);

                }

                var decodedMsg = signed.First().ToString();
                string digestAlg = Request.Headers["Disposition-notification-options"].ToString()
                    .Split(new[] { "; " }, StringSplitOptions.RemoveEmptyEntries)[1]
                    .Split(new[] { ", " }, StringSplitOptions.RemoveEmptyEntries)[1];

                string calculatedMic = As2Encryption.CalculateMic(decodedMsg, digestAlg);


                var aReportParts = new MultipartReport("disposition-notification");
                var aTextPart = new TextPart()
                {
                    ContentTransferEncoding = ContentEncoding.SevenBit,
                    Content = new MimeContent(
                        new MemoryStream(Encoding.ASCII.GetBytes("The AS2 message have been received.")))
                };

                var h1 = new HeaderList
                {
                    new Header("Reporting-UA", "ChrisAS2Test"),
                    new Header("Original-Recipient", $"rfc822 {as2To}"),
                    new Header("Final-Recipient", $"rfc822 {as2To}"),
                    new Header("Original-Message-ID", originalMessageId),
                    new Header("Disposition", "automatic-action/MDN-sent-automatically; processed"),
                    new Header("Received-Content-MIC",$"{calculatedMic}, {digestAlg}")
                };

                var mdnContent = new MemoryStream();
                h1.WriteTo(mdnContent);
                var aReportPart = new MessageDispositionNotification()
                {
                    Content = new MimeContent(mdnContent)
                };
                aReportParts.Add(aTextPart);
                aReportParts.Add(aReportPart);

                var headerAndBody = MultipartSigned.Create(_ctxMySecureMimeContext, new CmsSigner(@"c:\files\certs\MyPartnersPrivateCert.pfx", "MyPartnersKey"), aReportParts).ToString();

                mdnContent.Close();

                Response.Headers.Add("as2-to", "ChrisAS2Station");
                Response.Headers.Add("as2-from", "ChrisAS2Partner");

                var contentType = headerAndBody.Split(new[] { Environment.NewLine + Environment.NewLine },
                    StringSplitOptions.RemoveEmptyEntries)[0];
                var content = Encoding.ASCII.GetBytes(headerAndBody.Replace(contentType, "")
                    .Substring((Environment.NewLine + Environment.NewLine).Count()));
                Response.ContentType = contentType.Replace(Environment.NewLine + "\t", " ")
                    .Split(new[] { ": " }, StringSplitOptions.RemoveEmptyEntries)[1];
                Response.ContentLength = content.Length;

                System.IO.File.WriteAllText(@"c:\files\MDN\com01\mdnToCom01 MDN.MDN", Encoding.ASCII.GetString(content));

                Response.Body.Write(content, 0, content.Length);

                #region Old way

                ////Decrypt the message
                //byte[] encodedUnencryptedMessage = As2Encryption.Decrypt(requestBody, myPartnersPrivateCert);
                //string decodedMessage = Encoding.ASCII.GetString(encodedUnencryptedMessage);
                //System.IO.File.WriteAllText(@"c:\files\Dump\" + filename + " RawMessageDecrypted.txt", decodedMessage);

                //#region Extracts and Verifies the signature

                //// Extracts the signature
                //int firstBlankLineInMessage = decodedMessage.IndexOf(Environment.NewLine + Environment.NewLine, StringComparison.Ordinal);
                //string firstContentType = decodedMessage.Substring(0, firstBlankLineInMessage);
                //string getBoundary = As2MimeUtilities.GetBoundaryFromContentType(firstContentType);
                //string receivedSignature = As2MimeUtilities.ExtractSignature(decodedMessage, getBoundary);
                //System.IO.File.WriteAllText(@"c:\files\ErrorCheck\" + filename + " ExtractionCheck.txt", receivedSignature);

                //Verifies the signature

                //ContentInfo contentInfo = new ContentInfo(encodedUnencryptedMessage);
                //SignedCms signedCms = new SignedCms();
                //signedCms.Decode(Convert.FromBase64String(receivedSignature.Split(new[] { "\r\n\r\n" }, StringSplitOptions.RemoveEmptyEntries)[0]));
                //System.IO.File.WriteAllText(@"c:\files\ErrorCheck\" + filename + "ReceivedCheck.txt", "signedCms has decoded the received signature.");
                //signedCms.CheckSignature(certificate2Collection, true);
                //System.IO.File.WriteAllText(@"c:\files\ErrorCheck\" + filename + " SignatureCheck.txt", "Signature check: OK.");

                //#endregion

                //string payload = Encoding.ASCII.GetString(signedCms.ContentInfo.Content, 0, signedCms.ContentInfo.Content.Length);
                //System.IO.File.WriteAllText(@"c:\files\Dump\Verified\" + filename + " Payload.txt", payload);

                //#region MDN message

                //#region CalculateMIC

                //string digestAlg = Request.Headers["Disposition-notification-options"].ToString()
                //    .Split(new[] { "; " }, StringSplitOptions.RemoveEmptyEntries)[1]
                //    .Split(new[] { ", " }, StringSplitOptions.RemoveEmptyEntries)[1];

                //string calculatedMic = As2Encryption.CalculateMic(decodedMessage, digestAlg);

                //#endregion

                //#region Create the MDN

                //Response.Headers.Add("Date", DateTime.Now.ToString("R"));
                //Response.Headers.Add("MIME-Version", "1.0");
                //Response.Headers.Add("as2-version", "1.2");
                //Response.Headers.Add("Subject", "AS2 message");
                //Response.Headers.Add("message-id", $"<AS2_{DateTime.Now:g}@{as2From}_{as2To}>");
                //Response.Headers.Add("as2-to", "ChrisAS2Station");
                //Response.Headers.Add("as2-from", "ChrisAS2Partner");
                //Response.Headers.Add("To", "support@edisolutions.se");
                //Response.Headers.Add("ediint-features", "multiple-attachments, CEM");

                ////Create the content of the MDN message
                //var boundary = As2MimeUtilities.MimeBoundary();
                //string mdnMessage =
                //    $"Content-Type: multipart/report; report-type=disposition-notification; boundary=\"----=_Part{boundary}\"{Environment.NewLine}{Environment.NewLine}"
                //    + $"------=_Part{boundary}{Environment.NewLine}"
                //    + $"Content-Type: text/plain{Environment.NewLine}"
                //    + $"Content-Transfer-Encoding: 7bit{Environment.NewLine}{Environment.NewLine}"
                //    + $"The AS2 message has been received.{Environment.NewLine}"
                //    + $"------=_Part{boundary}{Environment.NewLine}"
                //    + $"Content-Type: message/disposition-notification{Environment.NewLine}"
                //    + $"Content-Transfer-Encoding: 7bit{Environment.NewLine}{Environment.NewLine}"
                //    + $"Reporting-UA: ChrisAS2Test{Environment.NewLine}"
                //    + $"Original-Recipient: rfc822; {as2To}{Environment.NewLine}"
                //    + $"Final-Recipient: rfc822; {as2To}{Environment.NewLine}"
                //    + $"Original-Message-ID: {originalMessageId}{Environment.NewLine}"
                //    + $"Disposition: automatic-action/MDN-sent-automatically; processed{Environment.NewLine}"
                //    + $"Received-Content-MIC: {calculatedMic}, {digestAlg}{Environment.NewLine}{Environment.NewLine}"
                //    + $"------=_Part{boundary}--{Environment.NewLine}{Environment.NewLine}";

                //byte[] content = Encoding.ASCII.GetBytes(mdnMessage);

                //content = As2MimeUtilities.MdnSignature(content, myPartnersPrivateCert, out string contentType);

                //string mdnResponse = Encoding.ASCII.GetString(content);
                //System.IO.File.WriteAllText(@"c:\files\ErrorCheck\mdnToCom01 MDN.MDN", mdnResponse);

                //Response.ContentLength = content.Length;
                //Response.ContentType = contentType;

                //Response.Body.Write(content, 0, content.Length);


                //#endregion


                //#endregion

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