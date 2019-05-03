using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using AS2_Proof_of_Concept.WebAPI.AS2;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MimeKit;
using MimeKit.Cryptography;
using CmsSigner = MimeKit.Cryptography.CmsSigner;

namespace AS2_Proof_of_Concept.WebAPI.Controllers
{
    [Route("api/[controller]")]
    public class MimeKitController : Controller
    {
        private readonly MySecureMimeContext _ctxMySecureMimeContext = new MySecureMimeContext();

        private readonly X509Certificate2 _myPartnersPrivateCert = new X509Certificate2(@"C:\Users\chris\source\repos\AS2 Proof of Concept\AS2_Proof_of_Concept\AS2_Proof_of_Concept.WebAPI\certs\MyPartnersPrivateCert.pfx", "MyPartnersKey");
        private readonly X509Certificate2 _myPrivateCert = new X509Certificate2(@"C:\Users\chris\source\repos\AS2 Proof of Concept\AS2_Proof_of_Concept\AS2_Proof_of_Concept.WebAPI\certs\MyPrivateCert.pfx", "MyPrivateKey");
        private readonly X509Certificate2 _verifySignatureCertMyCert = new X509Certificate2(@"C:\Users\chris\source\repos\AS2 Proof of Concept\AS2_Proof_of_Concept\AS2_Proof_of_Concept.WebAPI\certs\MyPublicCert.cer");
        private readonly X509Certificate2 _verifySignatureCertCom01 = new X509Certificate2(@"C:\files\certs\com01\as2com.edisolutions.se.20190118.cer");

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
            Response.WriteAsync($"<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\"><HTML><HEAD><TITLE>Generic AS2 Receiver</TITLE></HEAD><BODY><H1>{Response.StatusCode}</H1><hd>This is to inform you that the AS2 interface is working for MimeKitController and is accessible from your location. This is the standard response to all who would send a GET request to this page instead of the POST context.Request defined by the AS2 Draft Specifications.<hd><BODY></HTML>");
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
            Request.Body.Read(requestBody, 0, requestBody.Length);

            string filename = Request.Headers["Subject"];
            string as2To = Request.Headers["AS2-To"].ToString();
            string originalMessageId = Request.Headers["Message-Id"].ToString();

            try
            {
                #region Decrypt

                var encrypted = new StringBuilder("Content-Type: ").Append(Request.Headers["Content-Type"]).Append(Environment.NewLine);
                encrypted.Append("Content-disposition: ").Append(Request.Headers["Content-disposition"])
                    .Append(Environment.NewLine);
                encrypted.Append(("Content-Transfer-Encoding: ")).Append(Request.Headers["Content-Transfer-Encoding"])
                    .Append(Environment.NewLine + Environment.NewLine);

                var encryptedBytes = Encoding.ASCII.GetBytes(encrypted.ToString()).Concat(requestBody).ToArray();

                var decrypted = (MimeMessage.Load(new MemoryStream(encryptedBytes)).Body as ApplicationPkcs7Mime)?.Decrypt();

                using (var o = System.IO.File.OpenWrite(@"c:\files\Dump\MimeKit\" + filename + " RawMessageDecrypted.txt"))
                    decrypted?.WriteTo(o);

                #endregion

                #region Verify Signature

                var signed = decrypted as MultipartSigned;
                if (signed == null) return;

                if (!signed.Verify().First().Verify())
                    throw new CryptographicException();

                #endregion

                #region Calculate MIC

                var decodedMsg = signed.First().ToString();
                string digestAlg = Request.Headers["Disposition-notification-options"].ToString()
                    .Split(new[] { "; " }, StringSplitOptions.RemoveEmptyEntries)[1]
                    .Split(new[] { ", " }, StringSplitOptions.RemoveEmptyEntries)[1];

                string calculatedMic = As2Encryption.CalculateMic(decodedMsg, digestAlg);                

                #endregion

                #region Create MDN

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

                var headerAndBody = MultipartSigned.Create(_ctxMySecureMimeContext, new CmsSigner(@"C:\Users\chris\source\repos\AS2 Proof of Concept\AS2_Proof_of_Concept\AS2_Proof_of_Concept.WebAPI\certs\MyPartnersPrivateCert.pfx", "MyPartnersKey"), aReportParts).ToString();

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

                System.IO.File.WriteAllText($"c:\\files\\MDN\\MimeKit\\{filename} MDN.MDN", Encoding.ASCII.GetString(content));

                Response.Body.Write(content, 0, content.Length);                

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