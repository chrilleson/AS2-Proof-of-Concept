using System;
using System.Linq;
using System.Net;
using System.Security;
using System.Web;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace AS2_Proof_of_Concept.WebApplication
{
    public class As2Receive
    {

        public static void GetMessage(HttpResponse response)
        {
            response.Write(
                $"<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\"><HTML><HEAD><TITLE>Generic AS2 Receiver</TITLE></HEAD><BODY><H1>{response.Status}</H1><hd>This is to inform you that the AS2 interface is working and is accessible from your location. This is the standard response to all who would send a GET request to this page instead of the POST context.Request defined by the AS2 Draft Specifications.<hd><BODY></HTML>");
        }

        public static void BadRequest(HttpResponse response, string message)
        {
            response.StatusCode = (int)HttpStatusCode.BadRequest;
            response.Write(
                $"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\"><HTML><HEAD><TITLE>{response.Status}</TITLE></HEAD><BODY><H1>{response.Status}</H1><HR>There was a error processing this context.Request. The reason given by the server was:<P><font size=-1> {message} </Font><HR></BODY></HTML>");
        }

        public static void Process(HttpContext context, string dropLocation)
        {
            HttpRequest request = context.Request;

            string filename = request.Headers["Subject"];

            const string pwd = "MyCert";
            SecureString securePwd = new SecureString();
            Array.ForEach(pwd.ToArray(), securePwd.AppendChar);
            securePwd.MakeReadOnly();
            X509Certificate2 privateCert = new X509Certificate2("c:\\files\\certs\\MyPrivateCert.pfx", securePwd);
            X509Certificate2 senderCert = new X509Certificate2("c:\\files\\certs\\MyPublicCert.cer");


            byte[] data = request.BinaryRead(request.TotalBytes);
            bool isEncrypted = request.ContentType.Contains("application/pkcs7-mime");
            bool isSigned = request.ContentType.Contains("application/pkcs7-signature");

            string message;

            if (isSigned)
            {
                string messageWithMimeHeaders = Encoding.ASCII.GetString(data);
                string contentType = request.Headers["Content-Type"];

                message = as2.ExtractPayload(messageWithMimeHeaders, contentType);
            }
            else if (isEncrypted) // encrypted and signed inside
            {
                byte[] decryptedData = AS2Encryption.Decrypt(data);

                string messageWithContentTypeLineAndMimeHeaders = Encoding.ASCII.GetString(decryptedData);

                // when encrypted, the Content-Type line is actually stored in the start of the message
                int firstBlankLineInMessage = messageWithContentTypeLineAndMimeHeaders.IndexOf(Environment.NewLine + Environment.NewLine, StringComparison.Ordinal);
                string contentType = messageWithContentTypeLineAndMimeHeaders.Substring(0, firstBlankLineInMessage);

                message = As2MimeUtilities.ExtractPayload(messageWithContentTypeLineAndMimeHeaders, contentType);

            }
            else // not signed and not encrypted
            {
                message = Encoding.ASCII.GetString(data);
            }
            System.IO.File.WriteAllText(dropLocation + filename + "txt", message);
        }

        //public static void ReceiveAndSend(HttpRequest request, string dropLocation)
        //{
        //    string filename = request.Headers["Subject"];
        //    byte[] data = request.BinaryRead(request.TotalBytes);

        //    string pwd = "MyCert";
        //    SecureString securePwd = new SecureString();
        //    Array.ForEach(pwd.ToArray(), securePwd.AppendChar);
        //    securePwd.MakeReadOnly();
        //    X509Certificate2 recipientCert = new X509Certificate2("c:\\files\\certs\\MyPrivateCert.pfx", securePwd);

        //    try
        //    {
        //        byte[] decryptedData = AS2Encryption.Decrypt(data, recipientCert);

        //        SignedCms signedCms = new SignedCms();
        //        signedCms.Decode(decryptedData);
        //        X509Certificate2 senderCert = new X509Certificate2("c:\\files\\certs\\MyPublicCert.cer");
        //        signedCms.CheckSignature(new X509Certificate2Collection(senderCert), true);

        //        string messageWithContentTypeLineAndMimeHeaders = Encoding.ASCII.GetString(decryptedData);

        //        // when encrypted, the Content-Type line is actually stored in the start of the message
        //        int firstBlankLineInMessage = messageWithContentTypeLineAndMimeHeaders.IndexOf(Environment.NewLine + Environment.NewLine);
        //        string contentType = messageWithContentTypeLineAndMimeHeaders.Substring(0, firstBlankLineInMessage);

        //        string message = AS2MIMEUtilities.ExtractPayload(messageWithContentTypeLineAndMimeHeaders, contentType);
        //        System.IO.File.WriteAllText(dropLocation + filename, message);
        //        //string customDecodedMsg = Encoding.UTF8.GetString(signedCms.ContentInfo.Content);
        //        //System.IO.File.WriteAllText(dropLocation + filename, customDecodedMsg);
        //    }
        //    catch (CryptographicException ex)
        //    {
        //        Console.WriteLine(ex.Message);
        //    }
        //}
        //private static string CalculateMIC(string content, string micAlg)
        //{
        //    content = content.Contains("\r") ? content : content.Replace("\n", "\r\n");
        //    switch (micAlg)
        //    {
        //        case "sha1":
        //            var sha1 = SHA1.Create();
        //            return Convert.ToBase64String(sha1.ComputeHash(Encoding.UTF8.GetBytes(content)));
        //        case "sha256":
        //            var sha256 = SHA256.Create();
        //            return Convert.ToBase64String(sha256.ComputeHash(Encoding.UTF8.GetBytes(content)));
        //    }
        //    return "";
        //}
    }
}