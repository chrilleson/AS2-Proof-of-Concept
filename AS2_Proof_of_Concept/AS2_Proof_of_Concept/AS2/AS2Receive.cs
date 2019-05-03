using System;
using System.Net;
using System.Web;

namespace AS2_Proof_of_Concept.WebApp.AS2
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

        public static void Process(HttpRequest request, string dropLocation)
        {
            string filename = (string)request.Headers["Subject"];

            byte[] data = request.BinaryRead(request.TotalBytes);
            bool isEncrypted = request.ContentType.Contains("application/pkcs7-mime");
            bool isSigned = request.ContentType.Contains("application/pkcs7-signature");

            string message;

            if (isSigned)
            {
                string messageWithMimeHeaders = System.Text.Encoding.ASCII.GetString(data);
                string contentType = request.Headers["Content-Type"];

                message = AS2MIMEUtilities.ExtractPayload(messageWithMimeHeaders, contentType);
            }
            else if (isEncrypted) // encrypted and signed inside
            {
                byte[] decryptedData = AS2Encryption.Decrypt(data);

                string messageWithContentTypeLineAndMimeHeaders = System.Text.Encoding.ASCII.GetString(decryptedData);

                // when encrypted, the Content-Type line is actually stored in the start of the message
                int firstBlankLineInMessage = messageWithContentTypeLineAndMimeHeaders.IndexOf(Environment.NewLine + Environment.NewLine);
                string contentType = messageWithContentTypeLineAndMimeHeaders.Substring(0, firstBlankLineInMessage);

                message = AS2MIMEUtilities.ExtractPayload(messageWithContentTypeLineAndMimeHeaders, contentType);
            }
            else // not signed and not encrypted
            {
                message = System.Text.Encoding.ASCII.GetString(data);
            }

            System.IO.File.WriteAllText(dropLocation + filename, message);
        }
    }
}