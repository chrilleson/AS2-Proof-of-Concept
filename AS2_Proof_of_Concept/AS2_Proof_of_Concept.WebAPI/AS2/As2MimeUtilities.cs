using System;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace AS2_Proof_of_Concept.WebAPI.AS2
{
    /// <summary>
    /// Contains a number of useful static functions for creating MIME messages.
    /// </summary>
    public class As2MimeUtilities
    {
        public const string MessageSeparator = "\r\n\r\n";

        /// <summary>
        /// return a unique MIME style boundary
        /// this needs to be unique enought not to occur within the data
        /// and so is a Guid without - or { } characters.
        /// </summary>
        /// <returns></returns>
        public static string MimeBoundary()
        {
            return "_" + Guid.NewGuid().ToString("N");
        }

        /// <summary>
        /// Creates the a Mime header out of the components listed.
        /// </summary>
        /// <param name="sContentType">Content type</param>
        /// <param name="sEncoding">Encoding method</param>
        /// <param name="sDisposition">Disposition options</param>
        /// <returns>A string containing the three headers.</returns>
        public static string MimeHeader(string sContentType, string sEncoding, string sDisposition)
        {
            string sOut;

            sOut = "Content-Type: " + sContentType + "\r\n";
            if (sEncoding != "")
                sOut += "Content-Transfer-Encoding: " + sEncoding + "\r\n";

            if (sDisposition != "")
                sOut += "Content-Disposition: " + sDisposition + "\r\n";

            sOut = sOut + "\r\n";

            return sOut;
        }

        /// <summary>
        /// Return a single array of bytes out of all the supplied byte arrays.
        /// </summary>
        /// <param name="arBytes">Byte arrays to add</param>
        /// <returns>The single byte array.</returns>
        public static byte[] ConcatBytes(params byte[][] arBytes)
        {
            long lLength = 0;
            long lPosition = 0;

            //Get total size required.
            foreach (byte[] ar in arBytes)
                lLength += ar.Length;

            //Create new byte array
            byte[] toReturn = new byte[lLength];

            //Fill the new byte array
            foreach (byte[] ar in arBytes)
            {
                ar.CopyTo(toReturn, lPosition);
                lPosition += ar.Length;
            }

            return toReturn;
        }

        /// <summary>
        /// Create a Message out of byte arrays (this makes more sense than the above method)
        /// </summary>
        /// <param name="sContentType">Content type ie multipart/report</param>
        /// <param name="sEncoding">The encoding provided...</param>
        /// <param name="sDisposition">The disposition of the message...</param>
        /// <param name="abMessageParts">The byte arrays that make up the components</param>
        /// <returns>The message as a byte array.</returns>
        public static byte[] CreateMessage(string sContentType, string sEncoding, string sDisposition, params byte[][] abMessageParts)
        {
            return CreateMessage(sContentType, sEncoding, sDisposition, out _, abMessageParts);
        }

        /// <summary>
        /// Create a Message out of byte arrays (this makes more sense than the above method)
        /// </summary>
        /// <param name="sContentType">Content type ie multipart/report</param>
        /// <param name="sEncoding">The encoding provided...</param>
        /// <param name="sDisposition">The disposition of the message...</param>
        /// <param name="iHeaderLength">The length of the headers.</param>
        /// <param name="abMessageParts">The message parts.</param>
        /// <returns>The message as a byte array.</returns>
        public static byte[] CreateMessage(string sContentType, string sEncoding, string sDisposition, out int iHeaderLength, params byte[][] abMessageParts)
        {
            long lLength = 0;
            long lPosition = 0;

            //Only one part... Add headers only...
            if (abMessageParts.Length == 1)
            {
                byte[] bHeader = Encoding.ASCII.GetBytes(MimeHeader(sContentType, sEncoding, sDisposition));
                iHeaderLength = bHeader.Length;
                return ConcatBytes(bHeader, abMessageParts[0]);
            }
            else
            {
                // get boundary and "static" subparts.
                string sBoundary = MimeBoundary();
                byte[] bPackageHeader = Encoding.ASCII.GetBytes(MimeHeader(sContentType + "; boundary=\"----=_Part" + sBoundary + "\"", sEncoding, sDisposition));
                byte[] bBoundary = Encoding.ASCII.GetBytes(Environment.NewLine + "------=_Part" + sBoundary + Environment.NewLine);
                byte[] bFinalFooter = Encoding.ASCII.GetBytes(Environment.NewLine + "------=_Part" + sBoundary + "--" + Environment.NewLine);

                //Calculate the total size required.
                iHeaderLength = bPackageHeader.Length;

                foreach (byte[] ar in abMessageParts)
                    lLength += ar.Length;
                lLength += iHeaderLength + bBoundary.Length * abMessageParts.Length +
                    bFinalFooter.Length;

                //Create new byte array to that size.
                byte[] toReturn = new byte[lLength];

                //Copy the headers in.
                bPackageHeader.CopyTo(toReturn, lPosition);
                lPosition += bPackageHeader.Length;

                //Fill the new byte array in by coping the message parts.
                foreach (byte[] ar in abMessageParts)
                {
                    bBoundary.CopyTo(toReturn, lPosition);
                    lPosition += bBoundary.Length;

                    ar.CopyTo(toReturn, lPosition);
                    lPosition += ar.Length;
                }

                //Finally add the footer boundary.
                bFinalFooter.CopyTo(toReturn, lPosition);

                return toReturn;
            }
        }

        /// <summary>
        /// Signs a message and returns a MIME encoded array of bytes containing the signature.
        /// </summary>
        /// <param name="arMessage"></param>
        /// <param name="cert"></param>
        /// <param name="sContentType"></param>
        /// <returns></returns>
        public static byte[] Sign(byte[] arMessage, X509Certificate2 cert, out string sContentType)
        {
            byte[] bInPkcs7;

            // get a MIME boundary
            string sBoundary = MimeBoundary();

            // Get the Headers for the entire message.
            sContentType = "multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=sha-256; boundary=\"----=_Part" + sBoundary + "\"";

            // Define the boundary byte array.
            byte[] bBoundary = Encoding.ASCII.GetBytes("\r\n" + "------=_Part" + sBoundary + "\r\n");

            // Sign the header for the signature portion.
            byte[] bSignatureHeader = Encoding.ASCII.GetBytes(MimeHeader("application/pkcs7-signature; name=\"smime.p7s\"", "base64", "attachment filename=\"smime.p7s\""));

            // Get the signature.
            byte[] bSignature = As2Encryption.Sign(arMessage, cert);

            // convert to base64
            var wholeText = Convert.ToBase64String(bSignature);

            //76 character per line limit, see https://tools.ietf.org/html/rfc2045#section-6.8
            var sb = new StringBuilder(wholeText);
            for (int i = 76; i < sb.Length; i += 78)//76 + "\r\n"
            {
                sb.Insert(i, "\r\n");
            }
            string sig = sb + Environment.NewLine;
            bSignature = Encoding.ASCII.GetBytes(sig);

            // Calculate the final footer elements.
            byte[] bFinalFooter = Encoding.ASCII.GetBytes("------=_Part" + sBoundary + "--" + Environment.NewLine);

            // Concatenate all the above together to form the message.
            bInPkcs7 = ConcatBytes(bBoundary, arMessage, bBoundary,
                bSignatureHeader, bSignature, bFinalFooter);

            return bInPkcs7;
        }

        public static byte[] MdnSignature(byte[] arMessage, X509Certificate2 signingCert, out string sContentType)
        {
            byte[] bInPkcs7;

            // get a MIME boundary
            string sBoundary = MimeBoundary();

            // Get the Headers for the entire message.
            sContentType = $"multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=sha256; boundary=\"----=_Part{sBoundary}\"";

            // Define the boundary byte array.
            byte[] bBoundary = Encoding.ASCII.GetBytes($"------=_Part{sBoundary}{Environment.NewLine}");

            // Sign the header for the signature portion.
            byte[] bSignatureHeader = Encoding.ASCII.GetBytes(MimeHeader("application/pkcs7-signature; name=smime.p7s; smime-type=signed-data", "base64", "attachment; filename=\"smime.p7s\""));

            // Get the signature.
            byte[] bSignature = As2Encryption.Sign(arMessage, signingCert);

            // convert to base64
            var wholeText = Convert.ToBase64String(bSignature);

            //76 character per line limit, see https://tools.ietf.org/html/rfc2045#section-6.8
            var sb = new StringBuilder(wholeText);
            for (int i = 76; i < sb.Length; i += 78)//76 + "\r\n"
            {
                sb.Insert(i, Environment.NewLine);
            }
            string sig = sb + Environment.NewLine;
            bSignature = Encoding.ASCII.GetBytes(sig);
            
            // Calculate the final footer elements.
            byte[] bFinalFooter = Encoding.ASCII.GetBytes("------=_Part" + sBoundary + "--" + Environment.NewLine);

            // Concatenate all the above together to form the message.
            bInPkcs7 = ConcatBytes(bBoundary, arMessage, bBoundary,
                bSignatureHeader, bSignature, bFinalFooter);

            return bInPkcs7;
        }

        /// <summary>
        /// Extracts the signature, by looking for the signatures content-type
        /// </summary>
        public static string ExtractSignature(string message, string boundary)
        {
            if (!boundary.StartsWith("------=_Part"))
                boundary = "------=_Part" + boundary;

            int contentTypeHeader = message.IndexOf("Content-Type: application/pkcs7-signature;", StringComparison.Ordinal);
            int blankLineAfterContentTypeHeader =
                message.IndexOf(MessageSeparator, contentTypeHeader, StringComparison.Ordinal) +
                (MessageSeparator).Length;
            int nextBoundary = message.IndexOf("\r\n" + boundary, blankLineAfterContentTypeHeader,
                StringComparison.Ordinal);
            int signatureLength = nextBoundary - blankLineAfterContentTypeHeader;

            return message.Substring(blankLineAfterContentTypeHeader, signatureLength);
        }

        /// <summary>
        /// Extracts the boundary from a Content-Type string
        /// </summary>
        /// <param name="contentType">e.g: multipart/signed; protocol="application/pkcs7-signature"; micalg="sha1"; boundary="----=_Part_956100ef6a82431fb98f65ee70c00cb9_"</param>
        /// <returns>e.g: _956100ef6a82431fb98f65ee70c00cb9_</returns>
        public static string GetBoundaryFromContentType(string contentType)
        {
            return Trim(contentType, "boundary=\"----=_Part", "\"");
        }

        /// <summary>
        /// Trims the string from the end of startString until endString
        /// </summary>
        private static string Trim(string str, string start, string end)
        {
            int startIndex = str.IndexOf(start, StringComparison.Ordinal) + start.Length;
            int endIndex = str.IndexOf(end, startIndex, StringComparison.Ordinal);
            int length = endIndex - startIndex;

            return str.Substring(startIndex, length);
        }
    }
}