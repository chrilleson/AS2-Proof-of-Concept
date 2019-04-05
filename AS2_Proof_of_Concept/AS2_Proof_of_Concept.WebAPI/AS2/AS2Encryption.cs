using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace AS2_Proof_of_Concept.WebAPI.AS2
{
    public static class EncryptionAlgorithm
    {
        public static string Des3 = "3DES";
        public static string Rc2 = "RC2";
    }

    public class As2Encryption
    {
        internal static byte[] Sign(byte[] arMessage, X509Certificate2 signingCert)
        {
            ContentInfo contentInfo = new ContentInfo(arMessage);
            SignedCms signedCms = new SignedCms(contentInfo, false); // <- true detaches the signature
            CmsSigner cmsSigner = new CmsSigner(signingCert);

            signedCms.ComputeSignature(cmsSigner, true);
            byte[] signature = signedCms.Encode();

            return signature;
        }

        internal static byte[] Encrypt(byte[] message, X509Certificate2 recipientCert, string encryptionAlgorithm)
        {
            if (!string.Equals(encryptionAlgorithm, EncryptionAlgorithm.Des3) && !string.Equals(encryptionAlgorithm, EncryptionAlgorithm.Rc2))
                throw new ArgumentException("encryptionAlgorithm argument must be 3DES or RC2 - value specified was:" + encryptionAlgorithm);

            ContentInfo contentInfo = new ContentInfo(message);

            EnvelopedCms envelopedCms = new EnvelopedCms(contentInfo,
                new AlgorithmIdentifier(new Oid(encryptionAlgorithm))); // should be 3DES or RC2

            CmsRecipient recipient = new CmsRecipient(SubjectIdentifierType.IssuerAndSerialNumber, recipientCert);

            envelopedCms.Encrypt(recipient);

            byte[] encoded = envelopedCms.Encode();

            return encoded;
        }

        public static byte[] Decrypt(byte[] encodedEncryptedMessage, X509Certificate2 recipientCert)
        {
            EnvelopedCms envelopedCms = new EnvelopedCms();
            envelopedCms.Decode(encodedEncryptedMessage);
            envelopedCms.Decrypt(envelopedCms.RecipientInfos[0]);
            return envelopedCms.ContentInfo.Content;
        }

        public static string CalculateMic(string content, string micAlg)
        {
            content = content.Contains("\r") ? content : content.Replace("\n", "\r\n");
            switch (micAlg)
            {
                case"md5":
                case"md-5":
                    var md5 = MD5.Create();
                    return Convert.ToBase64String(md5.ComputeHash(Encoding.ASCII.GetBytes(content)));
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