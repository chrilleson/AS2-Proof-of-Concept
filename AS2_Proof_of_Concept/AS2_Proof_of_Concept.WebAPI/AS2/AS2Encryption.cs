using System;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace AS2_Proof_of_Concept.WebAPI.AS2
{
    public static class EncryptionAlgorithm
    {
        public static string Des3 = "3DES";
        public static string Rc2 = "RC2";
    }

    public class As2Encryption
    {
        internal static byte[] Encode(byte[] arMessage, X509Certificate2 signingCert)
        {
            ContentInfo contentInfo = new ContentInfo(arMessage);
            SignedCms signedCms = new SignedCms(contentInfo, true); // <- true detaches the signature
            CmsSigner cmsSigner = new CmsSigner(signingCert)
            {
                IncludeOption = X509IncludeOption.WholeChain
            };

            signedCms.ComputeSignature(cmsSigner);
            byte[] signature = signedCms.Encode();

            return signature;
        }

        internal static byte[] Encrypt(byte[] message, X509Certificate2 recipientCert, string encryptionAlgorithm)
        {
            if (!string.Equals(encryptionAlgorithm, EncryptionAlgorithm.Des3) && !string.Equals(encryptionAlgorithm, EncryptionAlgorithm.Rc2))
                throw new ArgumentException("encryptionAlgorithm argument must be 3DES or RC2 - value specified was:" + encryptionAlgorithm);

            ContentInfo contentInfo = new ContentInfo(message);

            EnvelopedCms envelopedCms = new EnvelopedCms(contentInfo,
                new AlgorithmIdentifier(new System.Security.Cryptography.Oid(encryptionAlgorithm))); // should be 3DES or RC2

            CmsRecipient recipient = new CmsRecipient(SubjectIdentifierType.IssuerAndSerialNumber, recipientCert);

            envelopedCms.Encrypt(recipient);

            byte[] encoded = envelopedCms.Encode();

            return encoded;
        }


        public static byte[] Decrypt(byte[] encodedEncryptedMessage)
        {
            EnvelopedCms envelopedCms = new EnvelopedCms();
            envelopedCms.Decode(encodedEncryptedMessage);
            envelopedCms.Decrypt();
            return envelopedCms.ContentInfo.Content;
        }
    }
}