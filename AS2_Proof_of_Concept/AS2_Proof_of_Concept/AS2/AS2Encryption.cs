using System;
using System.Security;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace AS2_Proof_of_Concept.WebApp.AS2
{
   public static class EncryptionAlgorithm
    {
        public static string DES3 = "3DES";
        public static string RC2 = "RC2";
    }
 
    public class AS2Encryption
    {
        internal static byte[] Encode(byte[] arMessage, string signerCert, SecureString signerPassword)
        {
            X509Certificate2 cert = new X509Certificate2(signerCert, signerPassword);
            ContentInfo contentInfo = new ContentInfo(arMessage);
 
            SignedCms signedCms = new SignedCms(contentInfo, true); // <- true detaches the signature
            CmsSigner cmsSigner = new CmsSigner(cert);
 
            signedCms.ComputeSignature(cmsSigner);
            byte[] signature = signedCms.Encode();
 
            return signature;
        }
 
        internal static byte[] Encrypt(byte[] message, string recipientCert, string encryptionAlgorithm)
        {
            if (!string.Equals(encryptionAlgorithm, EncryptionAlgorithm.DES3) && !string.Equals(encryptionAlgorithm, EncryptionAlgorithm.RC2))
                throw new ArgumentException("encryptionAlgorithm argument must be 3DES or RC2 - value specified was:" + encryptionAlgorithm);
 
            X509Certificate2 cert = new X509Certificate2(recipientCert);
 
            ContentInfo contentInfo = new ContentInfo(message);
 
            EnvelopedCms envelopedCms = new EnvelopedCms(contentInfo,
                new AlgorithmIdentifier(new System.Security.Cryptography.Oid(encryptionAlgorithm))); // should be 3DES or RC2
 
            CmsRecipient recipient = new CmsRecipient(SubjectIdentifierType.IssuerAndSerialNumber, cert);
 
            envelopedCms.Encrypt(recipient);
 
            byte[] encoded = envelopedCms.Encode();
 
            return encoded;
        }
 

        internal static byte[] Decrypt(byte[] encodedEncryptedMessage)
        {
            EnvelopedCms envelopedCms = new EnvelopedCms();
            envelopedCms.Decode(encodedEncryptedMessage);
            envelopedCms.Decrypt();
            return envelopedCms.Encode();
        }
    }
}