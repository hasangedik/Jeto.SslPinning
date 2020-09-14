using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Jeto.SslPinning.WebSite.Core
{
    public static class SslPinUtility
    {
        public static async Task<string> GetPublicKeyPinningHash(X509Certificate2 x509Cert)
        {
            //Public Domain: No attribution required
            //Get the SubjectPublicKeyInfo member of the certificate
            byte[] subjectPublicKeyInfo = await Task.Run(() => GetSubjectPublicKeyInfoRaw(x509Cert));

            //Take the SHA2-256 hash of the DER ASN.1 encoded value
            byte[] digest;
            using (var sha2 = new SHA256Managed())
            {
                digest = sha2.ComputeHash(subjectPublicKeyInfo);
            }

            //Convert hash to base64
            return Convert.ToBase64String(digest);
        }

        private static byte[] GetSubjectPublicKeyInfoRaw(X509Certificate2 x509Cert)
        {
            //Public Domain: No attribution required
            byte[] rawCert = x509Cert.GetRawCertData();

            /*
             Certificate is, by definition:

                Certificate  ::=  SEQUENCE  {
                    tbsCertificate       TBSCertificate,
                    signatureAlgorithm   AlgorithmIdentifier,
                    signatureValue       BIT STRING  
                }

               TBSCertificate  ::=  SEQUENCE  {
                    version         [0]  EXPLICIT Version DEFAULT v1,
                    serialNumber         CertificateSerialNumber,
                    signature            AlgorithmIdentifier,
                    issuer               Name,
                    validity             Validity,
                    subject              Name,
                    subjectPublicKeyInfo SubjectPublicKeyInfo,
                    issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL, -- If present, version MUST be v2 or v3
                    subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL, -- If present, version MUST be v2 or v3
                    extensions      [3]  EXPLICIT Extensions       OPTIONAL  -- If present, version MUST be v3
                }

            So we walk to ASN.1 DER tree in order to drill down to the SubjectPublicKeyInfo item
            */
            byte[] list = AsnNext(ref rawCert, true); //unwrap certificate sequence
            byte[] tbsCertificate = AsnNext(ref list, false); //get next item; which is tbsCertificate
            list = AsnNext(ref tbsCertificate, true); //unwap tbsCertificate sequence
            byte[] version = AsnNext(ref list, false); //tbsCertificate.Version
            byte[] serialNumber = AsnNext(ref list, false); //tbsCertificate.SerialNumber
            byte[] signature = AsnNext(ref list, false); //tbsCertificate.Signature
            byte[] issuer = AsnNext(ref list, false); //tbsCertificate.Issuer
            byte[] validity = AsnNext(ref list, false); //tbsCertificate.Validity
            byte[] subject = AsnNext(ref list, false); //tbsCertificate.Subject        
            byte[] subjectPublicKeyInfo = AsnNext(ref list, false); //tbsCertificate.SubjectPublicKeyInfo        

            return subjectPublicKeyInfo;
        }

        private static byte[] AsnNext(ref byte[] buffer, bool unwrap)
        {
            byte[] result;

            if (buffer.Length < 2)
            {
                result = buffer;
                buffer = new byte[0];
                return result;
            }

            int index = 1;
            int length = buffer[index];
            index += 1;

            int lengthBytes = 1;
            if (length >= 0x80)
            {
                lengthBytes = length & 0x0F;
                length = 0;

                for (int i = 0; i < lengthBytes; i++)
                {
                    length = (length << 8) + buffer[2 + i];
                    index += 1;
                }

                lengthBytes++;
            }

            int copyStart;
            int copyLength;
            if (unwrap)
            {
                copyStart = 1 + lengthBytes;
                copyLength = length;
            }
            else
            {
                copyStart = 0;
                copyLength = 1 + lengthBytes + length;
            }

            result = new byte[copyLength];
            Array.Copy(buffer, copyStart, result, 0, copyLength);

            byte[] remaining = new byte[buffer.Length - (copyStart + copyLength)];
            if (remaining.Length > 0)
                Array.Copy(buffer, copyStart + copyLength, remaining, 0, remaining.Length);
            buffer = remaining;

            return result;
        }
    }
}