using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.IO;
using System.Net.Http;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace TotalAgility.ThirdParty.Extraction
{
    public class TAGoogleExtractor
    {
        private static readonly HttpClient _httpClient = new HttpClient();

        public string Analyze(byte[] documentBytes, string contentType, string googleProjectId, string googleLocation, string processorId, string googleServiceAccountJson, int timeoutSeconds, string documentType)
        {
            if (documentBytes == null || documentBytes.Length == 0) throw new Exception("documentBytes is required.");
            if (string.IsNullOrWhiteSpace(contentType)) contentType = "application/octet-stream";
            if (string.IsNullOrWhiteSpace(googleProjectId)) throw new Exception("googleProjectId is required.");
            if (string.IsNullOrWhiteSpace(googleLocation)) throw new Exception("googleLocation is required (e.g., 'us').");
            if (string.IsNullOrWhiteSpace(processorId)) throw new Exception("processorId is required.");
            if (string.IsNullOrWhiteSpace(googleServiceAccountJson)) throw new Exception("googleServiceAccountJson is required.");
            if (timeoutSeconds <= 0) timeoutSeconds = 60;

            JObject sa;
            try { sa = JObject.Parse(googleServiceAccountJson); }
            catch (Exception ex) { throw new Exception("googleServiceAccountJson is not valid JSON. " + ex.Message, ex); }

            string clientEmail = sa["client_email"] != null ? sa["client_email"].ToString() : null;
            string privateKeyPem = sa["private_key"] != null ? sa["private_key"].ToString() : null;
            string tokenUri = sa["token_uri"] != null ? sa["token_uri"].ToString() : "https://oauth2.googleapis.com/token";

            if (string.IsNullOrWhiteSpace(clientEmail)) throw new Exception("Service account JSON missing 'client_email'.");
            if (string.IsNullOrWhiteSpace(privateKeyPem)) throw new Exception("Service account JSON missing 'private_key'.");

            string accessToken = GetAccessTokenFromServiceAccount(clientEmail, privateKeyPem, tokenUri, timeoutSeconds);

            string endpointHost = googleLocation.Trim().ToLower() + "-documentai.googleapis.com";
            string processorName = "projects/" + googleProjectId.Trim() + "/locations/" + googleLocation.Trim() + "/processors/" + processorId.Trim();
            string url = "https://" + endpointHost + "/v1/" + processorName + ":process";

            var requestPayload = new
            {
                rawDocument = new
                {
                    content = Convert.ToBase64String(documentBytes),
                    mimeType = contentType
                }
            };

            using (var req = new HttpRequestMessage(HttpMethod.Post, url))
            {
                req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
                req.Content = new StringContent(JsonConvert.SerializeObject(requestPayload), Encoding.UTF8, "application/json");

                using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds)))
                {
                    HttpResponseMessage resp = _httpClient.SendAsync(req, cts.Token).GetAwaiter().GetResult();
                    string body = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();

                    if (!resp.IsSuccessStatusCode)
                        throw new Exception("Google Document AI process failed. Status: " + resp.StatusCode + " Body: " + body);

                    // Check if response contains Driver License entities
                    // If yes, normalize to Azure-compatible format
                    // If no (Receipt, Invoice, etc.), return raw output with images stripped
                    JObject responseRoot = JObject.Parse(body);
                    JObject document = responseRoot["document"] as JObject;

                    if (documentType== "Driver License")
                    {
                        // Normalize DL output to Azure-compatible format
                        TAGoogleToAzureNormalizer normalizer = new TAGoogleToAzureNormalizer();
                        return normalizer.NormalizeResponse(body);
                    }
                    else
                    {
                        // For all other document types, strip embedded images
                        // and return the raw Google output
                        if (document != null)
                        {
                            StripEmbeddedImages(document);
                            body = responseRoot.ToString(Newtonsoft.Json.Formatting.None);
                        }
                        return body;
                    }
                }
            }
        }

        /// <summary>
        /// Checks if the Google response contains Driver License specific entities
        /// by looking for known DL entity types like "Family Name", "Given Names", etc.
        /// </summary>
        private bool IsDrivingLicenseResponse(JObject document)
        {
            JArray entities = document["entities"] as JArray;
            if (entities == null || entities.Count == 0) return false;

            foreach (JToken entity in entities)
            {
                string entityType = entity["type"]?.ToString();
                if (string.IsNullOrEmpty(entityType)) continue;

                // If any of these DL-specific entity types are found, it's a DL response
                if (string.Equals(entityType, "Family Name", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(entityType, "Given Names", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(entityType, "Document Id", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(entityType, "Date Of Birth", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(entityType, "Expiration Date", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Removes pages[].image.content to prevent response truncation.
        /// </summary>
        private void StripEmbeddedImages(JObject document)
        {
            JArray pages = document["pages"] as JArray;
            if (pages == null) return;

            foreach (JToken page in pages)
            {
                JObject pageObj = page as JObject;
                if (pageObj == null) continue;

                JObject image = pageObj["image"] as JObject;
                if (image != null && image["content"] != null)
                {
                    image.Remove("content");
                }
            }
        }

        private string GetAccessTokenFromServiceAccount(string clientEmail, string privateKeyPem, string tokenUri, int timeoutSeconds)
        {
            string scope = "https://www.googleapis.com/auth/cloud-platform";

            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            long exp = now + 3600;

            var header = new { alg = "RS256", typ = "JWT" };
            var payload = new
            {
                iss = clientEmail,
                scope = scope,
                aud = tokenUri,
                iat = now,
                exp = exp
            };

            string headerB64 = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(header)));
            string payloadB64 = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(payload)));
            string unsignedJwt = headerB64 + "." + payloadB64;

            byte[] signature = SignWithRsaSha256(unsignedJwt, privateKeyPem);
            string signedJwt = unsignedJwt + "." + Base64UrlEncode(signature);

            using (var req = new HttpRequestMessage(HttpMethod.Post, tokenUri))
            {
                string form = "grant_type=" + Uri.EscapeDataString("urn:ietf:params:oauth:grant-type:jwt-bearer")
                            + "&assertion=" + Uri.EscapeDataString(signedJwt);

                req.Content = new StringContent(form, Encoding.UTF8, "application/x-www-form-urlencoded");

                using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds)))
                {
                    HttpResponseMessage resp = _httpClient.SendAsync(req, cts.Token).GetAwaiter().GetResult();
                    string body = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();

                    if (!resp.IsSuccessStatusCode)
                        throw new Exception("Google OAuth token exchange failed. Status: " + resp.StatusCode + " Body: " + body);

                    JObject json = JObject.Parse(body);
                    string accessToken = json["access_token"] != null ? json["access_token"].ToString() : null;

                    if (string.IsNullOrWhiteSpace(accessToken))
                        throw new Exception("Google OAuth token response missing access_token. Body: " + body);

                    return accessToken;
                }
            }
        }

        private byte[] SignWithRsaSha256(string data, string privateKeyPem)
        {
            byte[] pkcs8 = ExtractPkcs8FromPem(privateKeyPem);
            RSAParameters rsaParams = RsaPkcs8PrivateKeyParser.DecodePkcs8PrivateKey(pkcs8);

            byte[] hash;
            using (var sha256 = new SHA256Managed())
            {
                hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(data));
            }

            byte[] digestInfoPrefix = new byte[]
            {
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09,
                0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                0x04, 0x02, 0x01,
                0x05, 0x00,
                0x04, 0x20
            };

            byte[] digestInfo = new byte[digestInfoPrefix.Length + hash.Length];
            Buffer.BlockCopy(digestInfoPrefix, 0, digestInfo, 0, digestInfoPrefix.Length);
            Buffer.BlockCopy(hash, 0, digestInfo, digestInfoPrefix.Length, hash.Length);

            int keySize = rsaParams.Modulus.Length;
            if (digestInfo.Length + 11 > keySize)
                throw new Exception("Key too small for SHA-256 PKCS#1 v1.5 signature.");

            byte[] em = new byte[keySize];
            em[0] = 0x00;
            em[1] = 0x01;

            int psLength = keySize - digestInfo.Length - 3;
            for (int i = 0; i < psLength; i++)
            {
                em[2 + i] = 0xFF;
            }

            em[2 + psLength] = 0x00;
            Buffer.BlockCopy(digestInfo, 0, em, 3 + psLength, digestInfo.Length);

            BigInteger emInt = ToBigIntegerUnsigned(em);
            BigInteger dInt = ToBigIntegerUnsigned(rsaParams.D);
            BigInteger nInt = ToBigIntegerUnsigned(rsaParams.Modulus);

            BigInteger sigInt = BigInteger.ModPow(emInt, dInt, nInt);

            return ToFixedLengthBigEndian(sigInt, keySize);
        }

        private BigInteger ToBigIntegerUnsigned(byte[] bigEndianBytes)
        {
            byte[] littleEndian = new byte[bigEndianBytes.Length + 1];
            for (int i = 0; i < bigEndianBytes.Length; i++)
            {
                littleEndian[bigEndianBytes.Length - 1 - i] = bigEndianBytes[i];
            }
            return new BigInteger(littleEndian);
        }

        private byte[] ToFixedLengthBigEndian(BigInteger value, int length)
        {
            byte[] littleEndian = value.ToByteArray();
            byte[] bigEndian = new byte[littleEndian.Length];
            for (int i = 0; i < littleEndian.Length; i++)
            {
                bigEndian[littleEndian.Length - 1 - i] = littleEndian[i];
            }

            int startIndex = 0;
            while (startIndex < bigEndian.Length && bigEndian[startIndex] == 0x00)
            {
                startIndex++;
            }

            byte[] trimmed = new byte[bigEndian.Length - startIndex];
            Buffer.BlockCopy(bigEndian, startIndex, trimmed, 0, trimmed.Length);

            if (trimmed.Length == length)
            {
                return trimmed;
            }
            else if (trimmed.Length < length)
            {
                byte[] padded = new byte[length];
                Buffer.BlockCopy(trimmed, 0, padded, length - trimmed.Length, trimmed.Length);
                return padded;
            }
            else
            {
                byte[] result = new byte[length];
                Buffer.BlockCopy(trimmed, trimmed.Length - length, result, 0, length);
                return result;
            }
        }

        private byte[] ExtractPkcs8FromPem(string pem)
        {
            string header = "-----BEGIN PRIVATE KEY-----";
            string footer = "-----END PRIVATE KEY-----";

            int start = pem.IndexOf(header, StringComparison.Ordinal);
            int end = pem.IndexOf(footer, StringComparison.Ordinal);

            if (start < 0 || end < 0)
                throw new Exception("Unsupported private key format. Expected PKCS8 PEM with 'BEGIN PRIVATE KEY'.");

            string base64 = pem.Substring(start + header.Length, end - (start + header.Length));
            base64 = base64.Replace("\r", "").Replace("\n", "").Trim();

            return Convert.FromBase64String(base64);
        }

        private string Base64UrlEncode(byte[] input)
        {
            string b64 = Convert.ToBase64String(input);
            return b64.Replace("+", "-").Replace("/", "_").Replace("=", "");
        }
    }

    internal static class RsaPkcs8PrivateKeyParser
    {
        public static RSAParameters DecodePkcs8PrivateKey(byte[] pkcs8)
        {
            using (var ms = new MemoryStream(pkcs8))
            using (var br = new BinaryReader(ms))
            {
                return DecodePkcs8PrivateKeySafe(br);
            }
        }

        private static RSAParameters DecodePkcs8PrivateKeySafe(BinaryReader br)
        {
            ReadAsn1Sequence(br);
            ReadAsn1Integer(br);
            ReadAsn1Sequence(br);
            SkipAsn1Element(br);
            if (PeekTag(br) == 0x05) SkipAsn1Element(br);
            byte[] pkcs1 = ReadAsn1OctetString(br);
            return DecodePkcs1PrivateKey(pkcs1);
        }

        private static RSAParameters DecodePkcs1PrivateKey(byte[] pkcs1)
        {
            using (var ms = new MemoryStream(pkcs1))
            using (var br = new BinaryReader(ms))
            {
                ReadAsn1Sequence(br);
                ReadAsn1Integer(br);
                RSAParameters p = new RSAParameters();
                p.Modulus = ReadAsn1IntegerBytes(br);
                p.Exponent = ReadAsn1IntegerBytes(br);
                p.D = ReadAsn1IntegerBytes(br);
                p.P = ReadAsn1IntegerBytes(br);
                p.Q = ReadAsn1IntegerBytes(br);
                p.DP = ReadAsn1IntegerBytes(br);
                p.DQ = ReadAsn1IntegerBytes(br);
                p.InverseQ = ReadAsn1IntegerBytes(br);
                return p;
            }
        }

        private static byte PeekTag(BinaryReader br)
        {
            long pos = br.BaseStream.Position;
            byte tag = br.ReadByte();
            br.BaseStream.Position = pos;
            return tag;
        }

        private static void ReadAsn1Sequence(BinaryReader br)
        {
            byte tag = br.ReadByte();
            if (tag != 0x30) throw new Exception("ASN.1: expected SEQUENCE (0x30).");
            ReadAsn1Length(br);
        }

        private static void ReadAsn1Integer(BinaryReader br)
        {
            byte tag = br.ReadByte();
            if (tag != 0x02) throw new Exception("ASN.1: expected INTEGER (0x02).");
            int len = ReadAsn1Length(br);
            br.ReadBytes(len);
        }

        private static byte[] ReadAsn1IntegerBytes(BinaryReader br)
        {
            byte tag = br.ReadByte();
            if (tag != 0x02) throw new Exception("ASN.1: expected INTEGER (0x02).");
            int len = ReadAsn1Length(br);
            byte[] bytes = br.ReadBytes(len);
            if (bytes.Length > 1 && bytes[0] == 0x00)
            {
                byte[] trimmed = new byte[bytes.Length - 1];
                Buffer.BlockCopy(bytes, 1, trimmed, 0, trimmed.Length);
                return trimmed;
            }
            return bytes;
        }

        private static byte[] ReadAsn1OctetString(BinaryReader br)
        {
            byte tag = br.ReadByte();
            if (tag != 0x04) throw new Exception("ASN.1: expected OCTET STRING (0x04).");
            int len = ReadAsn1Length(br);
            return br.ReadBytes(len);
        }

        private static void SkipAsn1Element(BinaryReader br)
        {
            br.ReadByte();
            int len = ReadAsn1Length(br);
            br.ReadBytes(len);
        }

        private static int ReadAsn1Length(BinaryReader br)
        {
            int length = br.ReadByte();
            if (length < 0x80) return length;
            int bytesCount = length & 0x7F;
            if (bytesCount == 0 || bytesCount > 4) throw new Exception("ASN.1: invalid length.");
            byte[] bytes = br.ReadBytes(bytesCount);
            int result = 0;
            for (int i = 0; i < bytes.Length; i++) result = (result << 8) + bytes[i];
            return result;
        }
    }
}
