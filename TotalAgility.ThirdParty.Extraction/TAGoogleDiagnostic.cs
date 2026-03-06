using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;

namespace TotalAgility.ThirdParty.Extraction
{
    public class TAGoogleDiagnostic
    {
        private static readonly HttpClient _httpClient = new HttpClient();

        public string RunDiagnostic(string googleServiceAccountJson, string googleProjectId, string googleLocation, string processorId)
        {
            StringBuilder report = new StringBuilder();

            try
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            }
            catch (Exception ex)
            {
                report.AppendLine("TLS Config failed: " + ex.GetType().FullName + " - " + ex.Message);
            }

            report.AppendLine("=== Google Extraction Diagnostic ===");
            report.AppendLine("Timestamp (UTC): " + DateTime.UtcNow.ToString("o"));
            report.AppendLine("Environment: " + Environment.OSVersion.ToString());
            report.AppendLine("CLR Version: " + Environment.Version.ToString());
            report.AppendLine("Is 64-bit process: " + Environment.Is64BitProcess);
            report.AppendLine();

            // -------------------------------------------------------
            // STEP 1: Parse Service Account JSON
            // -------------------------------------------------------
            string clientEmail = null;
            string privateKeyPem = null;
            string tokenUri = null;

            report.AppendLine("--- STEP 1: Parse Service Account JSON ---");
            try
            {
                if (string.IsNullOrWhiteSpace(googleServiceAccountJson))
                {
                    report.AppendLine("STATUS: FAIL - Input is null/empty");
                    report.AppendLine("Input length: " + (googleServiceAccountJson == null ? "NULL" : googleServiceAccountJson.Length.ToString()));
                    report.AppendLine("=== Diagnostic Aborted ===");
                    return report.ToString();
                }

                JObject sa = JObject.Parse(googleServiceAccountJson);
                clientEmail = sa["client_email"]?.ToString();
                privateKeyPem = sa["private_key"]?.ToString();
                tokenUri = sa["token_uri"]?.ToString() ?? "https://oauth2.googleapis.com/token";

                report.AppendLine("STATUS: PASS");
                report.AppendLine("client_email: " + (clientEmail ?? "NULL"));
                report.AppendLine("private_key present: " + (privateKeyPem != null ? "YES (" + privateKeyPem.Length + " chars)" : "NO"));
                report.AppendLine("token_uri: " + tokenUri);
                report.AppendLine();
            }
            catch (Exception ex)
            {
                report.AppendLine("STATUS: FAIL");
                AppendException(report, ex);
                report.AppendLine("=== Diagnostic Aborted ===");
                return report.ToString();
            }

            // -------------------------------------------------------
            // STEP 2: Extract PKCS8 bytes from PEM
            // -------------------------------------------------------
            byte[] pkcs8Bytes = null;

            report.AppendLine("--- STEP 2: Extract PKCS8 from PEM ---");
            try
            {
                pkcs8Bytes = ExtractPkcs8FromPem(privateKeyPem);
                report.AppendLine("STATUS: PASS");
                report.AppendLine("PKCS8 byte length: " + pkcs8Bytes.Length);
                report.AppendLine();
            }
            catch (Exception ex)
            {
                report.AppendLine("STATUS: FAIL");
                AppendException(report, ex);
                report.AppendLine("=== Diagnostic Aborted ===");
                return report.ToString();
            }

            // -------------------------------------------------------
            // STEP 3: Decode ASN.1 to RSA parameters
            // -------------------------------------------------------
            // Store raw parameter bytes for later use
            byte[] modulus = null, exponent = null, d = null, p = null, q = null, dp = null, dq = null, iq = null;

            report.AppendLine("--- STEP 3: Decode PKCS8 -> RSA parameter bytes ---");
            try
            {
                // Use our own parser to get raw bytes
                DecodeRsaParameters(pkcs8Bytes, out modulus, out exponent, out d, out p, out q, out dp, out dq, out iq);
                report.AppendLine("STATUS: PASS");
                report.AppendLine("Modulus length: " + modulus.Length + " bytes");
                report.AppendLine("Exponent length: " + exponent.Length + " bytes");
                report.AppendLine();
            }
            catch (Exception ex)
            {
                report.AppendLine("STATUS: FAIL");
                AppendException(report, ex);
                report.AppendLine("=== Diagnostic Aborted ===");
                return report.ToString();
            }

            // -------------------------------------------------------
            // STEP 4A: RSA Sign - RSACryptoServiceProvider (no flags)
            // Each attempt is in its OWN METHOD to isolate JIT failures
            // -------------------------------------------------------
            bool method4a = false;

            report.AppendLine("--- STEP 4A: RSA Sign (RSACryptoServiceProvider - default) ---");
            try
            {
                string testResult = TrySignWithCspDefault(modulus, exponent, d, p, q, dp, dq, iq);
                report.AppendLine("STATUS: PASS");
                report.AppendLine("Detail: " + testResult);
                method4a = true;
            }
            catch (Exception ex)
            {
                report.AppendLine("STATUS: FAIL");
                AppendException(report, ex);
            }
            report.AppendLine();

            // -------------------------------------------------------
            // STEP 4B: RSA Sign - RSACryptoServiceProvider (ephemeral)
            // -------------------------------------------------------
            bool method4b = false;

            report.AppendLine("--- STEP 4B: RSA Sign (RSACryptoServiceProvider - EphemeralKey) ---");
            try
            {
                string testResult = TrySignWithCspEphemeral(modulus, exponent, d, p, q, dp, dq, iq);
                report.AppendLine("STATUS: PASS");
                report.AppendLine("Detail: " + testResult);
                method4b = true;
            }
            catch (Exception ex)
            {
                report.AppendLine("STATUS: FAIL");
                AppendException(report, ex);
            }
            report.AppendLine();

            // -------------------------------------------------------
            // STEP 4C: RSA Sign - RSACng
            // -------------------------------------------------------
            bool method4c = false;

            report.AppendLine("--- STEP 4C: RSA Sign (RSACng) ---");
            try
            {
                string testResult = TrySignWithCng(modulus, exponent, d, p, q, dp, dq, iq);
                report.AppendLine("STATUS: PASS");
                report.AppendLine("Detail: " + testResult);
                method4c = true;
            }
            catch (Exception ex)
            {
                report.AppendLine("STATUS: FAIL");
                AppendException(report, ex);
            }
            report.AppendLine();

            // -------------------------------------------------------
            // STEP 4D: RSA Sign - RSA.Create()
            // -------------------------------------------------------
            bool method4d = false;

            report.AppendLine("--- STEP 4D: RSA Sign (RSA.Create()) ---");
            try
            {
                string testResult = TrySignWithRsaCreate(modulus, exponent, d, p, q, dp, dq, iq);
                report.AppendLine("STATUS: PASS");
                report.AppendLine("Detail: " + testResult);
                method4d = true;
            }
            catch (Exception ex)
            {
                report.AppendLine("STATUS: FAIL");
                AppendException(report, ex);
            }
            report.AppendLine();

            // -------------------------------------------------------
            // SUMMARY
            // -------------------------------------------------------
            string bestMethod = "NONE";
            if (method4b) bestMethod = "CSP_EPHEMERAL";
            else if (method4c) bestMethod = "CNG";
            else if (method4d) bestMethod = "RSA_CREATE";
            else if (method4a) bestMethod = "CSP_DEFAULT";

            report.AppendLine("=== SIGNING SUMMARY ===");
            report.AppendLine("4A CSP Default:   " + (method4a ? "PASS" : "FAIL"));
            report.AppendLine("4B CSP Ephemeral: " + (method4b ? "PASS" : "FAIL"));
            report.AppendLine("4C RSACng:        " + (method4c ? "PASS" : "FAIL"));
            report.AppendLine("4D RSA.Create():  " + (method4d ? "PASS" : "FAIL"));
            report.AppendLine("Best method:      " + bestMethod);
            report.AppendLine();

            if (bestMethod == "NONE")
            {
                report.AppendLine("ALL RSA METHODS FAILED. Cannot proceed.");
                report.AppendLine("=== Diagnostic Complete (Aborted at Step 4) ===");
                return report.ToString();
            }

            // -------------------------------------------------------
            // STEP 5: Build and Sign JWT (using best available method)
            // -------------------------------------------------------
            string signedJwt = null;

            report.AppendLine("--- STEP 5: Build and Sign JWT (using " + bestMethod + ") ---");
            try
            {
                signedJwt = BuildAndSignJwt(clientEmail, tokenUri, modulus, exponent, d, p, q, dp, dq, iq, bestMethod);
                report.AppendLine("STATUS: PASS");
                report.AppendLine("JWT length: " + signedJwt.Length);
                report.AppendLine();
            }
            catch (Exception ex)
            {
                report.AppendLine("STATUS: FAIL");
                AppendException(report, ex);
                report.AppendLine("=== Diagnostic Aborted ===");
                return report.ToString();
            }

            // -------------------------------------------------------
            // STEP 6: Exchange JWT for Access Token
            // -------------------------------------------------------
            string accessToken = null;

            report.AppendLine("--- STEP 6: Exchange JWT for Access Token ---");
            try
            {
                using (var req = new HttpRequestMessage(HttpMethod.Post, tokenUri))
                {
                    string form = "grant_type=" + Uri.EscapeDataString("urn:ietf:params:oauth:grant-type:jwt-bearer")
                                + "&assertion=" + Uri.EscapeDataString(signedJwt);
                    req.Content = new StringContent(form, Encoding.UTF8, "application/x-www-form-urlencoded");

                    using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30)))
                    {
                        var resp = _httpClient.SendAsync(req, cts.Token).GetAwaiter().GetResult();
                        string body = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();

                        report.AppendLine("HTTP Status: " + (int)resp.StatusCode + " " + resp.StatusCode);

                        if (!resp.IsSuccessStatusCode)
                        {
                            report.AppendLine("STATUS: FAIL");
                            report.AppendLine("Body: " + body);
                            report.AppendLine("=== Diagnostic Aborted ===");
                            return report.ToString();
                        }

                        JObject json = JObject.Parse(body);
                        accessToken = json["access_token"]?.ToString();
                        report.AppendLine("STATUS: PASS");
                        report.AppendLine("Token length: " + (accessToken != null ? accessToken.Length.ToString() : "NULL"));
                        report.AppendLine();
                    }
                }
            }
            catch (Exception ex)
            {
                report.AppendLine("STATUS: FAIL");
                AppendException(report, ex);
                report.AppendLine("=== Diagnostic Aborted ===");
                return report.ToString();
            }

            // -------------------------------------------------------
            // STEP 7: Test Document AI endpoint
            // -------------------------------------------------------
            report.AppendLine("--- STEP 7: Test Document AI Endpoint ---");
            try
            {
                if (string.IsNullOrWhiteSpace(googleProjectId) || string.IsNullOrWhiteSpace(googleLocation) || string.IsNullOrWhiteSpace(processorId))
                {
                    report.AppendLine("STATUS: SKIPPED (missing projectId/location/processorId)");
                }
                else
                {
                    string host = googleLocation.Trim().ToLower() + "-documentai.googleapis.com";
                    string procName = "projects/" + googleProjectId.Trim() + "/locations/" + googleLocation.Trim() + "/processors/" + processorId.Trim();
                    string url = "https://" + host + "/v1/" + procName + ":process";

                    var payload = new { rawDocument = new { content = Convert.ToBase64String(Encoding.UTF8.GetBytes("%PDF-1.0 test")), mimeType = "application/pdf" } };

                    using (var req = new HttpRequestMessage(HttpMethod.Post, url))
                    {
                        req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
                        req.Content = new StringContent(JsonConvert.SerializeObject(payload), Encoding.UTF8, "application/json");

                        using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30)))
                        {
                            var resp = _httpClient.SendAsync(req, cts.Token).GetAwaiter().GetResult();
                            string body = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();

                            report.AppendLine("HTTP Status: " + (int)resp.StatusCode + " " + resp.StatusCode);
                            report.AppendLine("STATUS: " + (resp.IsSuccessStatusCode || (int)resp.StatusCode == 400 ? "PASS (endpoint responded)" : "FAIL"));
                            report.AppendLine("Body (first 500): " + (body.Length > 500 ? body.Substring(0, 500) : body));
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                report.AppendLine("STATUS: FAIL");
                AppendException(report, ex);
            }

            report.AppendLine();
            report.AppendLine("=== Diagnostic Complete ===");
            return report.ToString();
        }

        // =====================================================
        // ISOLATED METHODS - Each one JIT-compiles independently
        // If a type (like RSACng) doesn't exist in this env,
        // only THAT method fails, not the whole diagnostic.
        // =====================================================

        private string TrySignWithCspDefault(byte[] mod, byte[] exp, byte[] d, byte[] p, byte[] q, byte[] dp, byte[] dq, byte[] iq)
        {
            var rsaParams = BuildRsaParams(mod, exp, d, p, q, dp, dq, iq);
            using (var rsa = new System.Security.Cryptography.RSACryptoServiceProvider())
            {
                rsa.ImportParameters(rsaParams);
                byte[] sig = rsa.SignData(Encoding.UTF8.GetBytes("test"), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
                return "Signature length: " + sig.Length;
            }
        }

        private string TrySignWithCspEphemeral(byte[] mod, byte[] exp, byte[] d, byte[] p, byte[] q, byte[] dp, byte[] dq, byte[] iq)
        {
            var rsaParams = BuildRsaParams(mod, exp, d, p, q, dp, dq, iq);
            var cspParams = new System.Security.Cryptography.CspParameters
            {
                Flags = System.Security.Cryptography.CspProviderFlags.CreateEphemeralKey
            };
            using (var rsa = new System.Security.Cryptography.RSACryptoServiceProvider(cspParams))
            {
                rsa.ImportParameters(rsaParams);
                byte[] sig = rsa.SignData(Encoding.UTF8.GetBytes("test"), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
                return "Signature length: " + sig.Length;
            }
        }

        private string TrySignWithCng(byte[] mod, byte[] exp, byte[] d, byte[] p, byte[] q, byte[] dp, byte[] dq, byte[] iq)
        {
            var rsaParams = BuildRsaParams(mod, exp, d, p, q, dp, dq, iq);
            using (var rsa = new System.Security.Cryptography.RSACng())
            {
                rsa.ImportParameters(rsaParams);
                byte[] sig = rsa.SignData(Encoding.UTF8.GetBytes("test"), System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
                return "Signature length: " + sig.Length;
            }
        }

        private string TrySignWithRsaCreate(byte[] mod, byte[] exp, byte[] d, byte[] p, byte[] q, byte[] dp, byte[] dq, byte[] iq)
        {
            var rsaParams = BuildRsaParams(mod, exp, d, p, q, dp, dq, iq);
            using (var rsa = System.Security.Cryptography.RSA.Create())
            {
                rsa.ImportParameters(rsaParams);
                byte[] sig = rsa.SignData(Encoding.UTF8.GetBytes("test"), System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
                return "RSA impl type: " + rsa.GetType().FullName + ", Signature length: " + sig.Length;
            }
        }

        // =====================================================
        // Helper methods (no risky type references)
        // =====================================================

        private System.Security.Cryptography.RSAParameters BuildRsaParams(byte[] mod, byte[] exp, byte[] d, byte[] p, byte[] q, byte[] dp, byte[] dq, byte[] iq)
        {
            return new System.Security.Cryptography.RSAParameters
            {
                Modulus = mod, Exponent = exp, D = d, P = p, Q = q, DP = dp, DQ = dq, InverseQ = iq
            };
        }

        private string BuildAndSignJwt(string clientEmail, string tokenUri, byte[] mod, byte[] exp, byte[] d, byte[] p, byte[] q, byte[] dp, byte[] dq, byte[] iq, string method)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var header = new { alg = "RS256", typ = "JWT" };
            var payload = new
            {
                iss = clientEmail,
                scope = "https://www.googleapis.com/auth/cloud-platform",
                aud = tokenUri,
                iat = now,
                exp = now + 3600
            };

            string headerB64 = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(header)));
            string payloadB64 = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(payload)));
            string unsignedJwt = headerB64 + "." + payloadB64;

            byte[] signature;
            var rsaParams = BuildRsaParams(mod, exp, d, p, q, dp, dq, iq);

            switch (method)
            {
                case "CSP_EPHEMERAL":
                    signature = SignCspEphemeral(unsignedJwt, rsaParams);
                    break;
                case "CNG":
                    signature = SignCng(unsignedJwt, rsaParams);
                    break;
                case "RSA_CREATE":
                    signature = SignRsaCreate(unsignedJwt, rsaParams);
                    break;
                default:
                    signature = SignCspDefault(unsignedJwt, rsaParams);
                    break;
            }

            return unsignedJwt + "." + Base64UrlEncode(signature);
        }

        private byte[] SignCspDefault(string data, System.Security.Cryptography.RSAParameters rsaParams)
        {
            using (var rsa = new System.Security.Cryptography.RSACryptoServiceProvider())
            {
                rsa.ImportParameters(rsaParams);
                return rsa.SignData(Encoding.UTF8.GetBytes(data), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
            }
        }

        private byte[] SignCspEphemeral(string data, System.Security.Cryptography.RSAParameters rsaParams)
        {
            var csp = new System.Security.Cryptography.CspParameters { Flags = System.Security.Cryptography.CspProviderFlags.CreateEphemeralKey };
            using (var rsa = new System.Security.Cryptography.RSACryptoServiceProvider(csp))
            {
                rsa.ImportParameters(rsaParams);
                return rsa.SignData(Encoding.UTF8.GetBytes(data), System.Security.Cryptography.CryptoConfig.MapNameToOID("SHA256"));
            }
        }

        private byte[] SignCng(string data, System.Security.Cryptography.RSAParameters rsaParams)
        {
            using (var rsa = new System.Security.Cryptography.RSACng())
            {
                rsa.ImportParameters(rsaParams);
                return rsa.SignData(Encoding.UTF8.GetBytes(data), System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
            }
        }

        private byte[] SignRsaCreate(string data, System.Security.Cryptography.RSAParameters rsaParams)
        {
            using (var rsa = System.Security.Cryptography.RSA.Create())
            {
                rsa.ImportParameters(rsaParams);
                return rsa.SignData(Encoding.UTF8.GetBytes(data), System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
            }
        }

        private void DecodeRsaParameters(byte[] pkcs8, out byte[] modulus, out byte[] exponent, out byte[] d, out byte[] p, out byte[] q, out byte[] dp, out byte[] dq, out byte[] iq)
        {
            // Reuse the existing parser
            var rsaParams = RsaPkcs8PrivateKeyParser.DecodePkcs8PrivateKey(pkcs8);
            modulus = rsaParams.Modulus;
            exponent = rsaParams.Exponent;
            d = rsaParams.D;
            p = rsaParams.P;
            q = rsaParams.Q;
            dp = rsaParams.DP;
            dq = rsaParams.DQ;
            iq = rsaParams.InverseQ;
        }

        private byte[] ExtractPkcs8FromPem(string pem)
        {
            string header = "-----BEGIN PRIVATE KEY-----";
            string footer = "-----END PRIVATE KEY-----";
            int start = pem.IndexOf(header, StringComparison.Ordinal);
            int end = pem.IndexOf(footer, StringComparison.Ordinal);
            if (start < 0 || end < 0) throw new Exception("Expected PKCS8 PEM with 'BEGIN PRIVATE KEY'.");
            string base64 = pem.Substring(start + header.Length, end - (start + header.Length)).Replace("\r", "").Replace("\n", "").Trim();
            return Convert.FromBase64String(base64);
        }

        private string Base64UrlEncode(byte[] input)
        {
            return Convert.ToBase64String(input).Replace("+", "-").Replace("/", "_").Replace("=", "");
        }

        private void AppendException(StringBuilder report, Exception ex)
        {
            report.AppendLine("Exception Type: " + ex.GetType().FullName);
            report.AppendLine("Message: " + ex.Message);
            report.AppendLine("Stack Trace: " + (ex.StackTrace ?? "null"));

            Exception inner = ex.InnerException;
            int depth = 1;
            while (inner != null && depth <= 5)
            {
                report.AppendLine("-- Inner Exception (depth " + depth + ") --");
                report.AppendLine("Type: " + inner.GetType().FullName);
                report.AppendLine("Message: " + inner.Message);
                inner = inner.InnerException;
                depth++;
            }
        }
    }
}
