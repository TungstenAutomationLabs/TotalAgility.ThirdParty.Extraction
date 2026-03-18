using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;

namespace TotalAgility.ThirdParty.Extraction
{
    public class TAThirdPartyConnector
    {
        private const string TPE_PROVIDER = "TPE-PROVIDER";
        private const string TPE_MODEL_MAP = "TPE-MODEL-MAP";
        private const string TPE_TIMEOUT_SECONDS = "TPE-TimeoutSeconds";

        private const string TPE_AZURE_DIENDPOINT = "TPE-Azure-DIEndpoint";
        private const string TPE_AZURE_APIVERSION = "TPE-Azure-APIVersion";
        private const string TPE_AZURE_POLL_INTERVAL_MS = "TPE-Azure-PollIntervalMs";

        private const string TPE_GOOGLE_PROJECT_ID = "TPE-GOOGLE-PROJECT-ID";
        private const string TPE_GOOGLE_LOCATION = "TPE-GOOGLE-LOCATION";

        // ── PulseAI server variables ──────────────────────────────────────────
        // pulseBaseUrl, schemaJson, timeoutSeconds, useAsync are all read from
        // server variables — NOT passed from TA side.
        // pulseApiKey is secure → passed as input parameter from TA.
        private const string TPE_PULSE_URL = "TPE-PULSE-URL";
        private const string TPE_PULSE_SCHEMA_MAP = "TPE-PULSE-SCHEMA-MAP";
        private const string TPE_PULSE_USE_ASYNC = "TPE-PULSE-USE-ASYNC";

        // pulseApiKey added as 7th parameter — secure credential passed from TA
        public string Extract(string documentId, string documentType, string taSessionId, string taSdkUrl, string azureApiKey, string googleServiceAccountJson, string pulseApiKey)
        {
            if (string.IsNullOrWhiteSpace(documentId)) throw new Exception("documentId is required.");
            if (string.IsNullOrWhiteSpace(documentType)) throw new Exception("documentType is required.");
            if (string.IsNullOrWhiteSpace(taSessionId)) throw new Exception("taSessionId is required.");
            if (string.IsNullOrWhiteSpace(taSdkUrl)) throw new Exception("taSdkUrl is required.");

            // 1) Read core server variables
            var coreVars = ReadServerVariables(taSessionId, taSdkUrl, new List<string>() { TPE_PROVIDER, TPE_MODEL_MAP, TPE_TIMEOUT_SECONDS });

            // ── Provider resolved via ResolveActiveProvider ───────────────────
            // Supports both:
            //   legacy plain string:  "Azure"
            //   new JSON array:       [{"name":"Azure","active":false},{"name":"PulseAI","active":true}]
            string provider = ResolveActiveProvider(coreVars[TPE_PROVIDER]);
            string modelMapJson = coreVars[TPE_MODEL_MAP];
            int timeoutSeconds = ParseIntOrDefault(coreVars[TPE_TIMEOUT_SECONDS], 60);
            if (timeoutSeconds <= 0) timeoutSeconds = 60;

            if (string.IsNullOrWhiteSpace(provider)) throw new Exception("Server variable '" + TPE_PROVIDER + "' is empty or has no active provider.");
            if (string.IsNullOrWhiteSpace(modelMapJson)) throw new Exception("Server variable '" + TPE_MODEL_MAP + "' is empty.");

            // 2) Get document bytes and content type (Azure + Google only)
            //    PulseAI retrieves its own PDF internally via GetKTADocumentFile
            byte[] documentBytes = null;
            string contentType = "application/octet-stream";

            if (!provider.Equals("PulseAI", StringComparison.OrdinalIgnoreCase))
            {
                documentBytes = GetKTADocumentFile(documentId, taSdkUrl, taSessionId);
                contentType = DetectContentType(documentBytes);
            }

            // 3) Route to provider
            if (provider.Equals("Azure", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    string resolvedModelOrProcessorId = ResolveModelForDocumentType(provider, modelMapJson, documentType);

                    var azureVars = ReadServerVariables(taSessionId, taSdkUrl, new List<string>() { TPE_AZURE_DIENDPOINT, TPE_AZURE_APIVERSION, TPE_AZURE_POLL_INTERVAL_MS });

                    string azureEndpoint = (azureVars[TPE_AZURE_DIENDPOINT] ?? "").Trim();
                    string apiVersion = (azureVars[TPE_AZURE_APIVERSION] ?? "").Trim();
                    int pollIntervalMs = ParseIntOrDefault(azureVars[TPE_AZURE_POLL_INTERVAL_MS], 1000);
                    if (pollIntervalMs <= 0) pollIntervalMs = 1000;

                    if (string.IsNullOrWhiteSpace(azureEndpoint)) throw new Exception("Server variable '" + TPE_AZURE_DIENDPOINT + "' is empty.");
                    if (string.IsNullOrWhiteSpace(apiVersion)) apiVersion = "2023-07-31";
                    if (string.IsNullOrWhiteSpace(azureApiKey)) throw new Exception("azureApiKey is required when provider is Azure.");

                    TAAzureExtractor azureExtractor = new TAAzureExtractor();
                    return azureExtractor.Analyze(documentBytes, contentType, azureEndpoint, azureApiKey, resolvedModelOrProcessorId, apiVersion, pollIntervalMs, timeoutSeconds);
                }
                catch (Exception azureEx) { throw new Exception("Exception occurred. " + azureEx.Message); }
            }

            if (provider.Equals("Google", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    string resolvedModelOrProcessorId = ResolveModelForDocumentType(provider, modelMapJson, documentType);

                    var googleVars = ReadServerVariables(taSessionId, taSdkUrl, new List<string>() { TPE_GOOGLE_PROJECT_ID, TPE_GOOGLE_LOCATION });

                    string googleProjectId = (googleVars[TPE_GOOGLE_PROJECT_ID] ?? "").Trim();
                    string googleLocation = (googleVars[TPE_GOOGLE_LOCATION] ?? "").Trim();

                    if (string.IsNullOrWhiteSpace(googleProjectId)) throw new Exception("Server variable '" + TPE_GOOGLE_PROJECT_ID + "' is empty.");
                    if (string.IsNullOrWhiteSpace(googleLocation)) throw new Exception("Server variable '" + TPE_GOOGLE_LOCATION + "' is empty.");
                    if (string.IsNullOrWhiteSpace(googleServiceAccountJson)) throw new Exception("googleServiceAccountJson is required when provider is Google.");

                    TAGoogleExtractor googleExtractor = new TAGoogleExtractor();
                    return googleExtractor.Analyze(documentBytes, contentType, googleProjectId, googleLocation, resolvedModelOrProcessorId, googleServiceAccountJson, timeoutSeconds, documentType);
                }
                catch (Exception googleEx) { throw new Exception("Exception occurred. " + googleEx.Message); }
            }

            if (provider.Equals("PulseAI", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    // pulseBaseUrl    ← TPE-PULSE-URL server variable
                    // schemaJson      ← TPE-PULSE-SCHEMA-MAP server variable (keyed by documentType)
                    // timeoutSeconds  ← TPE-TimeoutSeconds server variable (already read above)
                    // useAsync        ← TPE-PULSE-USE-ASYNC server variable ("true" / "false")
                    // pulseApiKey     ← secure — passed as input parameter from TA
                    var pulseVars = ReadServerVariables(taSessionId, taSdkUrl, new List<string>() { TPE_PULSE_URL, TPE_PULSE_SCHEMA_MAP, TPE_PULSE_USE_ASYNC });

                    string pulseBaseUrl = (pulseVars[TPE_PULSE_URL] ?? "").Trim();
                    string schemaMapJson = (pulseVars[TPE_PULSE_SCHEMA_MAP] ?? "").Trim();
                    bool useAsync = ParseBoolOrDefault(pulseVars[TPE_PULSE_USE_ASYNC], false);

                    if (string.IsNullOrWhiteSpace(pulseBaseUrl)) throw new Exception("Server variable '" + TPE_PULSE_URL + "' is empty.");
                    if (string.IsNullOrWhiteSpace(schemaMapJson)) throw new Exception("Server variable '" + TPE_PULSE_SCHEMA_MAP + "' is empty.");
                    if (string.IsNullOrWhiteSpace(pulseApiKey)) throw new Exception("pulseApiKey is required when provider is PulseAI (pass secure TA server variable as input).");

                    // Resolve schema for this document type from the single combined map
                    JObject schemaMap;
                    try { schemaMap = JObject.Parse(schemaMapJson); }
                    catch (Exception ex) { throw new Exception("Server variable '" + TPE_PULSE_SCHEMA_MAP + "' is not valid JSON. " + ex.Message); }

                    JObject schemaConfig = schemaMap[documentType] as JObject;
                    if (schemaConfig == null)
                        throw new Exception("No PulseAI schema found for document type '" + documentType + "' in server variable '" + TPE_PULSE_SCHEMA_MAP + "'.");

                    string schemaJson = schemaConfig.ToString(Newtonsoft.Json.Formatting.None);

                    TAPulseExtractor pulseExtractor = new TAPulseExtractor();
                    return pulseExtractor.Analyze(documentId, pulseBaseUrl, pulseApiKey, schemaJson, timeoutSeconds, taSdkUrl, taSessionId, useAsync);
                }
                catch (Exception pulseEx) { throw new Exception("Exception occurred. " + pulseEx.Message); }
            }

            throw new Exception("Unsupported provider in server variable '" + TPE_PROVIDER + "': " + provider);
        }



        public string GetActiveProvider(string taSessionId, string taSdkUrl)
        {
            var coreVars = ReadServerVariables(taSessionId, taSdkUrl,
                new List<string>() { TPE_PROVIDER });

            string resolved = ResolveActiveProvider(coreVars[TPE_PROVIDER]);

            if (string.IsNullOrWhiteSpace(resolved))
                throw new Exception("No active provider found in '" + TPE_PROVIDER + "'. Set one entry to active: true.");

            return resolved;
        }





        // ─────────────────────────────────────────────────────────────────────
        // Resolves active provider from TPE-PROVIDER server variable.
        // Supports two formats:
        //   1. Legacy plain string:  "Azure"
        //   2. New JSON array:       [{"name":"Azure","active":false},{"name":"PulseAI","active":true}]
        // Takes the FIRST entry where active = true.
        // If plain string — returns it as-is (backward compatible).
        // ─────────────────────────────────────────────────────────────────────
        private string ResolveActiveProvider(string providerJson)
        {
            if (string.IsNullOrWhiteSpace(providerJson)) return null;

            providerJson = providerJson.Trim();

            // Legacy plain string — "Azure", "Google", "PulseAI"
            if (!providerJson.StartsWith("[")) return providerJson;

            JArray providers;
            try { providers = JArray.Parse(providerJson); }
            catch { return providerJson; } // fallback to raw value if JSON is invalid

            // Take the FIRST entry where active = true
            foreach (JToken entry in providers)
            {
                bool isActive = entry["active"] != null && entry["active"].Value<bool>();
                string name = entry["name"] != null ? entry["name"].ToString().Trim() : null;
                if (isActive && !string.IsNullOrWhiteSpace(name)) return name;
            }

            return null; // no active provider found — caller will throw
        }

        private Dictionary<string, string> ReadServerVariables(string taSessionId, string taSdkUrl, List<string> variableNames)
        {
            ServerVariableHelper serverVariableHelper = new ServerVariableHelper();
            var dict = serverVariableHelper.GetServerVariables(taSessionId, taSdkUrl, variableNames);

            Dictionary<string, string> result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (string name in variableNames)
            {
                if (!dict.ContainsKey(name)) throw new Exception("Server variable '" + name + "' was not returned.");
                result[name] = dict[name].Value;
            }
            return result;
        }

        private int ParseIntOrDefault(string s, int defaultValue)
        {
            if (string.IsNullOrWhiteSpace(s)) return defaultValue;
            int v;
            if (int.TryParse(s.Trim(), out v)) return v;
            return defaultValue;
        }

        // New helper — reads TPE-PULSE-USE-ASYNC as bool
        private bool ParseBoolOrDefault(string s, bool defaultValue)
        {
            if (string.IsNullOrWhiteSpace(s)) return defaultValue;
            bool v;
            if (bool.TryParse(s.Trim(), out v)) return v;
            return defaultValue;
        }

        private string ResolveModelForDocumentType(string provider, string modelMapJson, string documentType)
        {
            if (string.IsNullOrWhiteSpace(documentType)) throw new Exception("documentType is required.");

            JObject root;
            try { root = JObject.Parse(modelMapJson); }
            catch (Exception ex) { throw new Exception("Server variable '" + TPE_MODEL_MAP + "' is not valid JSON. " + ex.Message); }

            var providerNode = root[provider];
            if (providerNode == null) throw new Exception("Provider '" + provider + "' not found in '" + TPE_MODEL_MAP + "' JSON.");

            var modelToken = providerNode[documentType];
            if (modelToken == null) throw new Exception("DocumentType '" + documentType + "' not found under provider '" + provider + "' in '" + TPE_MODEL_MAP + "' JSON.");

            string model = modelToken.ToString();
            if (string.IsNullOrWhiteSpace(model)) throw new Exception("Model value for DocumentType '" + documentType + "' under provider '" + provider + "' is empty.");

            return model.Trim();
        }

        private string DetectContentType(byte[] fileBytes)
        {
            if (fileBytes == null || fileBytes.Length == 0) return "application/octet-stream";

            if (fileBytes.Length > 4)
            {
                if (fileBytes[0] == 0x25 && fileBytes[1] == 0x50 && fileBytes[2] == 0x44 && fileBytes[3] == 0x46) return "application/pdf";
                if ((fileBytes[0] == 0x49 && fileBytes[1] == 0x49) || (fileBytes[0] == 0x4D && fileBytes[1] == 0x4D)) return "image/tiff";
                if (fileBytes[0] == 0xFF && fileBytes[1] == 0xD8) return "image/jpeg";
                if (fileBytes[0] == 0x89 && fileBytes[1] == 0x50 && fileBytes[2] == 0x4E && fileBytes[3] == 0x47) return "image/png";
            }

            return "application/octet-stream";
        }

        private byte[] GetKTADocumentFile(string docID, string ktaSDKUrl, string sessionID)
        {
            byte[] result = new byte[1];
            byte[] buffer = new byte[4096];

            var KTAGetDocumentFile = ktaSDKUrl + "/CaptureDocumentService.svc/json/GetDocumentFile2";
            HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create(KTAGetDocumentFile);

            httpWebRequest.Proxy = null;
            httpWebRequest.ContentType = "application/json";
            httpWebRequest.Method = "POST";

            using (var streamWriter = new StreamWriter(httpWebRequest.GetRequestStream()))
            {
                string json = "{\"sessionId\":\"" + sessionID + "\",\"reportingData\": {\"Station\": \"\", \"MarkCompleted\": false }, \"documentId\":\"" + docID + "\", \"documentFileOptions\": { \"FileType\": \"\", \"IncludeAnnotations\": 0 } }";
                streamWriter.Write(json);
                streamWriter.Flush();
            }

            HttpWebResponse httpWebResponse = (HttpWebResponse)httpWebRequest.GetResponse();

            using (Stream responseStream = httpWebResponse.GetResponseStream())
            using (MemoryStream memoryStream = new MemoryStream())
            {
                int count = 0;
                do
                {
                    count = responseStream.Read(buffer, 0, buffer.Length);
                    memoryStream.Write(buffer, 0, count);
                } while (count != 0);

                result = memoryStream.ToArray();
            }

            return result;
        }
    }
}
