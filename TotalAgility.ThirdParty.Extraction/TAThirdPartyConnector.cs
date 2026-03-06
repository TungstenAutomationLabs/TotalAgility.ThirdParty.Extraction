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

        // All params in one line (as you prefer)
        public string Extract(string documentId, string documentType, string taSessionId, string taSdkUrl, string azureApiKey, string googleServiceAccountJson)
        {
            if (string.IsNullOrWhiteSpace(documentId)) throw new Exception("documentId is required.");
            if (string.IsNullOrWhiteSpace(documentType)) throw new Exception("documentType is required.");
            if (string.IsNullOrWhiteSpace(taSessionId)) throw new Exception("taSessionId is required.");
            if (string.IsNullOrWhiteSpace(taSdkUrl)) throw new Exception("taSdkUrl is required.");
            if (string.IsNullOrWhiteSpace(taSdkUrl)) throw new Exception("ktaSdkUrl is required.");

            // 1) Read core server variables
            var coreVars = ReadServerVariables(taSessionId, taSdkUrl, new List<string>() { TPE_PROVIDER, TPE_MODEL_MAP, TPE_TIMEOUT_SECONDS });

            string provider = (coreVars[TPE_PROVIDER] ?? "").Trim();
            string modelMapJson = coreVars[TPE_MODEL_MAP];
            int timeoutSeconds = ParseIntOrDefault(coreVars[TPE_TIMEOUT_SECONDS], 60);
            if (timeoutSeconds <= 0) timeoutSeconds = 60;

            if (string.IsNullOrWhiteSpace(provider)) throw new Exception("Server variable '" + TPE_PROVIDER + "' is empty.");
            if (string.IsNullOrWhiteSpace(modelMapJson)) throw new Exception("Server variable '" + TPE_MODEL_MAP + "' is empty.");

            // 2) Resolve modelId (Azure) or processorId (Google) from JSON
            string resolvedModelOrProcessorId = ResolveModelForDocumentType(provider, modelMapJson, documentType);

            // 3) Get document bytes from TA/KTA
            byte[] documentBytes = GetKTADocumentFile(documentId, taSdkUrl, taSessionId);

            // 4) Detect content type
            string contentType = DetectContentType(documentBytes);

            // 5) Route
            if (provider.Equals("Azure", StringComparison.OrdinalIgnoreCase))
            {
               try
                { 
                var azureVars = ReadServerVariables(taSessionId, taSdkUrl, new List<string>() { TPE_AZURE_DIENDPOINT, TPE_AZURE_APIVERSION, TPE_AZURE_POLL_INTERVAL_MS });

                string azureEndpoint = (azureVars[TPE_AZURE_DIENDPOINT] ?? "").Trim();
                string apiVersion = (azureVars[TPE_AZURE_APIVERSION] ?? "").Trim();
                int pollIntervalMs = ParseIntOrDefault(azureVars[TPE_AZURE_POLL_INTERVAL_MS], 1000);
                if (pollIntervalMs <= 0) pollIntervalMs = 1000;

                if (string.IsNullOrWhiteSpace(azureEndpoint)) throw new Exception("Server variable '" + TPE_AZURE_DIENDPOINT + "' is empty.");
                if (string.IsNullOrWhiteSpace(apiVersion)) apiVersion = "2023-07-31";

                // Azure API key is secure -> passed as input parameter
                if (string.IsNullOrWhiteSpace(azureApiKey)) throw new Exception("azureApiKey is required when provider is Azure (pass secure TA server variable as input).");

                int maxPollSeconds = timeoutSeconds;

                TAAzureExtractor azureExtractor = new TAAzureExtractor();
                return azureExtractor.Analyze(documentBytes, contentType, azureEndpoint, azureApiKey, resolvedModelOrProcessorId, apiVersion, pollIntervalMs, maxPollSeconds);
                }
                catch (Exception azureEx)
                {
                    throw new Exception("Exception occurred. " + azureEx.Message);
                }
            }

            if (provider.Equals("Google", StringComparison.OrdinalIgnoreCase))
            {
                
                try
                {
                    var googleVars = ReadServerVariables(taSessionId, taSdkUrl, new List<string>() { TPE_GOOGLE_PROJECT_ID, TPE_GOOGLE_LOCATION });

                    string googleProjectId = (googleVars[TPE_GOOGLE_PROJECT_ID] ?? "").Trim();
                    string googleLocation = (googleVars[TPE_GOOGLE_LOCATION] ?? "").Trim();

                    if (string.IsNullOrWhiteSpace(googleProjectId)) throw new Exception("Server variable '" + TPE_GOOGLE_PROJECT_ID + "' is empty.");
                    if (string.IsNullOrWhiteSpace(googleLocation)) throw new Exception("Server variable '" + TPE_GOOGLE_LOCATION + "' is empty.");

                    // Google SA JSON is secure -> passed as input parameter (TPE-GOOGLE-SA-JSON)
                    if (string.IsNullOrWhiteSpace(googleServiceAccountJson)) throw new Exception("googleServiceAccountJson is required when provider is Google (pass secure TA server variable as input).");
                    
                    string processorId = resolvedModelOrProcessorId;

                    TAGoogleExtractor googleExtractor = new TAGoogleExtractor();
                   
                    return googleExtractor.Analyze(documentBytes, contentType, googleProjectId, googleLocation, processorId, googleServiceAccountJson, timeoutSeconds, documentType);
                    
                }
                catch(Exception googleEx)
                {
                    throw new Exception("Exception occurred. " + googleEx.Message);
                }
            }

            throw new Exception("Unsupported provider in server variable '" + TPE_PROVIDER + "': " + provider);
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
            if (string.IsNullOrWhiteSpace(model)) throw new Exception("Model/Processor value for DocumentType '" + documentType + "' under provider '" + provider + "' is empty in '" + TPE_MODEL_MAP + "' JSON.");

            return model.Trim();
        }

        private string DetectContentType(byte[] fileBytes)
        {
            if (fileBytes == null || fileBytes.Length == 0) return "application/octet-stream";

            if (fileBytes.Length > 4)
            {
                if (fileBytes[0] == 0x25 && fileBytes[1] == 0x50 && fileBytes[2] == 0x44 && fileBytes[3] == 0x46) return "application/pdf"; // %PDF
                if ((fileBytes[0] == 0x49 && fileBytes[1] == 0x49) || (fileBytes[0] == 0x4D && fileBytes[1] == 0x4D)) return "image/tiff"; // II / MM
                if (fileBytes[0] == 0xFF && fileBytes[1] == 0xD8) return "image/jpeg"; // FF D8
                if (fileBytes[0] == 0x89 && fileBytes[1] == 0x50 && fileBytes[2] == 0x4E && fileBytes[3] == 0x47) return "image/png"; // 89 50 4E 47
            }

            return "application/octet-stream";
        }

        // Existing method unchanged (params one line)
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