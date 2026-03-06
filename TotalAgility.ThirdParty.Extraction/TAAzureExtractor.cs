using Newtonsoft.Json.Linq;
using System;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;

namespace TotalAgility.ThirdParty.Extraction
{
    public class TAAzureExtractor
    {
        private static readonly HttpClient _httpClient = new HttpClient();

        // All parameters on one line (as you prefer)
        public string AnalyzeDepricated(byte[] documentBytes, string contentType, string azureEndpoint, string azureApiKey, string modelId, string apiVersion, int pollIntervalMs, int maxPollSeconds)
        {
            if (documentBytes == null || documentBytes.Length == 0) throw new Exception("documentBytes is required.");
            if (string.IsNullOrWhiteSpace(contentType)) contentType = "application/octet-stream";
            if (string.IsNullOrWhiteSpace(azureEndpoint)) throw new Exception("azureEndpoint is required.");
            if (string.IsNullOrWhiteSpace(azureApiKey)) throw new Exception("azureApiKey is required.");
            if (string.IsNullOrWhiteSpace(modelId)) throw new Exception("modelId is required.");

            if (string.IsNullOrWhiteSpace(apiVersion)) apiVersion = "2023-07-31";
            if (pollIntervalMs <= 0) pollIntervalMs = 1000;
            if (maxPollSeconds <= 0) maxPollSeconds = 60;

            string operationLocation = SubmitToAzure(documentBytes, contentType, azureEndpoint, azureApiKey, modelId, apiVersion);
            return PollForResult(operationLocation, azureApiKey, pollIntervalMs, maxPollSeconds);
        }




        public string Analyze(byte[] documentBytes, string contentType, string azureEndpoint, string azureApiKey, string modelId, string apiVersion, int pollIntervalMs, int maxPollSeconds)
        {
            if (documentBytes == null || documentBytes.Length == 0) throw new Exception("documentBytes is required.");
            if (string.IsNullOrWhiteSpace(contentType)) contentType = "application/octet-stream";
            if (string.IsNullOrWhiteSpace(azureEndpoint)) throw new Exception("azureEndpoint is required.");
            if (string.IsNullOrWhiteSpace(azureApiKey)) throw new Exception("azureApiKey is required.");
            if (string.IsNullOrWhiteSpace(modelId)) throw new Exception("modelId is required.");

            if (string.IsNullOrWhiteSpace(apiVersion)) apiVersion = "2023-07-31";
            if (pollIntervalMs <= 0) pollIntervalMs = 1000;
            if (maxPollSeconds <= 0) maxPollSeconds = 60;

            string operationLocation = SubmitToAzure(documentBytes, contentType, azureEndpoint, azureApiKey, modelId, apiVersion);
            string result = PollForResult(operationLocation, azureApiKey, pollIntervalMs, maxPollSeconds);

            // Convert inches to pixels if needed (invoices use inches, DL/receipts already use pixels)
            return ConvertInchesToPixelsIfNeeded(result);
        }

        private string SubmitToAzure(byte[] documentBytes, string contentType, string azureEndpoint, string azureApiKey, string modelId, string apiVersion)
        {
            string url = azureEndpoint.TrimEnd('/') + "/formrecognizer/documentModels/" + modelId + ":analyze?api-version=" + apiVersion;

            using (var request = new HttpRequestMessage(HttpMethod.Post, url))
            {
                request.Headers.Add("Ocp-Apim-Subscription-Key", azureApiKey);

                var content = new ByteArrayContent(documentBytes);
                content.Headers.ContentType = new MediaTypeHeaderValue(contentType);
                request.Content = content;

                var response = _httpClient.SendAsync(request).Result;

                if ((int)response.StatusCode != 202)
                {
                    string errorBody = response.Content.ReadAsStringAsync().Result;
                    throw new Exception("Azure DI Analyze failed. Status: " + response.StatusCode + " Body: " + errorBody);
                }

                if (!response.Headers.Contains("Operation-Location"))
                    throw new Exception("Azure DI Analyze did not return Operation-Location header.");

                return response.Headers.GetValues("Operation-Location").FirstOrDefault();
            }
        }

        private string PollForResult(string operationLocation, string azureApiKey, int pollIntervalMs, int maxPollSeconds)
        {
            if (string.IsNullOrWhiteSpace(operationLocation)) throw new Exception("operationLocation is empty; cannot poll.");

            DateTime timeoutAt = DateTime.UtcNow.AddSeconds(maxPollSeconds);

            while (true)
            {
                if (DateTime.UtcNow > timeoutAt)
                    throw new TimeoutException("Azure DI polling timed out after " + maxPollSeconds + " seconds.");

                using (var request = new HttpRequestMessage(HttpMethod.Get, operationLocation))
                {
                    request.Headers.Add("Ocp-Apim-Subscription-Key", azureApiKey);

                    var response = _httpClient.SendAsync(request).Result;
                    string json = response.Content.ReadAsStringAsync().Result;

                    if (!response.IsSuccessStatusCode)
                        throw new Exception("Azure DI polling failed. Status: " + response.StatusCode + " Body: " + json);

                    if (json.Contains("\"status\":\"succeeded\"")) return json;
                    if (json.Contains("\"status\":\"failed\"")) throw new Exception("Azure DI analysis failed. Body: " + json);
                }

                Thread.Sleep(pollIntervalMs);
            }
        }

        // =============================================================
        // INCH TO PIXEL CONVERSION
        // Converts ALL coordinates in the entire JSON from inches to
        // pixels so the output is structurally identical to DL/Receipt
        // outputs where unit is already "pixel".
        // =============================================================

        // Start with 200. If bounding boxes are offset, try 150, 96, 300, 72.
        private const int DPI = 200;

        private string ConvertInchesToPixelsIfNeeded(string azureJson)
        {
            JObject root = JObject.Parse(azureJson);
            JObject analyzeResult = root["analyzeResult"] as JObject;
            if (analyzeResult == null) return azureJson;

            JArray pages = analyzeResult["pages"] as JArray;
            if (pages == null || pages.Count == 0) return azureJson;

            // Check the unit of the first page
            string unit = pages[0]["unit"] != null ? pages[0]["unit"].ToString() : "";
            if (string.IsNullOrEmpty(unit) || unit == "pixel")
                return azureJson; // Already in pixels — no conversion needed

            if (unit != "inch")
                return azureJson; // Unknown unit — return as-is

            // ---- Convert EVERYTHING from inches to pixels ----

            // 1. Convert page dimensions + all page-level polygons (words, lines, spans)
            foreach (JToken page in pages)
            {
                JObject pageObj = page as JObject;
                if (pageObj == null) continue;

                double widthInch = pageObj["width"] != null ? pageObj["width"].Value<double>() : 0;
                double heightInch = pageObj["height"] != null ? pageObj["height"].Value<double>() : 0;

                pageObj["width"] = (int)Math.Round(widthInch * DPI);
                pageObj["height"] = (int)Math.Round(heightInch * DPI);
                pageObj["unit"] = "pixel";

                // Convert word polygons
                ConvertPolygonArray(pageObj["words"] as JArray);

                // Convert line polygons
                ConvertPolygonArray(pageObj["lines"] as JArray);

                // Convert selection mark polygons
                ConvertPolygonArray(pageObj["selectionMarks"] as JArray);
            }

            // 2. Convert table-level polygons
            JArray tables = analyzeResult["tables"] as JArray;
            if (tables != null)
            {
                foreach (JToken table in tables)
                {
                    ConvertBoundingRegions(table["boundingRegions"] as JArray);

                    JArray cells = table["cells"] as JArray;
                    if (cells != null)
                    {
                        foreach (JToken cell in cells)
                        {
                            ConvertBoundingRegions(cell["boundingRegions"] as JArray);
                        }
                    }
                }
            }

            // 3. Convert document-level polygons (fields, items, nested objects)
            JArray documents = analyzeResult["documents"] as JArray;
            if (documents != null)
            {
                foreach (JToken doc in documents)
                {
                    ConvertBoundingRegions(doc["boundingRegions"] as JArray);

                    JObject fields = doc["fields"] as JObject;
                    if (fields != null)
                    {
                        foreach (JProperty field in fields.Properties())
                        {
                            ConvertFieldPolygons(field.Value as JObject);
                        }
                    }
                }
            }

            return root.ToString(Newtonsoft.Json.Formatting.None);
        }

        /// <summary>
        /// Converts polygon arrays inside a list of objects (words, lines, etc.)
        /// Each object has a "polygon" property.
        /// </summary>
        private void ConvertPolygonArray(JArray items)
        {
            if (items == null) return;

            foreach (JToken item in items)
            {
                JArray polygon = item["polygon"] as JArray;
                if (polygon != null)
                {
                    for (int i = 0; i < polygon.Count; i++)
                    {
                        double inchValue = polygon[i].Value<double>();
                        polygon[i] = (int)Math.Round(inchValue * DPI);
                    }
                }
            }
        }

        /// <summary>
        /// Recursively converts all boundingRegions polygons in a field,
        /// including nested valueArray (Items) and valueObject (Address).
        /// </summary>
        private void ConvertFieldPolygons(JObject field)
        {
            if (field == null) return;

            ConvertBoundingRegions(field["boundingRegions"] as JArray);

            // Handle array fields (e.g., Items, TaxDetails)
            JArray valueArray = field["valueArray"] as JArray;
            if (valueArray != null)
            {
                foreach (JToken item in valueArray)
                {
                    JObject itemObj = item as JObject;
                    if (itemObj == null) continue;

                    ConvertBoundingRegions(itemObj["boundingRegions"] as JArray);

                    JObject properties = itemObj["valueObject"] as JObject;
                    if (properties != null)
                    {
                        foreach (JProperty prop in properties.Properties())
                        {
                            ConvertFieldPolygons(prop.Value as JObject);
                        }
                    }
                }
            }

            // Handle nested object fields (e.g., Address)
            JObject valueObject = field["valueObject"] as JObject;
            if (valueObject != null)
            {
                foreach (JProperty prop in valueObject.Properties())
                {
                    ConvertFieldPolygons(prop.Value as JObject);
                }
            }
        }

        /// <summary>
        /// Converts polygon values inside boundingRegions from inches to pixels.
        /// </summary>
        private void ConvertBoundingRegions(JArray boundingRegions)
        {
            if (boundingRegions == null) return;

            foreach (JToken region in boundingRegions)
            {
                JArray polygon = region["polygon"] as JArray;
                if (polygon == null) continue;

                for (int i = 0; i < polygon.Count; i++)
                {
                    double inchValue = polygon[i].Value<double>();
                    polygon[i] = (int)Math.Round(inchValue * DPI);
                }
            }
        }

        
    }
}