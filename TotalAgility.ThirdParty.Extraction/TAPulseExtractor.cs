using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace TotalAgility.ThirdParty.Extraction
{
    public class TAPulseExtractor
    {
        private static readonly HttpClient _httpClient = new HttpClient();        
        private const int DPI = 200;
        private const int PAGE_WIDTH_PIXELS = 1654; 
        private const int PAGE_HEIGHT_PIXELS = 2339;        
        private const int POLL_INTERVAL_MS = 2000;

        
        public string Analyze(string documentId, string pulseBaseUrl, string pulseApiKey, string schemaJson, int timeoutSeconds, string tasdkurl, string taSessionId, bool useAsync)
        {
            // Step 0: Get document bytes — always PDF, throw if not PDF
            byte[] documentBytes = GetKTADocumentFile(documentId, tasdkurl, taSessionId);

            if (documentBytes == null || documentBytes.Length == 0) throw new Exception("documentBytes is required.");
            if (string.IsNullOrWhiteSpace(pulseBaseUrl)) throw new Exception("pulseBaseUrl is required.");
            if (string.IsNullOrWhiteSpace(pulseApiKey)) throw new Exception("pulseApiKey is required.");
            if (string.IsNullOrWhiteSpace(schemaJson)) throw new Exception("schemaJson is required.");
            if (timeoutSeconds <= 0) timeoutSeconds = 60;

            pulseApiKey = pulseApiKey.Trim();
            string baseUrl = pulseBaseUrl.TrimEnd('/');

            // Dynamic random filename — always PDF extension.
            // contentType parameter is always "application/json" for the RESTful connection
            // so it cannot be used to determine the file extension.
            // GetKTADocumentFile always returns PDF — random GUID name per call.
            string fileName = Guid.NewGuid().ToString("N") + ".pdf";

            // Step 1: POST /extract (multipart/form-data)
            // sync:  returns extraction_id + bounding_boxes directly
            // async: returns job_id → PollForResult → same structure as sync
            string extractResponseJson = SubmitExtract(documentBytes, fileName, baseUrl, pulseApiKey, useAsync, timeoutSeconds);

            JObject extractResponse;
            try { extractResponse = JObject.Parse(extractResponseJson); }
            catch (Exception ex) { throw new Exception("PulseAI /extract response is not valid JSON. " + ex.Message); }

            string extractionId = extractResponse["extraction_id"] != null ? extractResponse["extraction_id"].ToString() : null;
            if (string.IsNullOrWhiteSpace(extractionId))
                throw new Exception("PulseAI /extract response did not return extraction_id.");

            JObject boundingBoxes = extractResponse["bounding_boxes"] as JObject;

            // Step 2: POST /schema — returns schema_output.values + citations
            string schemaResponseJson = ApplySchema(extractionId, schemaJson, baseUrl, pulseApiKey);

            JObject schemaResponse;
            try { schemaResponse = JObject.Parse(schemaResponseJson); }
            catch (Exception ex) { throw new Exception("PulseAI /schema response is not valid JSON. " + ex.Message); }

            JObject schemaOutput = schemaResponse["schema_output"] as JObject;
            if (schemaOutput == null)
                throw new Exception("PulseAI /schema response missing 'schema_output'.");

            JObject citations = schemaOutput["citations"] as JObject;

            // Step 3: Resolve citation IDs → bounding_boxes elements → convert to pixel coordinates
            JObject resolvedBoundingBoxes = ResolveBoundingBoxes(citations, boundingBoxes);

            // Step 4: Build combined result JSON — this becomes the TA data model payload
            JObject result = new JObject();
            result["schema_id"] = schemaResponse["schema_id"];
            result["version"] = schemaResponse["version"];

            JObject outputNode = new JObject();
            outputNode["values"] = schemaOutput["values"];
            outputNode["citations"] = citations;
            outputNode["bounding_boxes"] = resolvedBoundingBoxes;
            result["schema_output"] = outputNode;

            return result.ToString(Formatting.None);
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
                // FileType: ".pdf" — PulseAI does not support TIFF (FILE_001 error)
                string json = "{\"sessionId\":\"" + sessionID + "\",\"reportingData\": {\"Station\": \"\", \"MarkCompleted\": false }, \"documentId\":\"" + docID + "\", \"documentFileOptions\": { \"FileType\": \".pdf\", \"IncludeAnnotations\": 0 } }";
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

            // Verify PDF magic bytes: %PDF = 0x25 0x50 0x44 0x46
            // Throw immediately — PulseAI will reject any non-PDF with FILE_001
            if (result == null || result.Length < 4 ||
                result[0] != 0x25 || result[1] != 0x50 || result[2] != 0x44 || result[3] != 0x46)
                throw new Exception("GetKTADocumentFile: document returned by TA is not a valid PDF. " +
                                    "PulseAI only accepts PDF. Verify the document is stored as PDF in TotalAgility.");

            return result;
        }

        
        private string SubmitExtract(byte[] documentBytes, string fileName, string baseUrl, string apiKey, bool useAsync, int timeoutSeconds)
        {
            using (var request = new HttpRequestMessage(HttpMethod.Post, baseUrl + "/extract"))
            {
                request.Headers.Add("x-api-key", apiKey);

                var formContent = new MultipartFormDataContent();
                var fileContent = new ByteArrayContent(documentBytes);
                fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/pdf");
                formContent.Add(fileContent, "file", fileName);

                // Add async flag as form field when async mode is requested
                if (useAsync)
                    formContent.Add(new StringContent("true"), "async");

                request.Content = formContent;

                var response = _httpClient.SendAsync(request).Result;
                string body = response.Content.ReadAsStringAsync().Result;

                if (!response.IsSuccessStatusCode)
                    throw new Exception("PulseAI /extract failed. Status: " + response.StatusCode + " Body: " + body);

                // Async path — poll until job completes, return unwrapped result
                if (useAsync)
                    return PollForResult(body, baseUrl, apiKey, timeoutSeconds);

                // Sync path — body is the full extract response
                return body;
            }
        }

        

        private string PollForResult(string asyncResponseBody, string baseUrl, string apiKey, int timeoutSeconds)
        {
            JObject asyncResponse;
            try { asyncResponse = JObject.Parse(asyncResponseBody); }
            catch (Exception ex) { throw new Exception("PulseAI async /extract response is not valid JSON. " + ex.Message); }

            string jobId = asyncResponse["job_id"] != null ? asyncResponse["job_id"].ToString() : null;
            if (string.IsNullOrWhiteSpace(jobId))
                throw new Exception("PulseAI async /extract did not return job_id. Body: " + asyncResponseBody);

            DateTime timeoutAt = DateTime.UtcNow.AddSeconds(timeoutSeconds);

            while (true)
            {
                if (DateTime.UtcNow > timeoutAt)
                    throw new TimeoutException("PulseAI job polling timed out after " + timeoutSeconds + " seconds. job_id: " + jobId);

                // Task.Delay — preferred over Thread.Sleep in .NET Framework 4.8
                // Does not block the thread pool thread during the wait interval
                Task.Delay(POLL_INTERVAL_MS).GetAwaiter().GetResult();

                using (var request = new HttpRequestMessage(HttpMethod.Get, baseUrl + "/job/" + jobId))
                {
                    request.Headers.Add("x-api-key", apiKey);

                    var response = _httpClient.SendAsync(request).Result;
                    string body = response.Content.ReadAsStringAsync().Result;

                    if (!response.IsSuccessStatusCode)
                        throw new Exception("PulseAI job poll failed. Status: " + response.StatusCode + " Body: " + body);

                    JObject pollResponse;
                    try { pollResponse = JObject.Parse(body); }
                    catch (Exception ex) { throw new Exception("PulseAI poll response is not valid JSON. " + ex.Message); }

                    string status = pollResponse["status"] != null ? pollResponse["status"].ToString().ToLowerInvariant() : "";

                    if (status == "completed")
                    {
                        // "result" node has same structure as the sync /extract response
                        JToken resultToken = pollResponse["result"];
                        if (resultToken == null)
                            throw new Exception("PulseAI completed job missing 'result' field. job_id: " + jobId);
                        return resultToken.ToString(Formatting.None);
                    }

                    if (status == "failed")
                        throw new Exception("PulseAI job failed. job_id: " + jobId + " Body: " + body);

                    // status == "pending" or "processing" — continue polling
                }
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // Step 2 — Apply schema to the saved extraction
        // POST /schema
        // schemaJson = full schema_config JSON stored in TPE-PULSE-SCHEMA-{DocumentType}
        // Returns: schema_output.values + schema_output.citations
        // ─────────────────────────────────────────────────────────────────────
        private string ApplySchema(string extractionId, string schemaJson, string baseUrl, string apiKey)
        {
            JObject schemaConfig;
            try { schemaConfig = JObject.Parse(schemaJson); }
            catch (Exception ex) { throw new Exception("schemaJson server variable is not valid JSON. " + ex.Message); }

            JObject payload = new JObject();
            payload["extraction_id"] = extractionId;
            payload["schema_config"] = schemaConfig;

            using (var request = new HttpRequestMessage(HttpMethod.Post, baseUrl + "/schema"))
            {
                request.Headers.Add("x-api-key", apiKey);
                request.Content = new StringContent(payload.ToString(Formatting.None), Encoding.UTF8, "application/json");

                var response = _httpClient.SendAsync(request).Result;
                string body = response.Content.ReadAsStringAsync().Result;

                if (!response.IsSuccessStatusCode)
                    throw new Exception("PulseAI /schema failed. Status: " + response.StatusCode + " Body: " + body);

                return body;
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // Step 3 — Match citation IDs to bounding_boxes elements
        // citations:     { "vendor_name": "txt-2", "invoice_number": "tbl-1", ... }
        // boundingBoxes: full bounding_boxes object from /extract response
        // Array citations (line_items[]) → skipped, table-level highlight used instead
        // ─────────────────────────────────────────────────────────────────────
        private JObject ResolveBoundingBoxes(JObject citations, JObject boundingBoxes)
        {
            JObject resolved = new JObject();
            if (citations == null || boundingBoxes == null) return resolved;

            foreach (JProperty prop in citations.Properties())
            {
                string fieldName = prop.Name;
                JToken citationValue = prop.Value;

                // Simple string citation — resolve directly
                if (citationValue.Type == JTokenType.String)
                {
                    string elementId = citationValue.ToString();
                    JObject box = FindBoundingBoxById(elementId, boundingBoxes);
                    if (box != null) resolved[fieldName] = box;
                    continue;
                }

                // Array citation (e.g., Items[]) — resolve table-level bounding box
                // All rows reference the same table ID — use first entry found
                if (citationValue.Type == JTokenType.Array)
                {
                    JArray citationArray = citationValue as JArray;
                    if (citationArray != null && citationArray.Count > 0)
                    {
                        JObject firstItem = citationArray[0] as JObject;
                        if (firstItem != null)
                        {
                            // Get first string citation ID from first item properties
                            foreach (JProperty arrayProp in firstItem.Properties())
                            {
                                if (arrayProp.Value.Type == JTokenType.String)
                                {
                                    string tableId = arrayProp.Value.ToString();
                                    JObject box = FindBoundingBoxById(tableId, boundingBoxes);
                                    if (box != null)
                                    {
                                        // Store as table-level bounding box for the array field
                                        resolved[fieldName] = box;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    continue;
                }
            }

            return resolved;
        }


        // ─────────────────────────────────────────────────────────────────────
        // Lookup an element by ID across all bounding_boxes arrays.
        // Search order: Text → Tables → Images → Title
        // txt-N → Text[]   field-level precision
        // tbl-N → Tables[] table-level via table_info.location.coordinates
        // cht-N → Images[]
        // ─────────────────────────────────────────────────────────────────────
        private JObject FindBoundingBoxById(string id, JObject boundingBoxes)
        {
            // ── Text[] ──────────────────────────────────────────────────────
            JArray textElements = boundingBoxes["Text"] as JArray;
            if (textElements != null)
            {
                foreach (JToken element in textElements)
                {
                    if (element["id"] != null && element["id"].ToString() == id)
                    {
                        JArray coords = element["bounding_box"] as JArray;
                        int pageNumber = element["page_number"] != null ? element["page_number"].Value<int>() : 1;
                        if (coords != null && coords.Count == 8) return BuildBoundingBoxResult(coords, pageNumber);
                    }
                }
            }

            // ── Tables[] ────────────────────────────────────────────────────
            // Table bounding box is in table_info.location.coordinates
            // page key is "page" (not "page_number") for table location
            JArray tableElements = boundingBoxes["Tables"] as JArray;
            if (tableElements != null)
            {
                foreach (JToken table in tableElements)
                {
                    JObject tableInfo = table["table_info"] as JObject;
                    if (tableInfo == null) continue;
                    if (tableInfo["id"] != null && tableInfo["id"].ToString() == id)
                    {
                        JObject location = tableInfo["location"] as JObject;
                        JArray coords = location != null ? location["coordinates"] as JArray : null;
                        int pageNumber = (location != null && location["page"] != null) ? location["page"].Value<int>() : 1;
                        if (coords != null && coords.Count == 8) return BuildBoundingBoxResult(coords, pageNumber);
                    }
                }
            }

            // ── Images[] ────────────────────────────────────────────────────
            JArray imageElements = boundingBoxes["Images"] as JArray;
            if (imageElements != null)
            {
                foreach (JToken element in imageElements)
                {
                    if (element["id"] != null && element["id"].ToString() == id)
                    {
                        JArray coords = element["bounding_box"] as JArray;
                        int pageNumber = element["page_number"] != null ? element["page_number"].Value<int>() : 1;
                        if (coords != null && coords.Count == 8) return BuildBoundingBoxResult(coords, pageNumber);
                    }
                }
            }

            // ── Title[] ─────────────────────────────────────────────────────
            JArray titleElements = boundingBoxes["Title"] as JArray;
            if (titleElements != null)
            {
                foreach (JToken element in titleElements)
                {
                    if (element["id"] != null && element["id"].ToString() == id)
                    {
                        JArray coords = element["bounding_box"] as JArray;
                        int pageNumber = element["page_number"] != null ? element["page_number"].Value<int>() : 1;
                        if (coords != null && coords.Count == 8) return BuildBoundingBoxResult(coords, pageNumber);
                    }
                }
            }

            return null;
        }

        // ─────────────────────────────────────────────────────────────────────
        // Build the resolved bounding box object for a single field.
        // top/left/width/height pre-calculated here — TA process does NOT need
        // an equivalent of AzureAI_Calculate Top_Left_Width subprocess.
        //
        // PulseAI 8-point format: [x1,y1, x2,y2, x3,y3, x4,y4]
        //   (x1,y1) = Top-Left    (x2,y2) = Top-Right
        //   (x3,y3) = Bottom-Right  (x4,y4) = Bottom-Left
        // ─────────────────────────────────────────────────────────────────────
        private JObject BuildBoundingBoxResult(JArray normalizedCoords, int pageNumber)
        {
            JArray pixelPolygon = ConvertCoordinatesToPixels(normalizedCoords);

            int topLeftX = pixelPolygon[0].Value<int>(); // x1
            int topLeftY = pixelPolygon[1].Value<int>(); // y1
            int topRightX = pixelPolygon[2].Value<int>(); // x2
            int bottomLeftY = pixelPolygon[7].Value<int>(); // y4

            JObject result = new JObject();
            result["page_number"] = pageNumber;
            result["polygon"] = pixelPolygon;
            result["top"] = topLeftY;
            result["left"] = topLeftX;
            result["width"] = topRightX - topLeftX;
            result["height"] = bottomLeftY - topLeftY;

            return result;
        }

        // ─────────────────────────────────────────────────────────────────────
        // Step 4 — Convert normalized 0-1 bounding box coordinates to pixels.
        // Even indices (0,2,4,6) = X → multiply by PAGE_WIDTH_PIXELS
        // Odd  indices (1,3,5,7) = Y → multiply by PAGE_HEIGHT_PIXELS
        // ─────────────────────────────────────────────────────────────────────
        private JArray ConvertCoordinatesToPixels(JArray normalizedCoords)
        {
            JArray pixelCoords = new JArray();

            for (int i = 0; i < normalizedCoords.Count; i++)
            {
                double normalized = normalizedCoords[i].Value<double>();
                if (i % 2 == 0)
                    pixelCoords.Add((int)Math.Round(normalized * PAGE_WIDTH_PIXELS));
                else
                    pixelCoords.Add((int)Math.Round(normalized * PAGE_HEIGHT_PIXELS));
            }

            return pixelCoords;
        }
    }
}
