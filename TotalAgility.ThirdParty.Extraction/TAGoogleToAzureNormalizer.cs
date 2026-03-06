using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;

namespace TotalAgility.ThirdParty.Extraction
{
    public class TAGoogleToAzureNormalizer
    {
        // Known Google entity type -> Azure field name mappings
        // These ensure the fields TotalAgility already expects retain their exact names
        private static readonly Dictionary<string, string> EntityToFieldMap =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "Family Name",      "LastName" },
            { "Given Names",      "FirstName" },
            { "Document Id",      "DocumentNumber" },
            { "Date Of Birth",    "DateOfBirth" },
            { "Expiration Date",  "DateOfExpiration" },
            { "Issue Date",       "DateOfIssue" },
            { "Address",          "Address" }
        };

        public string NormalizeResponse(string googleJson)
        {
            if (string.IsNullOrWhiteSpace(googleJson))
                throw new Exception("Google JSON response is empty.");

            JObject root = JObject.Parse(googleJson);
            JObject document = root["document"] as JObject;

            if (document == null)
                throw new Exception("Google response missing 'document' node.");

            StripEmbeddedImages(document);

            JArray entities = document["entities"] as JArray;
            if (entities == null || entities.Count == 0)
                throw new Exception(
                    "Google response has no 'entities'. " +
                    "Ensure the processor is a US Driver License processor.");

            JArray tokens = null;
            JToken pagesToken = document["pages"];
            if (pagesToken is JArray && ((JArray)pagesToken).Count > 0)
            {
                tokens = pagesToken[0]["tokens"] as JArray;
            }

            JObject fields = new JObject();

            foreach (JToken entity in entities)
            {
                string entityType = entity["type"]?.ToString();
                if (string.IsNullOrEmpty(entityType)) continue;

                // Use known mapping if available, otherwise convert Google type to PascalCase
                string azureFieldName;
                if (!EntityToFieldMap.TryGetValue(entityType, out azureFieldName))
                {
                    azureFieldName = ConvertToPascalCase(entityType);
                }

                string mentionText = entity["mentionText"]?.ToString() ?? "";
                double confidence = entity["confidence"]?.Value<double>() ?? 0;

                int entityStart = -1;
                int entityEnd = -1;
                JArray textSegments = entity["textAnchor"]?["textSegments"] as JArray;
                if (textSegments != null && textSegments.Count > 0)
                {
                    entityStart = ParseIndex(textSegments[0]["startIndex"]);
                    entityEnd = ParseIndex(textSegments[0]["endIndex"]);
                }

                JArray polygon = ResolveBoundingBoxFromTokens(tokens, entityStart, entityEnd);

                fields[azureFieldName] = new JObject
                {
                    ["type"] = "string",
                    ["valueString"] = mentionText,
                    ["content"] = mentionText,
                    ["confidence"] = confidence,
                    ["boundingRegions"] = new JArray
                    {
                        new JObject
                        {
                            ["pageNumber"] = 1,
                            ["polygon"] = polygon
                        }
                    }
                };
            }

            JObject result = new JObject
            {
                ["analyzeResult"] = new JObject
                {
                    ["documents"] = new JArray
                    {
                        new JObject
                        {
                            ["fields"] = fields
                        }
                    }
                }
            };

            return result.ToString(Newtonsoft.Json.Formatting.None);
        }

        /// <summary>
        /// Converts a Google entity type like "Family Name" or "Date Of Birth"
        /// to PascalCase like "FamilyName" or "DateOfBirth" for use as Azure field name.
        /// </summary>
        private string ConvertToPascalCase(string entityType)
        {
            if (string.IsNullOrEmpty(entityType)) return entityType;

            string[] words = entityType.Split(new char[] { ' ', '_', '-' }, StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < words.Length; i++)
            {
                if (words[i].Length > 0)
                {
                    words[i] = char.ToUpper(words[i][0]) + words[i].Substring(1);
                }
            }
            return string.Join("", words);
        }

        private JArray ResolveBoundingBoxFromTokens(JArray tokens, int entityStart, int entityEnd)
        {
            JArray polygon = new JArray();

            if (tokens == null || entityStart < 0 || entityEnd < 0)
                return polygon;

            int minX = int.MaxValue, minY = int.MaxValue;
            int maxX = int.MinValue, maxY = int.MinValue;
            bool found = false;

            foreach (JToken token in tokens)
            {
                JArray tokenSegments = token["layout"]?["textAnchor"]?["textSegments"] as JArray;
                if (tokenSegments == null || tokenSegments.Count == 0) continue;

                int tokenStart = ParseIndex(tokenSegments[0]["startIndex"]);
                int tokenEnd = ParseIndex(tokenSegments[0]["endIndex"]);

                if (tokenEnd <= entityStart || tokenStart >= entityEnd)
                    continue;

                JArray vertices = token["layout"]?["boundingPoly"]?["vertices"] as JArray;
                if (vertices == null || vertices.Count < 4) continue;

                found = true;
                foreach (JToken vertex in vertices)
                {
                    int x = vertex["x"]?.Value<int>() ?? 0;
                    int y = vertex["y"]?.Value<int>() ?? 0;
                    if (x < minX) minX = x;
                    if (y < minY) minY = y;
                    if (x > maxX) maxX = x;
                    if (y > maxY) maxY = y;
                }
            }

            if (found)
            {
                polygon.Add(minX); polygon.Add(minY);
                polygon.Add(maxX); polygon.Add(minY);
                polygon.Add(maxX); polygon.Add(maxY);
                polygon.Add(minX); polygon.Add(maxY);
            }

            return polygon;
        }

        private int ParseIndex(JToken indexToken)
        {
            if (indexToken == null) return 0;
            string s = indexToken.ToString();
            if (string.IsNullOrEmpty(s)) return 0;
            int v;
            if (int.TryParse(s, out v)) return v;
            return 0;
        }

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
    }
}
