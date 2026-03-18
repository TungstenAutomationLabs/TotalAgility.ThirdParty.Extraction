using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TotalAgility.ThirdParty.Extraction;
using static System.Net.Mime.MediaTypeNames;

namespace TotalAgility.ThirdParty.ExtractionTests
{
    internal class Program
    {
        static void Main(string[] args)
        {

            //TAPulseExtractor tap= new TAPulseExtractor();
            //string schemaJson = @"
            //    {
            //      ""input_schema"": {
            //        ""type"": ""object"",
            //        ""properties"": {
            //          ""invoice_number"": { ""type"": ""string"" },
            //          ""vendor_name"": { ""type"": ""string"" },
            //          ""total"": { ""type"": ""number"" },
            //          ""line_items"": {
            //            ""type"": ""array"",
            //            ""items"": {
            //              ""type"": ""object"",
            //              ""properties"": {
            //                ""description"": { ""type"": ""string"" },
            //                ""amount"": { ""type"": ""number"" }
            //              }
            //            }
            //          }
            //        },
            //        ""required"": [""invoice_number"", ""total""]
            //      },
            //      ""schema_prompt"": ""Extract invoice details including line items""
            //    }";

            //string resultJsonPulse= tap.Analyze("92f72c1f-c390-4d76-a113-b40c0166c0d8", "https://api.runpulse.com", "DB8-kWRTwo4lvT80eJBZHmY7s0w4goznLTZ0Snmwnkk", schemaJson, 60, "https://ktacloudeco-dev.ttaprt.dev.tungstencloud.com/Services/Sdk", "D2A967C768C7854B91C210DF77F118A4", true);
           

            
            //YOUR_KEY_HERE as per below format. You can leave the googleServiceAccountJson empty if you are only testing Azure DI connectivity (i.e. TPE-PROVIDER=AzureDI). Make sure to fill in the correct secure input(s) based on your TPE-PROVIDER choice and your configuration in TA (e.g. if you set TPE-PROVIDER=Google, then you need to fill in googleServiceAccountJson with the correct service account info in JSON format as shown below)
            string googleServiceAccountJson = "YOUR_KEY_HERE";
            //string googleServiceAccountJson = @"
            //{
            //  ""type"": ""service_account"",
            //  ""project_id"": ""ttion"",
            //  ""private_key_id"": """",
            //  ""private_key"": """,
            //  ""client_email"": "",
            //  ""client_id"": """",
            //  ""auth_uri"": """",
            //  ""token_uri"": """",
            //  ""auth_provider_x509_cert_url"": """",
            //  ""client_x509_cert_url"": """",
            //  ""universe_domain"": """"
            //}";


            //TAGoogleDiagnostic tad=new TAGoogleDiagnostic();
            //tad.RunDiagnostic(googleServiceAccountJson, "201901307759", "us", "5cb38dc9fac99e45");

            //TotalAgility.ThirdParty.Extraction.ConnectivityTest connectivityTest = new TotalAgility.ThirdParty.Extraction.ConnectivityTest();
            //connectivityTest.TestGoogleConnectivity("us");

            // TODO: Fill these
            string documentId = @"92f72c1f-c390-4d76-a113-b40c0166c0d8";
            string documentType = "Invoice";// "Invoice" must match your TPE-MODEL-MAP keys   "Driver License"
            string taSessionId = "D2A967C768C7854B91C210DF77F118A4";
            string taSdkUrl = "https://ktacloudeco-dev.ttaprt.dev.tungstencloud.com/Services/Sdk"; // example: https://myta/Services/Sdk
            

            // Secure inputs (TA will pass secure server variable values to the DLL in real execution)
            string azureApiKey = "YOUR_KEY_HERE"; //       can be empty if TPE-PROVIDER=Google





            try
            {
                Console.WriteLine("Starting Third Party Extraction test...");

                TAThirdPartyConnector connector = new TAThirdPartyConnector();
                string resultJson = connector.Extract(documentId, documentType, taSessionId, taSdkUrl,  azureApiKey, googleServiceAccountJson, "DB8-kWRTwo4lvT80eJBZHmY7s0w4goznLTZ0Snmwnkk");

                Console.WriteLine("SUCCESS. First 1500 chars of response:");
                Console.WriteLine(resultJson != null && resultJson.Length > 1500 ? resultJson.Substring(0, 1500) + "..." : resultJson);

                Console.WriteLine("Done.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("FAILED:");
                Console.WriteLine(ex.ToString());
            }

            Console.WriteLine("Press ENTER to exit.");
            Console.ReadLine();
        }
    }
}
