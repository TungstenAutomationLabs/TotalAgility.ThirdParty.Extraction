using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TotalAgility.ThirdParty.Extraction;

namespace TotalAgility.ThirdParty.ExtractionTests
{
    internal class Program
    {
        static void Main(string[] args)
        {
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
            string documentId = @"";
            string documentType = "Invoice";// "Invoice" must match your TPE-MODEL-MAP keys   "Driver License"
            string taSessionId = "YOUR_KEY_HERE";
            string taSdkUrl = ""; // example: https://myta/Services/Sdk
            

            // Secure inputs (TA will pass secure server variable values to the DLL in real execution)
            string azureApiKey = "YOUR_KEY_HERE"; //       can be empty if TPE-PROVIDER=Google





            try
            {
                Console.WriteLine("Starting Third Party Extraction test...");

                TAThirdPartyConnector connector = new TAThirdPartyConnector();
                string resultJson = connector.Extract(documentId, documentType, taSessionId, taSdkUrl,  azureApiKey, googleServiceAccountJson);

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
