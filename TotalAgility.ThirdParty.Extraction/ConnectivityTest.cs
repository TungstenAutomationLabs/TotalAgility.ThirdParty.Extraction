using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace TotalAgility.ThirdParty.Extraction
{
    public class ConnectivityTest
    {
        public string TestGoogleConnectivity(string googleLocation)
        {
            // Force TLS 1.2
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            if (string.IsNullOrWhiteSpace(googleLocation)) googleLocation = "us";

            StringBuilder report = new StringBuilder();
            report.AppendLine("=== Google Connectivity Test ===");
            report.AppendLine("Timestamp (UTC): " + DateTime.UtcNow.ToString("o"));
            report.AppendLine();

            // Test 1: Google OAuth endpoint
            TestEndpoint(report, "Google OAuth", "https://oauth2.googleapis.com/");

            // Test 2: Google Document AI regional endpoint
            string docAiHost = googleLocation.Trim().ToLower() + "-documentai.googleapis.com";
            TestEndpoint(report, "Google Document AI (" + googleLocation + ")", "https://" + docAiHost + "/");

            // Test 3: General Google connectivity
            TestEndpoint(report, "Google (general)", "https://www.googleapis.com/");

            // Bonus: Test Azure for comparison (we know this works)
            TestEndpoint(report, "Azure (control test)", "https://cognitiveservices.azure.com/");

            report.AppendLine("=== Test Complete ===");
            return report.ToString();
        }

        private void TestEndpoint(StringBuilder report, string label, string url)
        {
            report.AppendLine("--- " + label + " ---");
            report.AppendLine("URL: " + url);

            try
            {
                using (var httpClient = new HttpClient())
                {
                    httpClient.Timeout = TimeSpan.FromSeconds(15);

                    // We just need to see if the connection is established.
                    // A 404 or 405 is FINE — it means the network connection succeeded.
                    // A timeout or connection refused means it's blocked.
                    var response = httpClient.GetAsync(url).GetAwaiter().GetResult();

                    report.AppendLine("STATUS: REACHABLE");
                    report.AppendLine("HTTP Status Code: " + (int)response.StatusCode + " " + response.StatusCode);
                    report.AppendLine();
                }
            }
            catch (Exception ex)
            {
                report.AppendLine("STATUS: UNREACHABLE");
                report.AppendLine("Exception Type: " + ex.GetType().FullName);
                report.AppendLine("Message: " + ex.Message);

                if (ex.InnerException != null)
                {
                    report.AppendLine("Inner Type: " + ex.InnerException.GetType().FullName);
                    report.AppendLine("Inner Message: " + ex.InnerException.Message);

                    if (ex.InnerException.InnerException != null)
                    {
                        report.AppendLine("Inner Inner Type: " + ex.InnerException.InnerException.GetType().FullName);
                        report.AppendLine("Inner Inner Message: " + ex.InnerException.InnerException.Message);
                    }
                }
                report.AppendLine();
            }
        }
    }
}
