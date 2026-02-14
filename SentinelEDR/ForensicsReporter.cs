// ==========================================================================
//  Sentinel EDR — ForensicsReporter.cs
//  Automated Forensics Module: generates HTML incident reports
//  Target: .NET 8.0  |  No external dependencies
// ==========================================================================
//
//  PURPOSE
//  ───────
//  After a threat is neutralised by the ResponseEngine, this class generates
//  a professional HTML incident report and saves it to a local folder.
//  Uses only System.IO and C# string interpolation — no PDF/third-party libs.
//
//  FILE NAMING
//  ───────────
//  IncidentReports/Incident_{IP}_{yyyyMMdd_HHmmss}.html
//
//  DESIGN
//  ──────
//  The HTML uses a Dark Mode / Cyberpunk theme consistent with the main UI:
//  black background, neon green headers, Courier New monospace font.
// ==========================================================================

using System;
using System.IO;

namespace SentinelEDR
{
    /// <summary>
    /// Generates professional HTML incident reports for neutralised threats.
    /// All methods are static — no instance state required.
    /// </summary>
    public static class ForensicsReporter
    {
        /// <summary>
        /// Directory (relative to the working directory) where reports are saved.
        /// </summary>
        private const string ReportFolder = "IncidentReports";

        /// <summary>
        /// Generates an HTML incident report and writes it to disk.
        /// </summary>
        /// <param name="ip">The IP address involved in the incident.</param>
        /// <param name="threatType">Category of the threat (e.g., "Brute Force").</param>
        /// <param name="aiVerdict">Raw verdict text from the Agentic AI engine.</param>
        /// <param name="actionTaken">Description of the countermeasure executed.</param>
        /// <returns>The full file path of the generated HTML report.</returns>
        public static string GenerateHtmlReport(
            string ip,
            string threatType,
            string aiVerdict,
            string actionTaken)
        {
            // Ensure the output directory exists
            string fullFolderPath = Path.GetFullPath(ReportFolder);
            Directory.CreateDirectory(fullFolderPath);

            // Build a filesystem-safe timestamp and filename
            string timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
            string safeIp = ip.Replace(":", "-");   // Handle IPv6 colons
            string fileName = $"Incident_{safeIp}_{timestamp}.html";
            string filePath = Path.Combine(fullFolderPath, fileName);

            // Current UTC time for the report header
            string reportTime = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss 'UTC'");

            // HTML-encode user-supplied values to prevent XSS if opened in a browser
            string safeIpHtml = System.Net.WebUtility.HtmlEncode(ip);
            string safeThreatType = System.Net.WebUtility.HtmlEncode(threatType);
            string safeAiVerdict = System.Net.WebUtility.HtmlEncode(aiVerdict);
            string safeActionTaken = System.Net.WebUtility.HtmlEncode(actionTaken);

            // ── Build the HTML report using raw string literal ────────────
            // Using $$""" so that single { } are literal (for CSS/HTML) and
            // {{expression}} is the interpolation hole.
            string html = $$"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
                <title>Sentinel EDR — Incident Report</title>
                <style>
                    * {
                        margin: 0;
                        padding: 0;
                        box-sizing: border-box;
                    }
                    body {
                        background-color: #0D0D0D;
                        color: #C0C0C0;
                        font-family: 'Courier New', Courier, monospace;
                        padding: 40px;
                        line-height: 1.6;
                    }
                    .container {
                        max-width: 800px;
                        margin: 0 auto;
                        border: 1px solid #39FF14;
                        padding: 30px;
                        box-shadow: 0 0 20px rgba(57, 255, 20, 0.15);
                    }
                    h1 {
                        color: #39FF14;
                        text-align: center;
                        font-size: 24px;
                        letter-spacing: 4px;
                        border-bottom: 2px solid #39FF14;
                        padding-bottom: 16px;
                        margin-bottom: 30px;
                        text-shadow: 0 0 10px rgba(57, 255, 20, 0.5);
                    }
                    h2 {
                        color: #39FF14;
                        font-size: 16px;
                        letter-spacing: 2px;
                        margin-top: 24px;
                        margin-bottom: 10px;
                        border-left: 3px solid #39FF14;
                        padding-left: 12px;
                    }
                    .field-label {
                        color: #00F0FF;
                        font-weight: bold;
                    }
                    .field-value {
                        color: #E0E0E0;
                        margin-left: 16px;
                        margin-bottom: 6px;
                    }
                    .verdict-box {
                        background-color: #1A1A2E;
                        border: 1px solid #FF003C;
                        padding: 16px;
                        margin-top: 8px;
                        white-space: pre-wrap;
                        word-wrap: break-word;
                        color: #FFA500;
                    }
                    .action-box {
                        background-color: #1A1A2E;
                        border: 1px solid #39FF14;
                        padding: 16px;
                        margin-top: 8px;
                        color: #39FF14;
                    }
                    .timestamp {
                        text-align: center;
                        color: #8892B0;
                        font-size: 13px;
                        margin-bottom: 20px;
                    }
                    .footer {
                        text-align: center;
                        color: #8892B0;
                        font-size: 11px;
                        margin-top: 30px;
                        border-top: 1px solid #2A2A4A;
                        padding-top: 16px;
                    }
                    .classification {
                        text-align: center;
                        color: #FF003C;
                        font-size: 14px;
                        font-weight: bold;
                        letter-spacing: 6px;
                        margin-bottom: 20px;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="classification">CONFIDENTIAL</div>
                    <h1>SENTINEL EDR &mdash; INCIDENT REPORT</h1>
                    <p class="timestamp">Report generated: {{reportTime}}</p>

                    <h2>THREAT INTELLIGENCE</h2>
                    <p><span class="field-label">Source IP:</span></p>
                    <p class="field-value">{{safeIpHtml}}</p>
                    <p><span class="field-label">Threat Type:</span></p>
                    <p class="field-value">{{safeThreatType}}</p>

                    <h2>AI ANALYSIS</h2>
                    <div class="verdict-box">{{safeAiVerdict}}</div>

                    <h2>ACTION TAKEN</h2>
                    <div class="action-box">{{safeActionTaken}}</div>

                    <div class="footer">
                        Sentinel EDR &mdash; Automated Forensics Module<br/>
                        This report was generated automatically upon threat neutralisation.
                    </div>
                </div>
            </body>
            </html>
            """;

            File.WriteAllText(filePath, html);

            return filePath;
        }
    }
}
