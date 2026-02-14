// ==========================================================================
//  Sentinel EDR — ThreatIntelService.cs
//  Module 1: "The Pre-Crime Division" — Threat Intelligence Engine
//  Target: .NET 8.0  |  AbuseIPDB API Integration (mock for demonstration)
// ==========================================================================
//
//  PURPOSE
//  ───────
//  Provides a single static method that returns an "Abuse Confidence Score"
//  (0–100) for any given IP address.  The architecture is wired for the
//  real AbuseIPDB v2 REST API — headers, query params, and JSON parsing
//  are all in place.  The actual HTTP call is mocked so the app runs
//  without an API key during demos and portfolio reviews.
//
//  PRODUCTION UPGRADE PATH
//  ───────────────────────
//  1. Replace ABUSEIPDB_API_KEY with a real key (load from env / vault).
//  2. Set USE_LIVE_API = true.
//  3. The live path is already implemented — it will call AbuseIPDB and
//     parse the JSON response automatically.
//
// ==========================================================================

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

namespace SentinelEDR
{
    /// <summary>
    /// Queries threat intelligence sources to determine if an IP address
    /// is associated with malicious activity.  Returns a confidence score
    /// from 0 (completely safe) to 100 (confirmed malicious).
    /// </summary>
    public static class ThreatIntelService
    {
        // ==================================================================
        //  CONFIGURATION
        // ==================================================================

        /// <summary>
        /// AbuseIPDB API key.  In production, load from environment variable
        /// or a secrets manager (Azure Key Vault, AWS Secrets Manager, etc.).
        /// </summary>
        private const string ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_KEY_HERE";

        /// <summary>
        /// AbuseIPDB v2 "check" endpoint — returns reputation data for a
        /// single IP including abuse confidence score, country, ISP, etc.
        /// </summary>
        private const string ABUSEIPDB_ENDPOINT =
            "https://api.abuseipdb.com/api/v2/check";

        /// <summary>
        /// Toggle for live vs. mock API calls.  Set to true when you have
        /// a valid API key and want real-time threat intelligence.
        /// </summary>
        private const bool USE_LIVE_API = false;

        /// <summary>
        /// Shared HttpClient — reused across all calls to avoid socket
        /// exhaustion (best practice for long-lived applications).
        /// </summary>
        private static readonly HttpClient _httpClient = new()
        {
            Timeout = TimeSpan.FromSeconds(15)
        };

        // ==================================================================
        //  MOCK THREAT DATABASE
        // ==================================================================

        /// <summary>
        /// Known malicious IPs and their confidence scores.  These match
        /// the IPs used by the Red Team Simulator so the full pipeline
        /// produces consistent, demonstrable results.
        /// </summary>
        private static readonly Dictionary<string, int> _knownMaliciousIps = new()
        {
            ["203.0.113.50"]  = 92,   // CN — brute force SSH
            ["198.51.100.23"] = 88,   // RU — credential stuffing
            ["45.155.205.99"] = 95,   // KP — APT C2 beacon
            ["185.220.101.34"] = 90,  // RU — Tor exit relay
            ["91.240.118.172"] = 85,  // IR — scanning / recon
            ["23.129.64.210"]  = 82   // US — Tor exit node
        };

        // ==================================================================
        //  PUBLIC API
        // ==================================================================

        /// <summary>
        /// Returns the Abuse Confidence Score (0–100) for the given IP.
        ///
        /// Scoring guide (mirrors AbuseIPDB's scale):
        ///   0       = Definitely safe (local / private range)
        ///   1–25    = Low risk
        ///   26–75   = Suspicious — warrants investigation
        ///   76–100  = High confidence malicious — recommend blocking
        ///
        /// This method is safe to call from the UI thread — it uses
        /// async/await and will not block.
        /// </summary>
        /// <param name="ip">IPv4 or IPv6 address to check.</param>
        /// <returns>Confidence score from 0 (safe) to 100 (malicious).</returns>
        public static async Task<int> GetAbuseConfidenceScore(string ip)
        {
            // ── STEP 1: Fast-path for known safe local / private IPs ────
            // RFC-1918 and loopback addresses are always internal traffic.
            // No need to waste an API call on these.
            if (IsPrivateOrLocalIp(ip))
            {
                return 0;
            }

            // ── STEP 2: Route to live API or mock database ──────────────
            if (USE_LIVE_API)
            {
                return await QueryAbuseIPDBLive(ip);
            }
            else
            {
                return await QueryMockDatabase(ip);
            }
        }

        // ==================================================================
        //  PRIVATE — IP Classification
        // ==================================================================

        /// <summary>
        /// Determines if an IP belongs to a private (RFC-1918) or
        /// loopback range.  These are never routable on the public
        /// internet and are therefore inherently safe from external
        /// threat intelligence perspective.
        /// </summary>
        private static bool IsPrivateOrLocalIp(string ip)
        {
            return ip == "127.0.0.1"
                || ip == "::1"
                || ip.StartsWith("192.168.")
                || ip.StartsWith("10.")
                || ip.StartsWith("172.16.")
                || ip.StartsWith("172.17.")
                || ip.StartsWith("172.18.")
                || ip.StartsWith("172.19.")
                || ip.StartsWith("172.20.")
                || ip.StartsWith("172.21.")
                || ip.StartsWith("172.22.")
                || ip.StartsWith("172.23.")
                || ip.StartsWith("172.24.")
                || ip.StartsWith("172.25.")
                || ip.StartsWith("172.26.")
                || ip.StartsWith("172.27.")
                || ip.StartsWith("172.28.")
                || ip.StartsWith("172.29.")
                || ip.StartsWith("172.30.")
                || ip.StartsWith("172.31.");
        }

        // ==================================================================
        //  PRIVATE — Mock Database Query
        // ==================================================================

        /// <summary>
        /// Simulates an API round-trip by checking the local threat
        /// database.  Adds a small delay to mimic network latency so
        /// the UI feels realistic during demos.
        /// </summary>
        private static async Task<int> QueryMockDatabase(string ip)
        {
            // Simulate network latency (100–300ms)
            await Task.Delay(Random.Shared.Next(100, 300));

            // Check our known-malicious database
            if (_knownMaliciousIps.TryGetValue(ip, out int score))
            {
                return score;
            }

            // Unknown public IPs get a low baseline score
            return 0;
        }

        // ==================================================================
        //  PRIVATE — Live AbuseIPDB API Query
        // ==================================================================

        /// <summary>
        /// Calls the real AbuseIPDB v2 /check endpoint.  This path is
        /// fully implemented — just supply a valid API key and flip
        /// USE_LIVE_API to true.
        ///
        /// Request:
        ///   GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&amp;maxAgeInDays=90
        ///   Headers: Key: {API_KEY}, Accept: application/json
        ///
        /// Response (JSON):
        ///   { "data": { "abuseConfidenceScore": 87, ... } }
        /// </summary>
        private static async Task<int> QueryAbuseIPDBLive(string ip)
        {
            try
            {
                // Build the request with required headers
                var request = new HttpRequestMessage(HttpMethod.Get,
                    $"{ABUSEIPDB_ENDPOINT}?ipAddress={Uri.EscapeDataString(ip)}&maxAgeInDays=90");

                request.Headers.Add("Key", ABUSEIPDB_API_KEY);
                request.Headers.Add("Accept", "application/json");

                // Execute the HTTP call
                HttpResponseMessage response = await _httpClient.SendAsync(request);

                if (!response.IsSuccessStatusCode)
                {
                    // On API failure, fall back to mock so the app remains functional
                    return await QueryMockDatabase(ip);
                }

                // Parse the AbuseIPDB JSON response
                string json = await response.Content.ReadAsStringAsync();
                using var doc = JsonDocument.Parse(json);

                int score = doc.RootElement
                    .GetProperty("data")
                    .GetProperty("abuseConfidenceScore")
                    .GetInt32();

                return Math.Clamp(score, 0, 100);
            }
            catch (Exception)
            {
                // Network timeout, DNS failure, etc. — degrade gracefully
                return await QueryMockDatabase(ip);
            }
        }
    }
}
