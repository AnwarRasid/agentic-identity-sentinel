// ==========================================================================
//  Sentinel EDR — MainWindow.xaml.cs
//  Real-time Windows Security Event monitoring + Agentic AI threat analysis
//  Target: .NET 8.0  |  WPF  |  Google Gemini API
// ==========================================================================
//
//  ARCHITECTURE OVERVIEW
//  ─────────────────────
//  1. EventLogWatcher   → Subscribes to Windows Security log (Event 4625)
//  2. Agentic AI Engine → Sends log to Gemini, parses tool-call requests,
//                          executes mock tools, returns final verdict
//  3. WPF Dispatcher    → Marshals all UI updates to the main thread
//
//  INTERVIEW NOTES on EventLogWatcher
//  ───────────────────────────────────
//  • EventLogWatcher uses the Windows Event Log API under the hood via
//    a push-based subscription (not polling).  The OS kernel fires a
//    callback whenever a new event matching your query arrives.
//  • The query uses XPath on the structured XML that every Windows event
//    contains.  "*[System[EventID=4625]]" selects only failed logons.
//  • EventRecordWritten fires on a ThreadPool thread, so you MUST use
//    Dispatcher.Invoke / InvokeAsync to touch WPF controls.
//  • Always call watcher.Enabled = false and Dispose() on shutdown,
//    otherwise the subscription leaks a kernel handle.
// ==========================================================================

using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;

namespace SentinelEDR
{
    public partial class MainWindow : Window
    {
        // ==================================================================
        //  CONSTANTS & CONFIGURATION
        // ==================================================================

        /// <summary>
        /// Replace with your actual Google Gemini API key.
        /// In production, load from environment variable or a secrets manager.
        /// </summary>
        private const string API_KEY = "YOUR_KEY_HERE";

        /// <summary>
        /// Gemini Flash (latest) endpoint.  The :generateContent suffix and
        /// key are appended at call time.
        /// </summary>
        private const string GEMINI_ENDPOINT =
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest";

        /// <summary>
        /// XPath query that selects only Event ID 4625 (Failed Logon) from
        /// the Security log.  This is passed to EventLogWatcher so the OS
        /// only notifies us about events we care about — zero polling needed.
        /// </summary>
        private const string SECURITY_EVENT_QUERY =
            "*[System[EventID=4625]]";

        // ==================================================================
        //  FIELDS
        // ==================================================================

        /// <summary>
        /// Kernel-level subscription handle for real-time Security events.
        /// Nullable because we create/destroy it on Start/Stop.
        /// </summary>
        private EventLogWatcher? _eventLogWatcher;

        /// <summary>
        /// Single shared HttpClient for all Gemini API calls.
        /// Best practice: one instance per application lifetime to reuse
        /// TCP connections and avoid socket exhaustion.
        /// </summary>
        private readonly HttpClient _httpClient = new()
        {
            Timeout = TimeSpan.FromSeconds(30)
        };

        /// <summary>Counter for the event feed badge.</summary>
        private int _eventCount;

        /// <summary>Tracks whether a CRITICAL alert has been raised.</summary>
        private bool _isCompromised;

        /// <summary>Whether Active Defense auto-eradicate mode is enabled.</summary>
        private bool _autoEradicateEnabled;

        /// <summary>Last IP address flagged by the AI agent (for manual blocking).</summary>
        private string? _lastDetectedIp;

        /// <summary>Running count of IPs blocked by the Response Engine.</summary>
        private int _blockedIpCount;

        // ==================================================================
        //  MODULE 2 — NETWORK MAP (God's Eye View)
        // ==================================================================

        /// <summary>
        /// Reference to the floating Network Map window.  Nullable because
        /// the user may not have opened it yet.
        /// </summary>
        private NetworkMapWindow? _networkMapWindow;

        // ==================================================================
        //  MODULE 3 — WAR ROOM (Gamification Engine)
        // ==================================================================

        /// <summary>Whether gamified mode is currently active.</summary>
        private bool _gamifiedModeEnabled;

        /// <summary>Current player score.  Can go negative.</summary>
        private int _score;

        /// <summary>
        /// Timestamp (UTC) when the current threat was first detected.
        /// Used to calculate if the user responded within 10 seconds.
        /// </summary>
        private DateTime? _threatDetectedAt;

        /// <summary>
        /// The IP that the gamification timer is counting down for.
        /// Null when no active threat is pending user action.
        /// </summary>
        private string? _pendingThreatIp;

        /// <summary>
        /// Whether the pending threat IP is actually malicious (for
        /// scoring the user's block action correctly).
        /// </summary>
        private bool _pendingThreatIsMalicious;

        /// <summary>
        /// 10-second countdown timer that ticks every second.
        /// Uses DispatcherTimer so callbacks run on the UI thread.
        /// </summary>
        private DispatcherTimer? _gamificationTimer;

        /// <summary>Seconds remaining on the current threat countdown.</summary>
        private int _countdownSeconds;

        // ==================================================================
        //  CONSTRUCTOR
        // ==================================================================

        public MainWindow()
        {
            InitializeComponent();

            // Initialise the gamification countdown timer (Module 3)
            _gamificationTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(1)
            };
            _gamificationTimer.Tick += GamificationTimer_Tick;

            AddLogEntry("SYSTEM", "Sentinel EDR initialised. Ready to monitor.", false);
            AddLogEntry("INFO", "Press 'Start Monitoring' to subscribe to Security Event 4625 (Failed Logon).", false);
            AddLogEntry("INFO", "Press 'Simulate Attack' to inject a fake failed-logon event for AI analysis.", false);
        }

        // ==================================================================
        //  UI HELPERS — all UI writes go through these so Dispatcher
        //  marshalling is handled in ONE place.
        // ==================================================================

        /// <summary>
        /// Append a timestamped, tagged entry to the live event feed.
        /// Safe to call from any thread.
        /// </summary>
        private void AddLogEntry(string tag, string message, bool isCritical)
        {
            // Dispatcher.InvokeAsync ensures we are on the UI thread.
            // This is critical because EventLogWatcher fires callbacks on
            // a ThreadPool thread — touching WPF controls from there would
            // throw an InvalidOperationException.
            Dispatcher.InvokeAsync(() =>
            {
                string timestamp = DateTime.Now.ToString("HH:mm:ss.fff", CultureInfo.InvariantCulture);
                string line = $"[{timestamp}]  [{tag}]  {message}";

                EventFeedList.Items.Add(line);
                _eventCount++;
                EventCountText.Text = $"{_eventCount} event{(_eventCount == 1 ? "" : "s")}";

                // Auto-scroll to the newest entry
                EventFeedList.ScrollIntoView(EventFeedList.Items[^1]);

                // Flash the status bar red on critical alerts
                if (isCritical && !_isCompromised)
                {
                    SetCompromisedStatus();
                }
            });
        }

        /// <summary>Flip the top-bar indicator to COMPROMISED (red).</summary>
        private void SetCompromisedStatus()
        {
            _isCompromised = true;
            StatusDot.Fill              = (SolidColorBrush)FindResource("NeonRed");
            StatusText.Text             = "THREAT DETECTED";
            StatusText.Foreground       = (SolidColorBrush)FindResource("NeonRed");
            StatusBorder.BorderBrush    = (SolidColorBrush)FindResource("NeonRed");
            StatusBorder.Background     = new SolidColorBrush(Color.FromArgb(0xFF, 0x2A, 0x0A, 0x0A));
        }

        /// <summary>Reset the top-bar indicator to SECURE (green).</summary>
        private void SetSecureStatus()
        {
            _isCompromised = false;
            StatusDot.Fill              = (SolidColorBrush)FindResource("NeonGreen");
            StatusText.Text             = "SYSTEM SECURE";
            StatusText.Foreground       = (SolidColorBrush)FindResource("NeonGreen");
            StatusBorder.BorderBrush    = (SolidColorBrush)FindResource("NeonGreen");
            StatusBorder.Background     = new SolidColorBrush(Color.FromArgb(0xFF, 0x0A, 0x2A, 0x0A));
        }

        // ==================================================================
        //  EVENT LOG WATCHER — Real-time Windows Security log subscription
        // ==================================================================
        //
        //  HOW IT WORKS (interview-prep notes):
        //
        //  1. We create an EventLogQuery targeting the "Security" channel
        //     with an XPath filter for EventID 4625 only.
        //
        //  2. EventLogWatcher wraps the native EvtSubscribe() Win32 API.
        //     When the Security log writes a new 4625 event, the OS kernel
        //     fires our EventRecordWritten callback — no timer, no poll.
        //
        //  3. The callback receives an EventRecordWrittenEventArgs that
        //     contains the full EventRecord.  We extract the XML payload,
        //     which includes the target account, source IP, logon type, etc.
        //
        //  4. We forward the raw XML to the Agentic AI engine for analysis.
        //
        //  5. On shutdown, we set Enabled = false and Dispose() the watcher
        //     to release the kernel subscription handle.
        //
        // ==================================================================

        /// <summary>
        /// Start listening for Security Event 4625 in real time.
        /// </summary>
        private void StartMonitoring()
        {
            try
            {
                // Build the query: "Security" log, XPath for 4625 only
                var query = new EventLogQuery("Security", PathType.LogName, SECURITY_EVENT_QUERY);

                // Create the watcher — this allocates a kernel subscription
                _eventLogWatcher = new EventLogWatcher(query);

                // Wire up the push-based callback
                _eventLogWatcher.EventRecordWritten += OnSecurityEventReceived;

                // Flip the switch — the OS starts delivering events NOW
                _eventLogWatcher.Enabled = true;

                AddLogEntry("MONITOR", "EventLogWatcher subscribed to Security:4625 (push model, zero polling).", false);
            }
            catch (EventLogNotFoundException)
            {
                AddLogEntry("ERROR",
                    "Security log not found. Run as Administrator or use 'Simulate Attack' for testing.", false);
            }
            catch (UnauthorizedAccessException)
            {
                AddLogEntry("ERROR",
                    "Access denied to Security log. Run as Administrator or use 'Simulate Attack' for testing.", false);
            }
            catch (Exception ex)
            {
                AddLogEntry("ERROR", $"Failed to start monitoring: {ex.Message}", false);
            }
        }

        /// <summary>
        /// Kernel callback — fires on a ThreadPool thread every time a new
        /// Event 4625 is written to the Security log.
        /// </summary>
        private async void OnSecurityEventReceived(object? sender, EventRecordWrittenEventArgs e)
        {
            if (e.EventRecord == null) return;

            try
            {
                // Extract the full XML payload from the event record
                string xml = e.EventRecord.ToXml();

                AddLogEntry("EVENT", $"Security Event 4625 captured (Record #{e.EventRecord.RecordId})", false);

                // Forward to the Agentic AI engine for multi-step analysis
                await AnalyzeLogWithAI(xml);
            }
            catch (Exception ex)
            {
                AddLogEntry("ERROR", $"Error processing event: {ex.Message}", false);
            }
        }

        /// <summary>Stop the watcher and release the kernel handle.</summary>
        private void StopMonitoring()
        {
            if (_eventLogWatcher != null)
            {
                _eventLogWatcher.Enabled = false;
                _eventLogWatcher.EventRecordWritten -= OnSecurityEventReceived;
                _eventLogWatcher.Dispose();
                _eventLogWatcher = null;
                AddLogEntry("MONITOR", "EventLogWatcher stopped and disposed.", false);
            }
        }

        // ==================================================================
        //  AGENTIC AI ENGINE — Multi-turn Gemini interaction with tool use
        // ==================================================================
        //
        //  THE AGENT LOOP (Observe → Think → Act → Decide):
        //
        //  Step 1 — OBSERVE:  We send the raw log entry to Gemini along
        //           with a system prompt that describes an available tool.
        //
        //  Step 2 — THINK:    Gemini reads the log and reasons about it.
        //           If it spots an IP address, it outputs a JSON tool call:
        //           {"tool": "check_ip", "arg": "<IP>"}
        //
        //  Step 3 — ACT:      We parse that JSON, call our local C# mock
        //           function CheckIpReputation(ip), and collect the result.
        //
        //  Step 4 — DECIDE:   We send the tool result back to Gemini in a
        //           second API call.  Gemini now has full context and emits
        //           a final verdict: "CRITICAL" or "SAFE".
        //
        //  This two-turn loop is the simplest possible agentic pattern —
        //  the same pattern LangChain, CrewAI, and AutoGen all build upon.
        //
        // ==================================================================

        /// <summary>
        /// The system prompt that turns Gemini into our security analyst agent.
        /// It describes the available tool so the model knows it can request it.
        /// </summary>
        private static readonly string AgentSystemPrompt = """
            You are a Senior SOC Analyst AI agent embedded in an EDR system.
            Your job is to analyze Windows Security Event logs and determine
            if they represent a real threat.

            === AVAILABLE TOOL ===
            Tool name : check_ip
            Description: Checks the reputation of an IP address against a
                         threat intelligence database.  Returns a JSON object
                         with fields: ip, reputation ("malicious" / "clean"),
                         country, and threat_type.

            === INSTRUCTIONS ===
            1. Read the log entry carefully.
            2. If you see an IP address in the log, you MUST call the tool
               by outputting ONLY the following JSON on a single line:
               {"tool": "check_ip", "arg": "THE_IP_ADDRESS"}
            3. Do NOT add any other text when requesting a tool.
            4. If there is no IP address, analyze the log directly and give
               your verdict.

            When giving a final verdict (after receiving tool results or when
            no tool is needed), respond with EXACTLY one of these two lines
            followed by a brief explanation:
               VERDICT: CRITICAL - <explanation>
               VERDICT: SAFE - <explanation>
            """;

        /// <summary>
        /// Main agentic analysis pipeline.  Sends the log to Gemini,
        /// handles tool-call round-trips, and emits the final verdict.
        /// </summary>
        private async Task AnalyzeLogWithAI(string logEntry)
        {
            AddLogEntry("AI-AGENT", "OBSERVE: New log received. Sending to Gemini for analysis...", false);

            // ── Turn 1: Send log + system prompt ────────────────────────
            string turn1Response = await CallGeminiAsync(AgentSystemPrompt, logEntry);

            if (string.IsNullOrWhiteSpace(turn1Response))
            {
                AddLogEntry("AI-AGENT", "Gemini returned an empty response. Skipping.", false);
                return;
            }

            AddLogEntry("AI-AGENT", $"THINK: Gemini says → {Truncate(turn1Response, 200)}", false);

            // ── Check if Gemini requested a tool call ───────────────────
            var toolCall = ParseToolCall(turn1Response);

            if (toolCall != null)
            {
                AddLogEntry("AI-AGENT",
                    $"ACT: Gemini requested tool '{toolCall.Value.Tool}' with arg '{toolCall.Value.Arg}'", false);

                // Capture IP address for Active Defense countermeasures
                string? detectedIp = toolCall.Value.Tool == "check_ip" ? toolCall.Value.Arg : null;

                // Execute the local mock tool
                string toolResult = toolCall.Value.Tool switch
                {
                    "check_ip" => CheckIpReputation(toolCall.Value.Arg),
                    _          => JsonSerializer.Serialize(new { error = $"Unknown tool: {toolCall.Value.Tool}" })
                };

                AddLogEntry("AI-AGENT", $"TOOL RESULT: {toolResult}", false);

                // ── MODULE 1: Query Threat Intel for Abuse Confidence ────
                // This runs in parallel with the Gemini Turn 2 call for
                // efficiency — we await it after the verdict arrives.
                int threatIntelScore = 0;
                Task<int>? threatIntelTask = null;
                if (detectedIp != null)
                {
                    threatIntelTask = ThreatIntelService.GetAbuseConfidenceScore(detectedIp);
                }

                // ── Turn 2: Send tool result back for final verdict ─────
                string turn2Prompt =
                    $"You previously requested the check_ip tool for the log entry below.\n" +
                    $"Here is the tool result:\n{toolResult}\n\n" +
                    $"Original log entry:\n{Truncate(logEntry, 2000)}\n\n" +
                    $"Now provide your final VERDICT: CRITICAL or SAFE with explanation.";

                string turn2Response = await CallGeminiAsync(AgentSystemPrompt, turn2Prompt);

                // Await the Threat Intel result (Module 1)
                if (threatIntelTask != null)
                {
                    threatIntelScore = await threatIntelTask;
                    AddLogEntry("THREAT-INTEL",
                        $"AbuseIPDB Confidence Score for {detectedIp}: {threatIntelScore}/100" +
                        (threatIntelScore >= 76 ? " — HIGH RISK" :
                         threatIntelScore >= 26 ? " — SUSPICIOUS" : " — LOW RISK"), false);
                }

                AddLogEntry("AI-AGENT", $"DECIDE: {Truncate(turn2Response, 300)}", false);

                bool isCritical = turn2Response.Contains("CRITICAL", StringComparison.OrdinalIgnoreCase);
                bool isMaliciousPerThreatIntel = threatIntelScore >= 76;

                AddLogEntry(isCritical ? "CRITICAL" : "SAFE",
                    isCritical
                        ? "Agentic AI has flagged this event as a CRITICAL threat."
                        : "Agentic AI has determined this event is SAFE.",
                    isCritical);

                // ── MODULE 2: Update Network Map (God's Eye View) ────────
                if (detectedIp != null)
                {
                    Dispatcher.InvokeAsync(() =>
                    {
                        _networkMapWindow?.AddNode(detectedIp, isMaliciousPerThreatIntel);
                    });
                }

                // ── Active Defense: auto-eradicate if CRITICAL + toggle ON ──
                if (isCritical && detectedIp != null)
                {
                    _lastDetectedIp = detectedIp;
                    Dispatcher.InvokeAsync(() =>
                    {
                        TxtLastDetectedIp.Text = $"Flagged: {detectedIp}";
                        BtnBlockIp.IsEnabled = true;
                    });

                    // ── MODULE 3: Start gamification countdown timer ─────
                    if (_gamifiedModeEnabled)
                    {
                        StartGamificationCountdown(detectedIp, isMaliciousPerThreatIntel);
                    }

                    if (_autoEradicateEnabled)
                    {
                        AddLogEntry("ERADICATE",
                            $"Auto-Eradicate engaged — blocking IP {detectedIp} in Windows Firewall...", false);

                        var result = ResponseEngine.BlockIpInFirewall(detectedIp);

                        AddLogEntry(result.Success ? "ERADICATE" : "ERROR",
                            result.Success
                                ? $"THREAT NEUTRALIZED: IP {detectedIp} blocked. {result.Message}"
                                : $"Firewall block failed: {result.Message}",
                            false);

                        if (result.Success)
                        {
                            _blockedIpCount++;
                            Dispatcher.InvokeAsync(() =>
                                TxtBlockedCount.Text = $"{_blockedIpCount} IP{(_blockedIpCount == 1 ? "" : "s")} blocked");
                        }
                    }
                }
            }
            else
            {
                // No tool call — Gemini gave a direct verdict
                AddLogEntry("AI-AGENT", $"DECIDE (direct): {Truncate(turn1Response, 300)}", false);

                bool isCritical = turn1Response.Contains("CRITICAL", StringComparison.OrdinalIgnoreCase);
                AddLogEntry(isCritical ? "CRITICAL" : "SAFE",
                    isCritical
                        ? "Agentic AI has flagged this event as a CRITICAL threat."
                        : "Agentic AI has determined this event is SAFE.",
                    isCritical);
            }
        }

        // ==================================================================
        //  GEMINI API CALLER
        // ==================================================================

        /// <summary>
        /// Send a single prompt to Google Gemini and return the text response.
        /// Uses the generateContent REST endpoint with a system instruction.
        /// </summary>
        private async Task<string> CallGeminiAsync(string systemPrompt, string userMessage)
        {
            string url = $"{GEMINI_ENDPOINT}:generateContent?key={API_KEY}";

            // Build the request body per the Gemini REST API spec.
            // system_instruction sets the agent persona; contents holds the
            // user turn with the log data.
            var requestBody = new
            {
                system_instruction = new
                {
                    parts = new[] { new { text = systemPrompt } }
                },
                contents = new[]
                {
                    new
                    {
                        role = "user",
                        parts = new[] { new { text = userMessage } }
                    }
                },
                generationConfig = new
                {
                    temperature = 0.2,   // low temperature → deterministic security analysis
                    maxOutputTokens = 1024
                }
            };

            string json = JsonSerializer.Serialize(requestBody);
            using var content = new StringContent(json, Encoding.UTF8, "application/json");

            try
            {
                HttpResponseMessage response = await _httpClient.PostAsync(url, content);

                if (!response.IsSuccessStatusCode)
                {
                    string errorBody = await response.Content.ReadAsStringAsync();
                    AddLogEntry("API-ERROR", $"Gemini returned {response.StatusCode}: {Truncate(errorBody, 200)}", false);
                    return string.Empty;
                }

                string responseJson = await response.Content.ReadAsStringAsync();
                return ExtractGeminiText(responseJson);
            }
            catch (TaskCanceledException)
            {
                AddLogEntry("API-ERROR", "Gemini request timed out.", false);
                return string.Empty;
            }
            catch (HttpRequestException ex)
            {
                AddLogEntry("API-ERROR", $"Network error calling Gemini: {ex.Message}", false);
                return string.Empty;
            }
        }

        /// <summary>
        /// Parse the Gemini REST response JSON and extract the text from the
        /// first candidate's first part.
        /// </summary>
        private static string ExtractGeminiText(string responseJson)
        {
            try
            {
                using var doc = JsonDocument.Parse(responseJson);
                return doc.RootElement
                    .GetProperty("candidates")[0]
                    .GetProperty("content")
                    .GetProperty("parts")[0]
                    .GetProperty("text")
                    .GetString() ?? string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }

        // ==================================================================
        //  TOOL CALL PARSER
        // ==================================================================

        /// <summary>
        /// Attempt to extract a tool-call JSON object from the AI's response.
        /// Looks for: {"tool": "check_ip", "arg": "1.2.3.4"}
        /// Returns null if no valid tool call is found.
        /// </summary>
        private static (string Tool, string Arg)? ParseToolCall(string aiResponse)
        {
            // Use regex to find a JSON object containing "tool" and "arg"
            // even if the AI added surrounding commentary.
            var match = Regex.Match(
                aiResponse,
                @"\{\s*""tool""\s*:\s*""(?<tool>[^""]+)""\s*,\s*""arg""\s*:\s*""(?<arg>[^""]+)""\s*\}",
                RegexOptions.IgnoreCase);

            if (match.Success)
            {
                return (match.Groups["tool"].Value, match.Groups["arg"].Value);
            }

            // Also try the reversed key order: {"arg": "...", "tool": "..."}
            match = Regex.Match(
                aiResponse,
                @"\{\s*""arg""\s*:\s*""(?<arg>[^""]+)""\s*,\s*""tool""\s*:\s*""(?<tool>[^""]+)""\s*\}",
                RegexOptions.IgnoreCase);

            return match.Success ? (match.Groups["tool"].Value, match.Groups["arg"].Value) : null;
        }

        // ==================================================================
        //  MOCK TOOL: IP REPUTATION CHECK
        // ==================================================================

        /// <summary>
        /// Simulates querying a Threat Intelligence API (e.g., VirusTotal,
        /// AbuseIPDB, AlienVault OTX) for the reputation of an IP address.
        ///
        /// In production, this would be a real HTTP call to a TI provider.
        /// Here we return deterministic mock data for demonstration.
        ///
        /// The database covers all IPs used by the Red Team Engine scenarios
        /// plus automatic RFC-1918 private IP range detection.
        /// </summary>
        private static string CheckIpReputation(string ip)
        {
            // ── RFC-1918 / private range detection ──────────────────────
            // Any private IP is automatically clean — the AI should learn
            // to treat internal traffic differently from external.
            if (ip.StartsWith("192.168.") || ip.StartsWith("10.") ||
                ip.StartsWith("172.16.") || ip.StartsWith("172.17.") ||
                ip.StartsWith("172.18.") || ip.StartsWith("172.19.") ||
                ip.StartsWith("172.2") || ip.StartsWith("172.30.") ||
                ip.StartsWith("172.31.") || ip == "127.0.0.1")
            {
                return JsonSerializer.Serialize(new
                {
                    ip,
                    reputation = "clean",
                    country = "INTERNAL",
                    threat_type = "none",
                    confidence = 100,
                    last_seen = "N/A",
                    note = "RFC-1918 private address — internal network traffic"
                });
            }

            // ── Mock threat-intel database ──────────────────────────────
            var threatIntelDb = new Dictionary<string, object>
            {
                ["203.0.113.50"] = new
                {
                    ip = "203.0.113.50",
                    reputation = "malicious",
                    country = "CN",
                    threat_type = "brute_force_ssh",
                    confidence = 92,
                    last_seen = "2026-02-12"
                },
                ["198.51.100.23"] = new
                {
                    ip = "198.51.100.23",
                    reputation = "malicious",
                    country = "RU",
                    threat_type = "credential_stuffing",
                    confidence = 88,
                    last_seen = "2026-02-11"
                },
                ["45.155.205.99"] = new
                {
                    ip = "45.155.205.99",
                    reputation = "malicious",
                    country = "KP",
                    threat_type = "apt_c2_beacon",
                    confidence = 95,
                    last_seen = "2026-02-13"
                },
                ["185.220.101.34"] = new
                {
                    ip = "185.220.101.34",
                    reputation = "malicious",
                    country = "RU",
                    threat_type = "tor_exit_relay",
                    confidence = 90,
                    last_seen = "2026-02-14"
                },
                ["91.240.118.172"] = new
                {
                    ip = "91.240.118.172",
                    reputation = "malicious",
                    country = "IR",
                    threat_type = "scanning_recon",
                    confidence = 85,
                    last_seen = "2026-02-10"
                },
                ["23.129.64.210"] = new
                {
                    ip = "23.129.64.210",
                    reputation = "malicious",
                    country = "US",
                    threat_type = "tor_exit_node",
                    confidence = 82,
                    last_seen = "2026-02-13"
                }
            };

            if (threatIntelDb.TryGetValue(ip, out var entry))
            {
                return JsonSerializer.Serialize(entry);
            }

            // Unknown IPs are flagged as suspicious
            return JsonSerializer.Serialize(new
            {
                ip,
                reputation = "suspicious",
                country = "UNKNOWN",
                threat_type = "not_in_database",
                confidence = 50,
                last_seen = "N/A"
            });
        }

        // ==================================================================
        //  ATTACK SIMULATOR — injects a fake Event 4625 for testing
        // ==================================================================

        /// <summary>
        /// Uses the Polymorphic Red Team Engine to generate a random attack
        /// scenario and runs it through the full agentic AI pipeline.
        /// Each click may produce a brute force, impossible travel,
        /// PowerShell attack, or a false-positive event — the AI must
        /// reason about each one independently.
        /// </summary>
        private async Task SimulateAttackAsync()
        {
            AddLogEntry("SIMULATE", "Red Team Engine spinning up — selecting random scenario...", false);

            var scenario = RedTeamSimulator.GenerateAttackScenario();

            AddLogEntry("SIMULATE", $"Scenario selected: [{scenario.Name}]", false);
            AddLogEntry("SIMULATE", scenario.Description, false);

            // Run the full agentic pipeline on the generated payload
            await AnalyzeLogWithAI(scenario.LogPayload);
        }

        // ==================================================================
        //  BUTTON CLICK HANDLERS
        // ==================================================================

        private void BtnStartMonitoring_Click(object sender, RoutedEventArgs e)
        {
            StartMonitoring();
            BtnStartMonitoring.IsEnabled = false;
            BtnStopMonitoring.IsEnabled  = true;
        }

        private void BtnStopMonitoring_Click(object sender, RoutedEventArgs e)
        {
            StopMonitoring();
            BtnStartMonitoring.IsEnabled = true;
            BtnStopMonitoring.IsEnabled  = false;
        }

        private async void BtnSimulateAttack_Click(object sender, RoutedEventArgs e)
        {
            BtnSimulateAttack.IsEnabled = false;
            await SimulateAttackAsync();
            BtnSimulateAttack.IsEnabled = true;
        }

        private void BtnClearFeed_Click(object sender, RoutedEventArgs e)
        {
            EventFeedList.Items.Clear();
            _eventCount = 0;
            EventCountText.Text = "0 events";
            SetSecureStatus();
        }

        // ==================================================================
        //  COUNTERMEASURE HANDLERS — Active Defense sidebar controls
        // ==================================================================

        /// <summary>Toggle the Auto-Eradicate mode on/off.</summary>
        private void ChkAutoEradicate_Changed(object sender, RoutedEventArgs e)
        {
            _autoEradicateEnabled = ChkAutoEradicate.IsChecked == true;
            AddLogEntry("CONFIG",
                _autoEradicateEnabled
                    ? "Active Defense: Auto-Eradicate mode ENABLED. CRITICAL threats will be blocked automatically."
                    : "Active Defense: Auto-Eradicate mode DISABLED.",
                false);
        }

        /// <summary>
        /// Manually block the last flagged IP via the Response Engine.
        /// Integrates with the War Room scoring system (Module 3):
        ///   +1000 points — blocking a malicious IP within 10 seconds
        ///   -500 points  — blocking a safe IP (false positive penalty)
        /// </summary>
        private void BtnBlockIp_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(_lastDetectedIp))
            {
                AddLogEntry("WARN", "No IP address available to block.", false);
                return;
            }

            // ── MODULE 3: Score the player's block action ────────────
            if (_gamifiedModeEnabled)
            {
                ScoreBlockAction(_lastDetectedIp);
            }

            AddLogEntry("ERADICATE",
                $"Manual block initiated for IP {_lastDetectedIp}...", false);

            var result = ResponseEngine.BlockIpInFirewall(_lastDetectedIp);

            AddLogEntry(result.Success ? "ERADICATE" : "ERROR",
                result.Success
                    ? $"THREAT NEUTRALIZED: IP {_lastDetectedIp} blocked. {result.Message}"
                    : $"Firewall block failed: {result.Message}",
                false);

            if (result.Success)
            {
                _blockedIpCount++;
                TxtBlockedCount.Text = $"{_blockedIpCount} IP{(_blockedIpCount == 1 ? "" : "s")} blocked";
                BtnBlockIp.IsEnabled = false;
            }
        }

        // ==================================================================
        //  MODULE 2 — NETWORK MAP HANDLER
        // ==================================================================

        /// <summary>
        /// Opens (or brings to front) the floating Network Map window.
        /// Uses a singleton pattern — only one map window can exist.
        /// </summary>
        private void BtnNetworkMap_Click(object sender, RoutedEventArgs e)
        {
            if (_networkMapWindow == null || !_networkMapWindow.IsLoaded)
            {
                _networkMapWindow = new NetworkMapWindow
                {
                    Owner = this
                };
                _networkMapWindow.Closed += (_, _) => _networkMapWindow = null;
                _networkMapWindow.Show();
                AddLogEntry("MAP", "Network Map window opened — God's Eye View active.", false);
            }
            else
            {
                // Window already exists — bring it to front
                _networkMapWindow.Activate();
            }
        }

        // ==================================================================
        //  MODULE 3 — WAR ROOM (Gamification Engine)
        // ==================================================================
        //
        //  SCORING RULES
        //  ─────────────
        //  +1000 points : User manually blocks a MALICIOUS IP within 10s
        //  -500  points : User blocks a SAFE IP (false positive penalty)
        //  -200  points : 10-second countdown expires without user action
        //
        //  The timer uses System.Windows.Threading.DispatcherTimer so all
        //  Tick callbacks execute on the WPF UI thread — no Dispatcher
        //  marshalling needed inside the handler.
        //
        // ==================================================================

        /// <summary>Toggle gamified mode on/off from the sidebar checkbox.</summary>
        private void ChkGamifiedMode_Changed(object sender, RoutedEventArgs e)
        {
            _gamifiedModeEnabled = ChkGamifiedMode.IsChecked == true;

            if (_gamifiedModeEnabled)
            {
                _score = 0;
                TxtScore.Text = "0";
                TxtCountdown.Text = "--";
                AddLogEntry("WAR-ROOM",
                    "Gamified Mode ENABLED. Score reset to 0. Block threats fast for points!", false);
            }
            else
            {
                StopGamificationCountdown();
                AddLogEntry("WAR-ROOM",
                    $"Gamified Mode DISABLED. Final score: {_score}.", false);
            }
        }

        /// <summary>
        /// Starts a 10-second countdown for the user to respond to a
        /// detected threat.  Called from AnalyzeLogWithAI when a CRITICAL
        /// verdict is issued and gamified mode is active.
        /// </summary>
        private void StartGamificationCountdown(string ip, bool isMalicious)
        {
            Dispatcher.InvokeAsync(() =>
            {
                // If a countdown is already running, let it expire naturally
                // (don't reset for overlapping threats)
                if (_pendingThreatIp != null) return;

                _pendingThreatIp = ip;
                _pendingThreatIsMalicious = isMalicious;
                _threatDetectedAt = DateTime.UtcNow;
                _countdownSeconds = 10;

                TxtCountdown.Text = "10s";
                TxtCountdown.Foreground = (SolidColorBrush)FindResource("NeonGreen");

                AddLogEntry("WAR-ROOM",
                    $"THREAT DETECTED: {ip} — You have 10 seconds to respond! Block or ignore.", false);

                _gamificationTimer?.Start();
            });
        }

        /// <summary>
        /// Fires every second while the gamification countdown is active.
        /// Updates the UI countdown display and handles timer expiry.
        /// </summary>
        private void GamificationTimer_Tick(object? sender, EventArgs e)
        {
            _countdownSeconds--;

            if (_countdownSeconds <= 0)
            {
                // Time expired — the user didn't act in time
                _score -= 200;
                TxtScore.Text = _score.ToString();
                TxtCountdown.Text = "EXPIRED";
                TxtCountdown.Foreground = (SolidColorBrush)FindResource("NeonRed");

                AddLogEntry("WAR-ROOM",
                    $"-200 POINTS: Timer expired for {_pendingThreatIp}. Total score: {_score}", false);

                StopGamificationCountdown();
            }
            else
            {
                // Update the countdown display
                TxtCountdown.Text = $"{_countdownSeconds}s";

                // Colour transitions: green → amber → red
                if (_countdownSeconds <= 3)
                    TxtCountdown.Foreground = (SolidColorBrush)FindResource("NeonRed");
                else if (_countdownSeconds <= 6)
                    TxtCountdown.Foreground = (SolidColorBrush)FindResource("NeonAmber");
            }
        }

        /// <summary>
        /// Stops the gamification timer and clears the pending threat.
        /// </summary>
        private void StopGamificationCountdown()
        {
            _gamificationTimer?.Stop();
            _pendingThreatIp = null;
            _threatDetectedAt = null;
            _pendingThreatIsMalicious = false;

            Dispatcher.InvokeAsync(() => TxtCountdown.Text = "--");
        }

        /// <summary>
        /// Calculates and applies the score delta when the user clicks
        /// "Block Selected IP".  Called from BtnBlockIp_Click.
        ///
        /// Scoring logic:
        ///   • If the blocked IP matches the pending threat AND is truly
        ///     malicious AND the user acted within 10 seconds → +1000
        ///   • If the blocked IP is safe → -500 (false positive penalty)
        /// </summary>
        private void ScoreBlockAction(string blockedIp)
        {
            bool respondedToActiveThreat = _pendingThreatIp == blockedIp
                                           && _threatDetectedAt != null
                                           && (DateTime.UtcNow - _threatDetectedAt.Value).TotalSeconds <= 10;

            if (_pendingThreatIsMalicious && respondedToActiveThreat)
            {
                // Correct block of a malicious IP within time limit
                _score += 1000;
                AddLogEntry("WAR-ROOM",
                    $"+1000 POINTS: Malicious IP {blockedIp} blocked in time! Total score: {_score}", false);
            }
            else if (!_pendingThreatIsMalicious || !respondedToActiveThreat)
            {
                // Determine if this is a safe-IP block (penalty) or a late block
                // Check if the IP is actually in the known malicious list
                bool isTrulyMalicious = _pendingThreatIp == blockedIp && _pendingThreatIsMalicious;

                if (!isTrulyMalicious)
                {
                    _score -= 500;
                    AddLogEntry("WAR-ROOM",
                        $"-500 POINTS: Blocked a safe IP ({blockedIp})! False positive penalty. Total score: {_score}", false);
                }
                else
                {
                    // Late but correct — no bonus, but no penalty either
                    AddLogEntry("WAR-ROOM",
                        $"0 POINTS: Correct block but too slow. No bonus. Total score: {_score}", false);
                }
            }

            // Update the score display and stop the countdown
            Dispatcher.InvokeAsync(() => TxtScore.Text = _score.ToString());
            StopGamificationCountdown();
        }

        // ==================================================================
        //  CLEANUP — release the kernel subscription handle on exit
        // ==================================================================

        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            StopMonitoring();
            _gamificationTimer?.Stop();
            _networkMapWindow?.Close();
            _httpClient.Dispose();
        }

        // ==================================================================
        //  UTILITY
        // ==================================================================

        /// <summary>Truncate a string to a max length, appending "..." if cut.</summary>
        private static string Truncate(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value)) return string.Empty;
            value = value.ReplaceLineEndings(" ");
            return value.Length <= maxLength ? value : string.Concat(value.AsSpan(0, maxLength), "...");
        }
    }
}
