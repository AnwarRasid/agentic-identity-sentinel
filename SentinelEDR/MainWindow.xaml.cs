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
        /// Gemini 2.0 Flash endpoint.  The :generateContent suffix and key
        /// are appended at call time.
        /// </summary>
        private const string GEMINI_ENDPOINT =
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash";

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

        // ==================================================================
        //  CONSTRUCTOR
        // ==================================================================

        public MainWindow()
        {
            InitializeComponent();
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

                // Execute the local mock tool
                string toolResult = toolCall.Value.Tool switch
                {
                    "check_ip" => CheckIpReputation(toolCall.Value.Arg),
                    _          => JsonSerializer.Serialize(new { error = $"Unknown tool: {toolCall.Value.Tool}" })
                };

                AddLogEntry("AI-AGENT", $"TOOL RESULT: {toolResult}", false);

                // ── Turn 2: Send tool result back for final verdict ─────
                string turn2Prompt =
                    $"You previously requested the check_ip tool for the log entry below.\n" +
                    $"Here is the tool result:\n{toolResult}\n\n" +
                    $"Original log entry:\n{Truncate(logEntry, 2000)}\n\n" +
                    $"Now provide your final VERDICT: CRITICAL or SAFE with explanation.";

                string turn2Response = await CallGeminiAsync(AgentSystemPrompt, turn2Prompt);

                AddLogEntry("AI-AGENT", $"DECIDE: {Truncate(turn2Response, 300)}", false);

                bool isCritical = turn2Response.Contains("CRITICAL", StringComparison.OrdinalIgnoreCase);
                AddLogEntry(isCritical ? "CRITICAL" : "SAFE",
                    isCritical
                        ? "Agentic AI has flagged this event as a CRITICAL threat."
                        : "Agentic AI has determined this event is SAFE.",
                    isCritical);
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
        /// </summary>
        private static string CheckIpReputation(string ip)
        {
            // Mock threat-intel database
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
                ["192.168.1.100"] = new
                {
                    ip = "192.168.1.100",
                    reputation = "clean",
                    country = "INTERNAL",
                    threat_type = "none",
                    confidence = 100,
                    last_seen = "N/A"
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
        /// Generates a realistic-looking (but fake) Windows Security Event
        /// 4625 XML payload and runs it through the agentic AI pipeline.
        /// This lets you test the full agent loop without needing to actually
        /// trigger a failed logon on the machine.
        /// </summary>
        private async Task SimulateAttackAsync()
        {
            AddLogEntry("SIMULATE", "Injecting simulated failed-logon event (Event 4625)...", false);

            // Realistic Event 4625 XML — this mirrors the actual schema that
            // Windows writes to the Security log on a failed logon attempt.
            string fakeEventXml = $$"""
                <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
                  <System>
                    <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/>
                    <EventID>4625</EventID>
                    <Version>0</Version>
                    <Level>0</Level>
                    <Task>12544</Task>
                    <Opcode>0</Opcode>
                    <Keywords>0x8010000000000000</Keywords>
                    <TimeCreated SystemTime='{{DateTime.UtcNow:yyyy-MM-ddTHH:mm:ss.fffffffZ}}'/>
                    <EventRecordID>884231</EventRecordID>
                    <Correlation ActivityID='{00000000-0000-0000-0000-000000000000}'/>
                    <Execution ProcessID='612' ThreadID='1832'/>
                    <Channel>Security</Channel>
                    <Computer>WORKSTATION-07.corp.local</Computer>
                    <Security/>
                  </System>
                  <EventData>
                    <Data Name='SubjectUserSid'>S-1-0-0</Data>
                    <Data Name='SubjectUserName'>-</Data>
                    <Data Name='SubjectDomainName'>-</Data>
                    <Data Name='SubjectLogonId'>0x0</Data>
                    <Data Name='TargetUserSid'>S-1-0-0</Data>
                    <Data Name='TargetUserName'>admin</Data>
                    <Data Name='TargetDomainName'>CORP</Data>
                    <Data Name='Status'>0xC000006D</Data>
                    <Data Name='FailureReason'>%%2313</Data>
                    <Data Name='SubStatus'>0xC0000064</Data>
                    <Data Name='LogonType'>10</Data>
                    <Data Name='LogonProcessName'>User32</Data>
                    <Data Name='AuthenticationPackageName'>Negotiate</Data>
                    <Data Name='WorkstationName'>ATTACKER-PC</Data>
                    <Data Name='TransmittedServices'>-</Data>
                    <Data Name='LmPackageName'>-</Data>
                    <Data Name='KeyLength'>0</Data>
                    <Data Name='ProcessId'>0x0</Data>
                    <Data Name='ProcessName'>-</Data>
                    <Data Name='IpAddress'>203.0.113.50</Data>
                    <Data Name='IpPort'>49823</Data>
                  </EventData>
                </Event>
                """;

            AddLogEntry("SIMULATE",
                "Fake event injected: Failed RDP logon for CORP\\admin from 203.0.113.50 (known malicious IP)", false);

            // Run the full agentic pipeline on the simulated event
            await AnalyzeLogWithAI(fakeEventXml);
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
        //  CLEANUP — release the kernel subscription handle on exit
        // ==================================================================

        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            StopMonitoring();
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
