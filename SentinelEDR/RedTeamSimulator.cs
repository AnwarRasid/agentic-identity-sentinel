// ==========================================================================
//  Sentinel EDR — RedTeamSimulator.cs
//  Polymorphic Red Team Engine for AI Agent stress-testing
//  Target: .NET 8.0
// ==========================================================================
//
//  PURPOSE
//  ───────
//  Generates random, context-aware attack scenarios — including deliberate
//  false positives — so the Agentic AI engine must actually reason about
//  each event rather than blindly flagging everything as malicious.
//
//  SCENARIOS
//  ─────────
//  1. Brute Force        – High-volume Event 4625 from a hostile IP
//  2. Impossible Travel  – Same user, two countries, minutes apart
//  3. PowerShell Attack  – Event 4688 with encoded command-line payload
//  4. False Positive     – Single typo login from a local/safe IP
//
// ==========================================================================

using System;
using System.Text;

namespace SentinelEDR
{
    /// <summary>
    /// Polymorphic Red Team Engine — generates randomized attack scenarios
    /// that exercise every branch of the AI agent's decision logic.
    /// </summary>
    public static class RedTeamSimulator
    {
        private static readonly Random _rng = new();

        // ==================================================================
        //  DATA ARRAYS — attack surface vocabulary
        // ==================================================================

        /// <summary>High-value target accounts an attacker would aim for.</summary>
        private static readonly string[] TargetUsernames =
        {
            "admin", "administrator", "svc_backup", "system",
            "jsmith", "dba_prod", "sa", "root"
        };

        /// <summary>Active Directory domain names.</summary>
        private static readonly string[] Domains = { "CORP", "PROD", "HQ", "DMZ" };

        /// <summary>Workstation names that look suspicious in an audit log.</summary>
        private static readonly string[] HostileWorkstations =
        {
            "ATTACKER-PC", "KALI-BOX", "PENTEST-01",
            "UNKNOWN-PC", "C2-NODE", "BOTNET-42"
        };

        /// <summary>Normal corporate workstations (for false-positive scenarios).</summary>
        private static readonly string[] SafeWorkstations =
        {
            "WORKSTATION-07", "DESKTOP-HR03", "LAPTOP-DEV12",
            "PC-RECEPTION", "PC-FINANCE01"
        };

        /// <summary>
        /// Known-malicious public IPs.  These map to entries in the mock
        /// threat-intel database inside MainWindow.CheckIpReputation().
        /// </summary>
        private static readonly string[] MaliciousIps =
        {
            "203.0.113.50",    // CN — brute_force_ssh
            "198.51.100.23",   // RU — credential_stuffing
            "45.155.205.99",   // KP — apt_c2_beacon
            "185.220.101.34",  // RU — tor_exit_relay
            "91.240.118.172",  // IR — scanning_recon
            "23.129.64.210"    // US — tor_exit_node
        };

        /// <summary>
        /// Safe internal / RFC-1918 IPs that should NOT trigger a critical
        /// verdict — used to test the AI's false-positive discrimination.
        /// </summary>
        private static readonly string[] SafeLocalIps =
        {
            "192.168.1.55", "192.168.1.100", "10.0.0.15",
            "172.16.0.20", "192.168.10.42"
        };

        /// <summary>Countries associated with hostile threat actors.</summary>
        private static readonly (string Code, string Name)[] HostileCountries =
        {
            ("CN", "China"), ("RU", "Russia"),
            ("KP", "North Korea"), ("IR", "Iran")
        };

        /// <summary>Friendly/domestic countries for one leg of impossible-travel.</summary>
        private static readonly (string Code, string Name)[] FriendlyCountries =
        {
            ("US", "United States"), ("GB", "United Kingdom"),
            ("DE", "Germany"), ("CA", "Canada"), ("AU", "Australia")
        };

        /// <summary>
        /// Base64-encoded PowerShell command fragments.  These represent the
        /// kind of encoded payloads seen in real-world attacks (e.g., living
        /// off the land via -EncodedCommand).
        /// </summary>
        private static readonly string[] EncodedPayloads =
        {
            "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==",  // Invoke-WebRequest
            "RwBlAHQALQBDAHIAZQBkAGUAbgB0AGkAYQBsAA==",            // Get-Credential
            "QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQA=",        // Add-MpPreference
            "UwBlAHQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQA=",        // Set-MpPreference
            "TgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA"  // New-Object Net.WebClient
        };

        // ==================================================================
        //  SCENARIO RESULT
        // ==================================================================

        /// <summary>
        /// The output of a single generated attack scenario.
        /// Contains everything the caller needs to inject and describe the event.
        /// </summary>
        public record AttackScenario(
            /// <summary>Short human-readable label (e.g. "BRUTE FORCE").</summary>
            string Name,
            /// <summary>One-line description of what was simulated.</summary>
            string Description,
            /// <summary>The raw log payload (XML) to feed into the AI pipeline.</summary>
            string LogPayload
        );

        // ==================================================================
        //  PUBLIC API
        // ==================================================================

        /// <summary>
        /// Randomly selects one of four attack scenarios and generates a
        /// fully randomised log payload for it.  Each call may produce a
        /// different scenario with different parameters — "polymorphic."
        /// </summary>
        public static AttackScenario GenerateAttackScenario()
        {
            int scenario = _rng.Next(4);
            return scenario switch
            {
                0 => GenerateBruteForce(),
                1 => GenerateImpossibleTravel(),
                2 => GeneratePowerShellAttack(),
                3 => GenerateFalsePositive(),
                _ => GenerateFalsePositive()
            };
        }

        // ==================================================================
        //  SCENARIO 1 — BRUTE FORCE
        //  High volume of Event 4625 from a single malicious IP, targeting
        //  a privileged account.  Packaged as a SIEM correlation alert so
        //  the AI receives full context in a single payload.
        // ==================================================================

        private static AttackScenario GenerateBruteForce()
        {
            string ip        = Pick(MaliciousIps);
            string user      = Pick(TargetUsernames);
            string domain    = Pick(Domains);
            string wkst      = Pick(HostileWorkstations);
            var    country   = Pick(HostileCountries);
            int    attempts  = _rng.Next(5, 16);

            var sb = new StringBuilder();
            sb.AppendLine($"=== SIEM CORRELATION ALERT: {attempts} failed logon attempts in 60 seconds ===");
            sb.AppendLine($"Source IP: {ip} | Target: {domain}\\{user} | Origin: {country.Name} | Pattern: Brute Force");
            sb.AppendLine();

            for (int i = 0; i < attempts; i++)
            {
                var ts = DateTime.UtcNow.AddSeconds(-_rng.Next(1, 61));
                sb.AppendLine(BuildEvent4625Xml(user, domain, ip, wkst, ts, 884231 + i));
                sb.AppendLine();
            }

            return new AttackScenario(
                "BRUTE FORCE",
                $"{attempts}x failed RDP logons for {domain}\\{user} from {ip} ({country.Name})",
                sb.ToString()
            );
        }

        // ==================================================================
        //  SCENARIO 2 — IMPOSSIBLE TRAVEL
        //  Same user authenticated from two geographically distant countries
        //  within a few minutes — physically impossible without credential
        //  compromise.
        // ==================================================================

        private static AttackScenario GenerateImpossibleTravel()
        {
            string user       = Pick(TargetUsernames);
            string domain     = Pick(Domains);
            var    country1   = Pick(FriendlyCountries);
            var    country2   = Pick(HostileCountries);
            string ip1        = $"{_rng.Next(50, 200)}.{_rng.Next(1, 255)}.{_rng.Next(1, 255)}.{_rng.Next(1, 255)}";
            string ip2        = Pick(MaliciousIps);
            int    minsApart  = _rng.Next(2, 6);

            var time1 = DateTime.UtcNow.AddMinutes(-minsApart);
            var time2 = DateTime.UtcNow;

            string payload = $"""
                === SIEM CORRELATION ALERT: Impossible Travel Detected ===
                User: {domain}\{user}
                Login 1: {time1:yyyy-MM-dd HH:mm:ss} UTC from {ip1} ({country1.Name})
                Login 2: {time2:yyyy-MM-dd HH:mm:ss} UTC from {ip2} ({country2.Name})
                Time delta: {minsApart} minutes | Geographic distance: ~8,000 km

                --- Event 1 (Successful Logon — Event 4624) ---
                {BuildEvent4624Xml(user, domain, ip1, time1)}

                --- Event 2 (Successful Logon — Event 4624) ---
                {BuildEvent4624Xml(user, domain, ip2, time2)}
                """;

            return new AttackScenario(
                "IMPOSSIBLE TRAVEL",
                $"{domain}\\{user} logged in from {country1.Name} then {country2.Name} — {minsApart} min apart",
                payload
            );
        }

        // ==================================================================
        //  SCENARIO 3 — POWERSHELL ATTACK
        //  Event 4688 (Process Creation) showing powershell.exe launched
        //  with a Base64-encoded command — a classic living-off-the-land
        //  technique used for C2 beaconing and defence evasion.
        // ==================================================================

        private static AttackScenario GeneratePowerShellAttack()
        {
            string user       = Pick(TargetUsernames);
            string domain     = Pick(Domains);
            string encodedCmd = Pick(EncodedPayloads);

            return new AttackScenario(
                "POWERSHELL ATTACK",
                $"Encoded PowerShell execution by {domain}\\{user} — possible C2 / defence evasion",
                BuildEvent4688Xml(user, domain, encodedCmd)
            );
        }

        // ==================================================================
        //  SCENARIO 4 — FALSE POSITIVE (SAFE)
        //  A single failed logon from a trusted local IP — the kind of
        //  noise a SOC sees hundreds of times a day (password typo, locked
        //  account, expired credential).  The AI MUST classify this as SAFE.
        // ==================================================================

        private static AttackScenario GenerateFalsePositive()
        {
            string ip   = Pick(SafeLocalIps);
            string user = Pick(TargetUsernames);
            string domain = Pick(Domains);
            string wkst = Pick(SafeWorkstations);

            return new AttackScenario(
                "FALSE POSITIVE TEST",
                $"Single failed logon for {domain}\\{user} from local IP {ip} (likely a password typo)",
                BuildEvent4625Xml(user, domain, ip, wkst, DateTime.UtcNow, _rng.Next(880000, 890000))
            );
        }

        // ==================================================================
        //  XML EVENT BUILDERS — realistic Windows Event Log payloads
        // ==================================================================

        /// <summary>Build a Windows Security Event 4625 (Failed Logon) XML payload.</summary>
        private static string BuildEvent4625Xml(
            string user, string domain, string ip,
            string workstation, DateTime timestamp, int recordId)
        {
            int port = _rng.Next(49152, 65535);
            return $$"""
                <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
                  <System>
                    <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/>
                    <EventID>4625</EventID>
                    <Version>0</Version>
                    <Level>0</Level>
                    <Task>12544</Task>
                    <Opcode>0</Opcode>
                    <Keywords>0x8010000000000000</Keywords>
                    <TimeCreated SystemTime='{{timestamp:yyyy-MM-ddTHH:mm:ss.fffffffZ}}'/>
                    <EventRecordID>{{recordId}}</EventRecordID>
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
                    <Data Name='TargetUserName'>{{user}}</Data>
                    <Data Name='TargetDomainName'>{{domain}}</Data>
                    <Data Name='Status'>0xC000006D</Data>
                    <Data Name='FailureReason'>%%2313</Data>
                    <Data Name='SubStatus'>0xC0000064</Data>
                    <Data Name='LogonType'>10</Data>
                    <Data Name='LogonProcessName'>User32</Data>
                    <Data Name='AuthenticationPackageName'>Negotiate</Data>
                    <Data Name='WorkstationName'>{{workstation}}</Data>
                    <Data Name='TransmittedServices'>-</Data>
                    <Data Name='LmPackageName'>-</Data>
                    <Data Name='KeyLength'>0</Data>
                    <Data Name='ProcessId'>0x0</Data>
                    <Data Name='ProcessName'>-</Data>
                    <Data Name='IpAddress'>{{ip}}</Data>
                    <Data Name='IpPort'>{{port}}</Data>
                  </EventData>
                </Event>
                """;
        }

        /// <summary>Build a Windows Security Event 4624 (Successful Logon) XML payload.</summary>
        private static string BuildEvent4624Xml(
            string user, string domain, string ip, DateTime timestamp)
        {
            int port     = _rng.Next(49152, 65535);
            int recordId = _rng.Next(880000, 890000);
            return $$"""
                <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
                  <System>
                    <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/>
                    <EventID>4624</EventID>
                    <Version>2</Version>
                    <Level>0</Level>
                    <Task>12544</Task>
                    <Opcode>0</Opcode>
                    <Keywords>0x8020000000000000</Keywords>
                    <TimeCreated SystemTime='{{timestamp:yyyy-MM-ddTHH:mm:ss.fffffffZ}}'/>
                    <EventRecordID>{{recordId}}</EventRecordID>
                    <Correlation ActivityID='{00000000-0000-0000-0000-000000000000}'/>
                    <Execution ProcessID='612' ThreadID='1832'/>
                    <Channel>Security</Channel>
                    <Computer>WORKSTATION-07.corp.local</Computer>
                    <Security/>
                  </System>
                  <EventData>
                    <Data Name='SubjectUserSid'>S-1-5-18</Data>
                    <Data Name='SubjectUserName'>WORKSTATION-07$</Data>
                    <Data Name='SubjectDomainName'>CORP</Data>
                    <Data Name='SubjectLogonId'>0x3E7</Data>
                    <Data Name='TargetUserSid'>S-1-5-21-0000000000-0000000000-0000000000-1001</Data>
                    <Data Name='TargetUserName'>{{user}}</Data>
                    <Data Name='TargetDomainName'>{{domain}}</Data>
                    <Data Name='LogonType'>10</Data>
                    <Data Name='LogonProcessName'>User32</Data>
                    <Data Name='AuthenticationPackageName'>Negotiate</Data>
                    <Data Name='WorkstationName'>WORKSTATION-07</Data>
                    <Data Name='LogonGuid'>{00000000-0000-0000-0000-000000000000}</Data>
                    <Data Name='TransmittedServices'>-</Data>
                    <Data Name='LmPackageName'>-</Data>
                    <Data Name='KeyLength'>0</Data>
                    <Data Name='ProcessId'>0x0</Data>
                    <Data Name='ProcessName'>-</Data>
                    <Data Name='IpAddress'>{{ip}}</Data>
                    <Data Name='IpPort'>{{port}}</Data>
                  </EventData>
                </Event>
                """;
        }

        /// <summary>
        /// Build a Windows Security Event 4688 (Process Creation) XML payload
        /// with an encoded PowerShell command line.
        /// </summary>
        private static string BuildEvent4688Xml(
            string user, string domain, string encodedCmd)
        {
            int recordId = _rng.Next(880000, 890000);
            return $$"""
                <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
                  <System>
                    <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/>
                    <EventID>4688</EventID>
                    <Version>2</Version>
                    <Level>0</Level>
                    <Task>13312</Task>
                    <Opcode>0</Opcode>
                    <Keywords>0x8020000000000000</Keywords>
                    <TimeCreated SystemTime='{{DateTime.UtcNow:yyyy-MM-ddTHH:mm:ss.fffffffZ}}'/>
                    <EventRecordID>{{recordId}}</EventRecordID>
                    <Correlation ActivityID='{00000000-0000-0000-0000-000000000000}'/>
                    <Execution ProcessID='4' ThreadID='88'/>
                    <Channel>Security</Channel>
                    <Computer>WORKSTATION-07.corp.local</Computer>
                    <Security/>
                  </System>
                  <EventData>
                    <Data Name='SubjectUserSid'>S-1-5-21-0000000000-0000000000-0000000000-1001</Data>
                    <Data Name='SubjectUserName'>{{user}}</Data>
                    <Data Name='SubjectDomainName'>{{domain}}</Data>
                    <Data Name='SubjectLogonId'>0x3E7</Data>
                    <Data Name='NewProcessId'>0x1A2C</Data>
                    <Data Name='NewProcessName'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
                    <Data Name='TokenElevationType'>%%1937</Data>
                    <Data Name='ProcessId'>0x0FC8</Data>
                    <Data Name='CommandLine'>powershell.exe -NoProfile -WindowStyle Hidden -enc {{encodedCmd}}</Data>
                    <Data Name='TargetUserSid'>S-1-0-0</Data>
                    <Data Name='TargetUserName'>-</Data>
                    <Data Name='TargetDomainName'>-</Data>
                    <Data Name='TargetLogonId'>0x0</Data>
                    <Data Name='ParentProcessName'>C:\Windows\System32\cmd.exe</Data>
                    <Data Name='MandatoryLabel'>S-1-16-12288</Data>
                  </EventData>
                </Event>
                """;
        }

        // ==================================================================
        //  HELPER
        // ==================================================================

        /// <summary>Pick a random element from an array.</summary>
        private static T Pick<T>(T[] array) => array[_rng.Next(array.Length)];
    }
}
