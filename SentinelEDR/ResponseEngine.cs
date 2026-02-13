// ==========================================================================
//  Sentinel EDR — ResponseEngine.cs
//  Active Defense Response Engine: OS-level threat eradication
//  Target: .NET 8.0  |  Requires Administrator privileges
// ==========================================================================
//
//  PURPOSE
//  ───────
//  This static helper class provides "Active Defense" countermeasures that
//  interact directly with the Windows operating system to neutralise threats
//  identified by the Agentic AI engine.
//
//  All methods shell out to built-in Windows admin commands.  Because these
//  require elevated privileges, each ProcessStartInfo sets Verb = "runas"
//  so Windows presents a UAC prompt if the app is not already elevated.
//
//  METHODS
//  ───────
//  1. BlockIpInFirewall(ip)      → netsh advfirewall … action=block
//  2. KillProcess(pid)           → taskkill /PID <pid> /F
//  3. DisableUserAccount(user)   → net user <user> /active:no
//
//  SECURITY NOTES
//  ──────────────
//  • Every public method validates its input BEFORE building the command
//    string.  IP addresses are parsed with IPAddress.TryParse, PIDs are
//    range-checked, and usernames are filtered to safe characters only.
//    This prevents command-injection attacks.
//
//  • Verb = "runas" + UseShellExecute = true triggers UAC elevation.
//    If the operator declines the UAC prompt, the Win32Exception with
//    NativeErrorCode 1223 (ERROR_CANCELLED) is caught gracefully.
// ==========================================================================

using System;
using System.Diagnostics;
using System.Net;
using System.Text.RegularExpressions;

namespace SentinelEDR
{
    /// <summary>
    /// Active Defense Response Engine.
    /// Executes OS-level countermeasures to eradicate identified threats.
    /// All methods require Administrator privileges.
    /// </summary>
    public static class ResponseEngine
    {
        // ==================================================================
        //  PUBLIC API
        // ==================================================================

        /// <summary>
        /// Creates a Windows Firewall inbound BLOCK rule for the given IP.
        /// Command: netsh advfirewall firewall add rule
        ///            name="SentinelEDR_Block_{ip}" dir=in action=block
        ///            remoteip={ip} enable=yes
        /// </summary>
        public static (bool Success, string Message) BlockIpInFirewall(string ip)
        {
            if (!IPAddress.TryParse(ip, out _))
                return (false, $"Invalid IP address format: {ip}");

            string ruleName = $"SentinelEDR_Block_{ip}_{DateTime.Now:yyyyMMdd_HHmmss}";
            string arguments =
                $"advfirewall firewall add rule " +
                $"name=\"{ruleName}\" " +
                $"dir=in action=block remoteip={ip} enable=yes";

            return ExecuteElevatedCommand(
                "netsh",
                arguments,
                $"Firewall rule '{ruleName}' created — inbound traffic from {ip} is now BLOCKED.");
        }

        /// <summary>
        /// Immediately terminates a process by its PID.
        /// Command: taskkill /PID {pid} /F
        /// The /F flag forces termination even if the process is unresponsive.
        /// </summary>
        public static (bool Success, string Message) KillProcess(int pid)
        {
            if (pid <= 0)
                return (false, $"Invalid PID: {pid}. Must be a positive integer.");

            return ExecuteElevatedCommand(
                "taskkill",
                $"/PID {pid} /F",
                $"Process with PID {pid} has been forcefully terminated.");
        }

        /// <summary>
        /// Disables a local Windows user account to lock out a compromised identity.
        /// Command: net user {username} /active:no
        /// </summary>
        public static (bool Success, string Message) DisableUserAccount(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return (false, "Username cannot be empty.");

            // Allow only safe characters — prevents command injection
            if (!Regex.IsMatch(username, @"^[a-zA-Z0-9._\-]+$"))
                return (false, $"Invalid username format: '{username}'. Only alphanumeric, dot, underscore, and hyphen are allowed.");

            return ExecuteElevatedCommand(
                "net",
                $"user {username} /active:no",
                $"User account '{username}' has been DISABLED.");
        }

        // ==================================================================
        //  PRIVATE HELPER — elevated command execution
        // ==================================================================

        /// <summary>
        /// Starts a process with Administrator elevation (Verb = "runas").
        /// UseShellExecute must be true for runas to work.
        /// WindowStyle.Hidden suppresses the command-prompt flash.
        /// </summary>
        private static (bool Success, string Message) ExecuteElevatedCommand(
            string fileName,
            string arguments,
            string successMessage)
        {
            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName       = fileName,
                    Arguments      = arguments,
                    Verb           = "runas",                       // Request UAC elevation
                    UseShellExecute = true,                         // Required for Verb = "runas"
                    WindowStyle    = ProcessWindowStyle.Hidden      // Hide the cmd flash
                };

                using var process = Process.Start(startInfo);

                if (process == null)
                    return (false, "Failed to start the elevated process.");

                // Wait up to 10 seconds for the command to complete
                process.WaitForExit(10_000);

                return process.ExitCode == 0
                    ? (true, successMessage)
                    : (false, $"Command exited with code {process.ExitCode}.");
            }
            catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
            {
                // ERROR_CANCELLED — the user clicked "No" on the UAC prompt
                return (false, "UAC elevation was declined by the operator.");
            }
            catch (Exception ex)
            {
                return (false, $"Execution failed: {ex.Message}");
            }
        }
    }
}
