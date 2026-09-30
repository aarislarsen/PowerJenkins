# Invoke-JenkinsWebLogin

`Invoke-JenkinsWebLogin.ps1` is a PowerShell helper for authorized Jenkins security testing when only the web UI is available. It authenticates through the Jenkins login form, handles CSRF crumbs, and submits Groovy to `/scriptText` to run a command or selected assessment payloads through the Jenkins Script Console.

The Jenkins Script Console provides code execution by design to users with `Overall/RunScripts`. Use this only on Jenkins instances you own or are explicitly authorized to test.

## Features

- Supports Jenkins web login with username and password.
- Automatically parses login form action and hidden fields.
- Handles Jenkins CSRF crumbs for login and Script Console requests.
- Supports Jenkins deployed at a non-root context path, such as `/jenkins`.
- Tries anonymous Script Console access first for intentionally open Jenkins instances.
- Supports PowerShell 5.1 and PowerShell 7+.
- Supports HTTP and HTTPS, including optional certificate validation bypass for lab systems.
- Can run a single OS command, a custom Groovy script, or built-in security assessment modes.

## Requirements

- PowerShell 5.1 or PowerShell 7+.
- Network access to the Jenkins web interface.
- A Jenkins account with `Overall/RunScripts`, unless anonymous users already have Script Console access.
- Jenkins Script Console enabled and reachable at `/scriptText`.

## Installation

Clone or download this repository, then import the function:

```powershell
. .\Invoke-JenkinsWebLogin.ps1
```

If PowerShell blocks local script execution, run PowerShell from a trusted working directory and use an execution policy appropriate for your environment, for example:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\your-runner.ps1
```

## Quick Start

Run the default command, `whoami`, against a Jenkins controller:

```powershell
Invoke-JenkinsWebLogin -Target 10.0.0.5 -User admin -Password 'P@ssw0rd!'
```

Run a specific command:

```powershell
Invoke-JenkinsWebLogin -Target 10.0.0.5 -User admin -Password 'P@ssw0rd!' -Command 'id'
```

Use HTTPS with a self-signed certificate:

```powershell
Invoke-JenkinsWebLogin -Target jenkins.example.local -Scheme https -Port 443 -User admin -Password 'P@ssw0rd!' -Command 'whoami' -SkipCertCheck
```

Use a Jenkins instance deployed under a context path:

```powershell
Invoke-JenkinsWebLogin -Target 10.0.0.5 -Port 8080 -ContextPath '/jenkins' -User admin -Password 'P@ssw0rd!' -Command 'hostname'
```

You can also pass a full URL as the target. The script normalizes the scheme, host, port, and context path:

```powershell
Invoke-JenkinsWebLogin -Target 'https://jenkins.example.local:8443/jenkins' -User admin -Password 'P@ssw0rd!' -Command 'whoami' -SkipCertCheck
```

## Usage

```powershell
Invoke-JenkinsWebLogin [-Target] <string> [[-Command] <string>] [-Port <int>] [-Scheme <http|https>] [-User <string>] [-Password <string>] [-Script <string>] [-ContextPath <string>] [-LegacyLogin] [-SkipCertCheck] [-DumpCreds] [-DumpSSHKeys] [-DumpBasicCreds] [-TaskList] [-Recon] [-All] [-ListModes] [-Debug]
```

## Parameters

| Parameter | Description |
| --- | --- |
| `-Target` | Jenkins hostname or IP address. Also accepts `host:port/path` or a full URL, which the script normalizes. Required unless `-ListModes` is used. |
| `-Command` | OS command to execute on the Jenkins controller. Defaults to `whoami`. Ignored when `-Script` is supplied. |
| `-Port` | TCP port for Jenkins. Defaults to `8080`. |
| `-Scheme` | `http` or `https`. Defaults to `http`. |
| `-User` | Jenkins username. Required if anonymous Script Console access is not available. |
| `-Password` | Jenkins password as a plain string. Required if anonymous Script Console access is not available. |
| `-Script` | Custom Groovy payload to submit to `/scriptText`. Overrides `-Command` and extraction switches. |
| `-ContextPath` | Optional Jenkins context path, such as `/jenkins`. |
| `-LegacyLogin` | Use `/j_acegi_security_check` for older Jenkins builds. |
| `-SkipCertCheck` | Ignore TLS certificate validation errors. Useful for self-signed lab certificates. |
| `-DumpCreds` | Run the built-in Jenkins credential enumeration payload. |
| `-DumpSSHKeys` | Run the built-in SSH key credential enumeration payload. |
| `-DumpBasicCreds` | Run the built-in basic username/password and secret credential enumeration payload. |
| `-TaskList` | Run process listing on the controller. Uses `tasklist /v /fo:csv` on Windows and `ps -ef` on Linux. |
| `-Recon` | Run built-in host reconnaissance commands on the controller. |
| `-All` | Run all built-in extraction and reconnaissance modes. |
| `-ListModes` | Print available extraction modes and exit. |
| `-Debug` | Print detailed request flow, target normalization, cookies, crumb handling, and failure response details. Passwords are masked in debug login output. |

## Built-In Modes

List available built-in modes:

```powershell
Invoke-JenkinsWebLogin -ListModes
```

Run process listing:

```powershell
Invoke-JenkinsWebLogin -Target 10.0.0.5 -User admin -Password 'P@ssw0rd!' -TaskList
```

Run host reconnaissance:

```powershell
Invoke-JenkinsWebLogin -Target 10.0.0.5 -User admin -Password 'P@ssw0rd!' -Recon
```

Run all built-in modes:

```powershell
Invoke-JenkinsWebLogin -Target 10.0.0.5 -User admin -Password 'P@ssw0rd!' -All
```

## Custom Groovy

Use `-Script` to submit your own Groovy to the Script Console:

```powershell
$groovy = @'
println "Jenkins version: " + Jenkins.instance.getVersion()
println "Controller user: " + System.getProperty("user.name")
'@

Invoke-JenkinsWebLogin -Target 10.0.0.5 -User admin -Password 'P@ssw0rd!' -Script $groovy
```

`-Script` takes priority over `-Command` and all built-in modes.

## Authentication Flow

The function follows the same high-level flow as a browser login:

1. Build the Jenkins base URL from `-Target`, `-Scheme`, `-Port`, and `-ContextPath`.
2. Try anonymous `/scriptText` execution first.
3. Fetch `/login?from=%2Fscript` and parse the login form action and hidden fields.
4. POST credentials to the detected login endpoint.
5. Fetch an authenticated CSRF crumb from `/crumbIssuer/api/json`.
6. POST the Groovy payload to `/scriptText` with the session cookie and crumb.

## Troubleshooting

Use `-Debug` when troubleshooting:

```powershell
Invoke-JenkinsWebLogin -Target 10.0.0.5 -User admin -Password 'P@ssw0rd!' -Command 'whoami' -Debug
```

Common issues:

| Symptom | Likely Cause |
| --- | --- |
| `This Jenkins instance requires authentication` | Anonymous Script Console access failed and `-User` or `-Password` was not provided. |
| `Authentication failed` | Bad credentials, locked account, or unexpected login flow. Retry with `-Debug`. |
| `No session cookie set` | Login did not establish a Jenkins session. Check target URL, context path, and credentials. |
| `403 => account lacks Overall/RunScripts` | The account authenticated but does not have Script Console permissions. |
| TLS certificate errors | Use `-SkipCertCheck` for authorized lab or internal systems with self-signed certificates. |
| Old Jenkins login endpoint fails | Try `-LegacyLogin`. |

## Security Notes

- Jenkins Script Console access is equivalent to controller-level code execution.
- Built-in credential extraction modes can expose sensitive secrets. Handle output carefully.
- Prefer scoped test accounts and dedicated lab targets when validating behavior.
- Do not run this against third-party systems without written authorization.

## License

Add your preferred license before publishing this repository.
