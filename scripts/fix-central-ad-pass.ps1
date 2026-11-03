$ErrorActionPreference = 'Stop'
$admin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run in elevated PowerShell.' }

$serverRoot = Join-Path $env:ProgramFiles 'ThessleyAD\app\thessley_ad_service'
$clientRoot = Join-Path $env:ProgramData 'ThessleyPamWin\app\thessley_pam_win'
if (Test-Path (Join-Path $serverRoot 'http_api.py')) {
    $role = 'server'; $root = $serverRoot; $taskName = 'ThessleyADApi'
    $python = Join-Path $env:ProgramFiles 'ThessleyAD\Python\python.exe'
    $names = @('http_api.py','phone_registry.py')
} elseif (Test-Path (Join-Path $clientRoot 'daemon.py')) {
    $role = 'client'; $root = $clientRoot; $taskName = 'ThessleyPamWin'
    $python = Join-Path $env:ProgramFiles 'Python313\python.exe'
    $names = @('ad_agent.py','daemon.py')
} else { throw 'Thessley AD service/client was not found; no changes made.' }
if (-not (Test-Path -LiteralPath $python)) { throw "Python runtime missing: $python" }
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
$wasRunning = $task.State -eq 'Running'
$updated = @{}
foreach ($name in $names) { $updated[$name] = [IO.File]::ReadAllText((Join-Path $root $name), [Text.Encoding]::UTF8) }

if ($role -eq 'server') {
    $api = $updated['http_api.py']
    $start = $api.IndexOf('def phone_keys_route('); $end = $api.IndexOf('def phone_key_revoke_route(', $start)
    if ($start -lt 0 -or $end -lt 0) { throw 'Unexpected AD API source; no files changed.' }
    $oldRoute = $api.Substring($start, $end - $start)
    if ($oldRoute -notmatch 'list_for_principal_on_machine') {
        $route = @'
def phone_keys_route(registry: "MachineRegistry", replay_guard: "ReplayGuard",
                     phones: "PhoneRegistry"):
    """List machine keys, or active keys for one principal usable on this machine."""
    def handle(_client_ip: str, body: dict, raw_body: bytes, auth_headers: dict[str, str]):
        expected = {"x-thessley-machine-id", "x-thessley-timestamp", "x-thessley-nonce", "x-thessley-signature"}
        principal_id = body.get("principal_id")
        if (set(auth_headers) != expected
                or (body != {} and (set(body) != {"principal_id"}
                                    or not isinstance(principal_id, str)
                                    or not re.fullmatch(r"[a-f0-9]{64}", principal_id)))):
            return 400, {"result": "error", "message": "Invalid phone-key listing request."}
        machine_id = auth_headers["x-thessley-machine-id"]
        if not _authenticated_machine(machine_id, auth_headers["x-thessley-timestamp"],
                                      auth_headers["x-thessley-nonce"], auth_headers["x-thessley-signature"],
                                      PHONE_KEYS_PATH, raw_body, registry, replay_guard):
            return 401, {"result": "error", "message": "Machine authentication failed."}
        if not registry.machine_name(machine_id):
            return 401, {"result": "error", "message": "Machine authentication failed."}
        keys = (phones.list_for_machine(machine_id) if principal_id is None
                else phones.list_for_principal_on_machine(principal_id, machine_id))
        if len(keys) > 5000:
            return 503, {"result": "error", "message": "The phone-key listing is too large."}
        return 200, {"result": "listed", "keys": keys}
    return RawBodyRoute(handle)


'@
        $updated['http_api.py'] = $api.Substring(0,$start) + $route + $api.Substring($end)
    }
    $registry = $updated['phone_registry.py']
    if (-not $registry.Contains('def list_for_principal_on_machine(')) {
        $marker = '    def revoke_for_machine('
        $pos = $registry.IndexOf($marker)
        if ($pos -lt 0) { throw 'Unexpected phone registry source; no files changed.' }
        $method = @'
    def list_for_principal_on_machine(self, principal_id: str, machine_id: str) -> list[dict]:
        """Return active account keys usable on this workstation, including centrally enrolled keys."""
        if (not isinstance(principal_id, str) or not _PRINCIPAL_ID.fullmatch(principal_id)
                or not isinstance(machine_id, str) or not _MACHINE_ID.fullmatch(machine_id)):
            return []
        connection = self._connect()
        try:
            rows = connection.execute(
                """SELECT p.credential_id, p.principal_id, p.label, p.enrolled_at
                   FROM phone_credentials AS p
                   LEFT JOIN machines AS m ON m.machine_id = p.machine_id
                   WHERE p.principal_id = ? AND p.revoked_at IS NULL
                     AND ((p.machine_id = ? AND m.revoked_at IS NULL) OR p.machine_id = ?)
                   ORDER BY p.enrolled_at, p.credential_id""",
                (principal_id, machine_id, CENTRAL_AD_MACHINE_ID),
            ).fetchall()
            return [{"credential_id": str(c), "principal_id": str(p), "label": str(label), "enrolled_at": int(t)}
                    for c, p, label, t in rows]
        finally:
            connection.close()

'@
        $updated['phone_registry.py'] = $registry.Insert($pos,$method)
    }
} else {
    $agent = $updated['ad_agent.py']
    $start = $agent.IndexOf('def phone_keys() -> list[dict]:')
    if ($start -ge 0) {
        $end = $agent.IndexOf('def resolve_principal(', $start)
        if ($end -lt 0) { throw 'Unexpected AD client source; no files changed.' }
        $function = @'
def phone_keys(principal_id: str | None = None) -> list[dict]:
    """List active keys, optionally scoped to this account on this workstation."""
    if principal_id is not None and not re.fullmatch(r"[a-f0-9]{64}", principal_id):
        raise AgentError("The AD principal ID for phone-key lookup is invalid.")
    body = {} if principal_id is None else {"principal_id": principal_id}
    result = _signed_post("/thessley-ad/v1/directory/phone-keys", body, timeout=15.0)
    keys = result.get("keys")
    if result.get("result") != "listed" or not isinstance(keys, list) or len(keys) > 5000:
        raise AgentError("The AD service returned an invalid phone-key listing.")
    clean = []
    for key in keys:
        if not isinstance(key, dict): raise AgentError("The AD service returned an invalid phone-key listing.")
        credential, principal, label, enrolled = (key.get("credential_id"), key.get("principal_id"),
                                                    key.get("label"), key.get("enrolled_at"))
        if (not isinstance(credential, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,64}", credential)
                or not isinstance(principal, str) or not re.fullmatch(r"[a-f0-9]{64}", principal)
                or not isinstance(label, str) or not 1 <= len(label) <= 64
                or isinstance(enrolled, bool) or not isinstance(enrolled, int) or enrolled < 0
                or (principal_id is not None and principal != principal_id)):
            raise AgentError("The AD service returned an invalid phone-key listing.")
        clean.append({"credential_id": credential, "principal_id": principal, "label": label, "enrolled_at": enrolled})
    return clean


'@
        $updated['ad_agent.py'] = $agent.Substring(0,$start) + $function + $agent.Substring($end)
    } elseif (-not $agent.Contains('def phone_keys(principal_id: str | None = None)')) {
        throw 'Unexpected AD client phone-key function; no files changed.'
    }
    $daemon = $updated['daemon.py']
    $oldCall = 'key["credential_id"] for key in ad_agent.phone_keys()'
    $newCall = 'key["credential_id"] for key in ad_agent.phone_keys(principal["principal_id"])'
    if ($daemon.Contains($oldCall)) { $updated['daemon.py'] = $daemon.Replace($oldCall,$newCall) }
    elseif (-not $daemon.Contains($newCall)) { throw 'Unexpected AD SSH pass check; no files changed.' }
}

$stage = Join-Path $env:TEMP ('ThessleyPassFix-' + [guid]::NewGuid().ToString('N'))
$backup = Join-Path $env:ProgramData ("ThessleyPassFix-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $stage -Force | Out-Null
try {
    foreach ($name in $names) {
        $staged = Join-Path $stage $name
        [IO.File]::WriteAllText($staged,$updated[$name],[Text.UTF8Encoding]::new($false))
        & $python -I -c "import pathlib; p=pathlib.Path(r'$staged'); compile(p.read_text(encoding='utf-8'), p.name, 'exec')"
        if ($LASTEXITCODE -ne 0) { throw "Syntax check failed for $name; live files unchanged." }
    }
    New-Item -ItemType Directory -Path $backup -Force | Out-Null
    if ($wasRunning) {
        Stop-ScheduledTask -TaskName $taskName
        $until = (Get-Date).AddSeconds(20)
        do { Start-Sleep -Milliseconds 300; $task = Get-ScheduledTask -TaskName $taskName } while ($task.State -eq 'Running' -and (Get-Date) -lt $until)
        if ($task.State -eq 'Running') { throw 'Task did not stop; files unchanged.' }
    }
    foreach ($name in $names) {
        $path = Join-Path $root $name
        Copy-Item -LiteralPath $path -Destination (Join-Path $backup $name) -Force
        Copy-Item -LiteralPath (Join-Path $stage $name) -Destination $path -Force
    }
    if ($wasRunning) {
        Start-ScheduledTask -TaskName $taskName
        $until = (Get-Date).AddSeconds(45)
        do { Start-Sleep -Milliseconds 500; $task = Get-ScheduledTask -TaskName $taskName } while ($task.State -ne 'Running' -and (Get-Date) -lt $until)
        if ($task.State -ne 'Running') { throw 'Task did not return to Running.' }
    }
    Write-Host "Updated $role pass validation. Backup: $backup"
} catch {
    foreach ($name in $names) {
        $saved = Join-Path $backup $name
        if (Test-Path $saved) { Copy-Item $saved (Join-Path $root $name) -Force }
    }
    if ($wasRunning) { Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue; Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue }
    throw
} finally { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue }
