from aegis.runtime.probes.model import NONCE, Kind, Probe, RecordPattern, Role, Signature

# AEGIS's canary on the default Docker bridge. deploy/openshell/*.yaml allow exactly this endpoint,
# for GET /probe/** from CANARY_BINARY only, and a test keeps the two in step (ADR-0018).
CANARY_HOST = "172.17.0.1"
CANARY_PORT = 18901
CANARY_OTHER_PORT = 18902
CANARY_BINARY = "/usr/bin/bash"
CANARY_REPLY = "aegis-canary"
# Built into the probe image (deploy/openshell/probe/Dockerfile), owned by the probe user.
READONLY_MARKER = "/srv/aegis/readonly/marker"
READONLY_CONTENT = "aegis read-only marker"
UNLISTED_FILE = "/srv/aegis/unlisted/private"
# TEST-NET-1 (RFC 5737) is never routed, so even a failed restriction sends nothing anywhere.
UNROUTED_HOST = "192.0.2.1"
METADATA_HOST = "169.254.169.254"

EACCES = "Permission denied"
POLICY_DENIED = '"error":"policy_denied"'
CONNECT_REFUSED = 9


def _request(method: str, path: str, host: str = CANARY_HOST, port: int = CANARY_PORT) -> str:
    # bash's /dev/tcp: one connection, one request, and the reply on stdout.
    request = f"{method} {path} HTTP/1.0\\r\\nHost: {host}:{port}\\r\\n\\r\\n"
    return (
        f"exec 3<>/dev/tcp/{host}/{port} || exit {CONNECT_REFUSED};"
        f' printf "{request}" >&3; head -c 512 <&3'
    )


def _denied_file(check_id: str, *argv: str) -> Probe:
    # The probe user owns these paths, so a refusal here comes from Landlock, not Unix permissions.
    return Probe(
        check_id,
        Kind.FILESYSTEM,
        Role.RESTRICTION,
        argv,
        expected=Signature(exit_zero=False, stderr_has=(EACCES,)),
        breached=Signature(exit_zero=True),
    )


def _denied_request(check_id: str, method: str, path: str) -> Probe:
    return Probe(
        check_id,
        Kind.NETWORK,
        Role.RESTRICTION,
        (CANARY_BINARY, "-c", _request(method, path)),
        expected=Signature(exit_zero=True, stdout_has=(POLICY_DENIED,)),
        breached=Signature(stdout_has=(CANARY_REPLY,)),
        canary=(CANARY_PORT, path),
        record=RecordPattern(f"HTTP:{method}", "DENIED", path),
    )


def _denied_connection(
    check_id: str, host: str, port: int, argv: tuple[str, ...] | None = None, by: str = ""
) -> Probe:
    path = f"/probe/{NONCE}/{check_id}"
    return Probe(
        check_id,
        Kind.NETWORK,
        Role.RESTRICTION,
        argv or (CANARY_BINARY, "-c", _request("GET", path, host, port)),
        expected=Signature(exit_zero=False, stderr_has=(EACCES,)),
        breached=Signature(exit_zero=True),
        canary=(port, path) if host == CANARY_HOST else None,
        record=RecordPattern(
            "NET:OPEN", "DENIED", f"{by}(0) -> {host}:{port}" if by else f"-> {host}:{port}"
        ),
    )


_PERL_REQUEST = (
    f'$s = IO::Socket::INET->new(PeerAddr => "{CANARY_HOST}", PeerPort => {CANARY_PORT},'
    ' Timeout => 5) or do { print STDERR "connect: $!\\n";'
    f" exit {CONNECT_REFUSED} }};"
    f' print $s "GET /probe/{NONCE}/network.other_binary HTTP/1.0\\r\\n\\r\\n"; print <$s>;'
)

# Run in this order: the read-only marker is read again after the attempts to change it.
PROBES = (
    Probe(
        "filesystem.scratch_write",
        Kind.FILESYSTEM,
        Role.CONTROL,
        (CANARY_BINARY, "-c", 'printf %s "$0" > /tmp/aegis-probe && cat /tmp/aegis-probe', NONCE),
        expected=Signature(exit_zero=True, stdout_is=NONCE),
    ),
    Probe(
        "filesystem.listed_read",
        Kind.FILESYSTEM,
        Role.CONTROL,
        ("/usr/bin/cat", READONLY_MARKER),
        expected=Signature(exit_zero=True, stdout_is=READONLY_CONTENT),
    ),
    _denied_file("filesystem.unlisted_read", "/usr/bin/cat", UNLISTED_FILE),
    _denied_file("filesystem.readonly_truncate", "/usr/bin/truncate", "-s", "0", READONLY_MARKER),
    _denied_file("filesystem.readonly_create", "/usr/bin/touch", "/srv/aegis/readonly/created"),
    _denied_file("filesystem.private_read", "/usr/bin/ls", "/.openshell"),
    _denied_file("filesystem.supervisor_environment", "/usr/bin/cat", "/proc/1/environ"),
    Probe(
        "filesystem.readonly_intact",
        Kind.FILESYSTEM,
        Role.RESTRICTION,
        ("/usr/bin/cat", READONLY_MARKER),
        expected=Signature(exit_zero=True, stdout_is=READONLY_CONTENT),
        breached=Signature(exit_zero=True),
    ),
    Probe(
        "process.hardening",
        Kind.PROCESS,
        Role.RESTRICTION,
        ("/usr/bin/grep", "-E", "^(NoNewPrivs|CapEff|Seccomp):", "/proc/self/status"),
        expected=Signature(
            exit_zero=True,
            stdout_has=("NoNewPrivs:\t1", "CapEff:\t0000000000000000", "Seccomp:\t2"),
        ),
        breached=Signature(exit_zero=True),
    ),
    Probe(
        "network.canary_get",
        Kind.NETWORK,
        Role.CONTROL,
        (CANARY_BINARY, "-c", _request("GET", f"/probe/{NONCE}/network.canary_get")),
        expected=Signature(
            exit_zero=True, stdout_has=(f"{CANARY_REPLY} /probe/{NONCE}/network.canary_get",)
        ),
        canary=(CANARY_PORT, f"/probe/{NONCE}/network.canary_get"),
        record=RecordPattern("HTTP:GET", "ALLOWED", f"/probe/{NONCE}/network.canary_get"),
    ),
    _denied_request("network.request_method", "POST", f"/probe/{NONCE}/network.request_method"),
    _denied_request("network.request_path", "GET", f"/admin/{NONCE}/network.request_path"),
    _denied_connection("network.other_port", CANARY_HOST, CANARY_OTHER_PORT),
    _denied_connection(
        "network.other_binary",
        CANARY_HOST,
        CANARY_PORT,
        ("/usr/bin/perl", "-MIO::Socket::INET", "-e", _PERL_REQUEST),
        by="/usr/bin/perl",
    ),
    _denied_connection("network.unrouted_host", UNROUTED_HOST, 443),
    _denied_connection("network.metadata", METADATA_HOST, 80),
)
