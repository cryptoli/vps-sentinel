#!/usr/bin/env sh
set -eu

usage() {
  cat <<'EOF'
Usage:
  scripts/vs-fleet.sh --host HOST [--host HOST ...] [-- command...]
  scripts/vs-fleet.sh --host-file hosts.txt [-- command...]

Options:
  --host HOST        SSH host target. May be repeated.
  --host-file PATH   File with one SSH host per line. Blank lines and # comments are ignored.
  --user USER        SSH username.
  --identity PATH    SSH private key path.
  --jump HOST        SSH ProxyJump target.
  --port PORT        SSH port for all hosts.
  --timeout SECONDS  SSH connect timeout. Default: 10.

Examples:
  scripts/vs-fleet.sh --host root@vps1 --host root@vps2 -- sudo vs status
  scripts/vs-fleet.sh --host-file hosts.txt -- sudo vs config validate
  scripts/vs-fleet.sh --host-file hosts.txt -- sudo vs menu
EOF
}

hosts=""
host_file=""
ssh_user=""
identity=""
jump_host=""
ssh_port=""
timeout_seconds="10"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --host)
      [ "$#" -ge 2 ] || { echo "--host requires a value" >&2; exit 2; }
      hosts="${hosts}
$2"
      shift 2
      ;;
    --host-file)
      [ "$#" -ge 2 ] || { echo "--host-file requires a value" >&2; exit 2; }
      host_file="$2"
      shift 2
      ;;
    --user)
      [ "$#" -ge 2 ] || { echo "--user requires a value" >&2; exit 2; }
      ssh_user="$2"
      shift 2
      ;;
    --identity)
      [ "$#" -ge 2 ] || { echo "--identity requires a value" >&2; exit 2; }
      identity="$2"
      shift 2
      ;;
    --jump)
      [ "$#" -ge 2 ] || { echo "--jump requires a value" >&2; exit 2; }
      jump_host="$2"
      shift 2
      ;;
    --port)
      [ "$#" -ge 2 ] || { echo "--port requires a value" >&2; exit 2; }
      ssh_port="$2"
      shift 2
      ;;
    --timeout)
      [ "$#" -ge 2 ] || { echo "--timeout requires a value" >&2; exit 2; }
      timeout_seconds="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    *)
      break
      ;;
  esac
done

if [ -n "$host_file" ]; then
  [ -f "$host_file" ] || { echo "host file not found: $host_file" >&2; exit 2; }
  file_hosts="$(sed 's/[[:space:]]*#.*$//' "$host_file" | sed '/^[[:space:]]*$/d')"
  hosts="${hosts}
${file_hosts}"
fi

command_text="${*:-sudo vs status}"
targets="$(printf '%s\n' "$hosts" | sed '/^[[:space:]]*$/d')"
if [ -z "$targets" ]; then
  echo "at least one --host or --host-file target is required" >&2
  usage >&2
  exit 2
fi

ssh_config="$(mktemp "${TMPDIR:-/tmp}/vs-fleet-ssh-config.XXXXXX")"
trap 'rm -f "$ssh_config"' EXIT INT TERM
{
  printf '%s\n' 'Host *'
  printf '%s\n' '  BatchMode yes'
  printf '%s\n' '  StrictHostKeyChecking accept-new'
  printf '  ConnectTimeout %s\n' "$timeout_seconds"
  [ -n "$identity" ] && printf '  IdentityFile %s\n' "$identity"
  [ -n "$jump_host" ] && printf '  ProxyJump %s\n' "$jump_host"
  [ -n "$ssh_port" ] && printf '  Port %s\n' "$ssh_port"
} >"$ssh_config"
chmod 0600 "$ssh_config"

failed=0
for target in $targets; do
  case "$target" in
    *@*) ssh_target="$target" ;;
    *) ssh_target="${ssh_user:+$ssh_user@}$target" ;;
  esac
  case "$ssh_target" in
    -*) echo "refusing SSH target that starts with '-': $ssh_target" >&2; failed=$((failed + 1)); continue ;;
  esac
  printf '\n== %s ==\n' "$ssh_target"
  if ! ssh -F "$ssh_config" "$ssh_target" "$command_text"; then
    failed=$((failed + 1))
  fi
done

if [ "$failed" -gt 0 ]; then
  echo "failed targets: $failed" >&2
  exit 1
fi
