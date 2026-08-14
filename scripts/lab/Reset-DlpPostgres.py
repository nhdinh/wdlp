"""Reset the DLP database on LAB-SERVER01 via SSH/Sudo.

The Ubuntu admin account (dlpadmin) is used for SSH; sudo switches to the
postgres OS user to run psql. No PostgreSQL role password is required.
"""
import os
import re
import sys
import paramiko


_POSTGRES_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}\Z")


def configured_identifier(name, default):
    """Return a PostgreSQL identifier after enforcing the lab naming policy."""
    value = os.environ.get(name, default)
    if not _POSTGRES_IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must be a PostgreSQL identifier")
    return value


def main():
    host = os.environ.get("DLP_SERVER01_HOST", "192.168.50.12")
    user = os.environ.get("DLP_SERVER01_ADMIN_USER", "dlpadmin")
    password = os.environ.get("DLP_SERVER01_ADMIN_PASSWORD")
    if not password:
        print("DLP_SERVER01_ADMIN_PASSWORD is required", file=sys.stderr)
        sys.exit(1)

    try:
        db_owner = configured_identifier("DLP_DATABASE_USER", "dlp_server")
        db_name = configured_identifier("DLP_DATABASE_NAME", "dlp")
    except ValueError as error:
        print(error, file=sys.stderr)
        sys.exit(1)

    known_hosts = os.environ.get("DLP_SERVER01_KNOWN_HOSTS")
    if not known_hosts or not os.path.isfile(known_hosts):
        print(
            "DLP_SERVER01_KNOWN_HOSTS must name a readable file containing the pinned SSH host key",
            file=sys.stderr,
        )
        sys.exit(1)

    client = paramiko.SSHClient()
    client.load_host_keys(known_hosts)
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.connect(host, username=user, password=password, timeout=30)

    def psql(sql):
        # The password and SQL travel only over SSH stdin.  Identifiers are
        # constrained above and passed as psql variables rather than spliced
        # into either the remote shell command or SQL text.
        command = (
            "sudo -S -u postgres psql -X -v ON_ERROR_STOP=1 "
            f"-v db_name={db_name} -v db_owner={db_owner} -f -"
        )
        stdin, stdout, stderr = client.exec_command(command, get_pty=False)
        stdin.write(password + "\n" + sql)
        stdin.flush()
        stdin.channel.shutdown_write()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        return out, err, stdout.channel.recv_exit_status()

    sql = """
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE datname = :'db_name' AND pid <> pg_backend_pid();
DROP DATABASE IF EXISTS :\"db_name\";
CREATE DATABASE :\"db_name\" OWNER :\"db_owner\";
"""
    out_create, err_create, exit_status = psql(sql)
    client.close()

    print(out_create)
    if err_create:
        print(err_create, file=sys.stderr)
    if exit_status != 0 or "CREATE DATABASE" not in out_create:
        sys.exit(1)


if __name__ == "__main__":
    main()
