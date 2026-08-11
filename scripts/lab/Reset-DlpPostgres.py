"""Reset the DLP database on LAB-SERVER01 via SSH/Sudo.

The Ubuntu admin account (dlpadmin) is used for SSH; sudo switches to the
postgres OS user to run psql. No PostgreSQL role password is required.
"""
import os
import sys
import paramiko


def main():
    host = os.environ.get("DLP_SERVER01_HOST", "192.168.50.12")
    user = os.environ.get("DLP_SERVER01_ADMIN_USER", "dlpadmin")
    password = os.environ.get("DLP_SERVER01_ADMIN_PASSWORD")
    if not password:
        print("DLP_SERVER01_ADMIN_PASSWORD is required", file=sys.stderr)
        sys.exit(1)

    db_owner = os.environ.get("DLP_DATABASE_USER", "dlp_server")
    db_name = os.environ.get("DLP_DATABASE_NAME", "dlp")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=user, password=password, timeout=30)

    def psql(sql):
        # Escape double quotes in SQL so the shell command remains valid.
        escaped = sql.replace('"', '\\"')
        cmd = f"echo '{password}' | sudo -S -u postgres psql -v ON_ERROR_STOP=1 -c \"{escaped}\""
        stdin, stdout, stderr = client.exec_command(cmd, get_pty=True)
        stdin.write(password + "\n")
        stdin.flush()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        # Remove password prompt echo from stderr to avoid leaking secrets.
        err = err.replace(f"[sudo] password for {user}:", "").strip()
        return out, err

    # Terminate existing connections before dropping.
    terminate_sql = (
        f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
        f"WHERE datname = '{db_name}' AND pid <> pg_backend_pid();"
    )
    psql(terminate_sql)

    out_drop, err_drop = psql(f'DROP DATABASE IF EXISTS {db_name};')
    out_create, err_create = psql(f'CREATE DATABASE {db_name} OWNER {db_owner};')
    client.close()

    print(out_drop)
    print(out_create)
    combined_err = (err_drop or "") + (err_create or "")
    if combined_err:
        print(combined_err, file=sys.stderr)
    if "CREATE DATABASE" not in out_create:
        sys.exit(1)


if __name__ == "__main__":
    main()
