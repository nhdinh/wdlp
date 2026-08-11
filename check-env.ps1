[Environment]::GetEnvironmentVariables().GetEnumerator() | Where-Object { $_.Key -like 'DLP_*' } | ForEach-Object { '{0}=[redacted]' -f $_.Key }
