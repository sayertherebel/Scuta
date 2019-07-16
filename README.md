# Scuta
Service for Windows computers to automatically add firewall rules for invalid SSH users or failed logins

Watches an OpenSSH log for failed logins and invalid users, and adds the incoming IP to block rules in the Windows Firewall. This only works for scenarios where the true IP of the connecting client is apparent to the machine running OpenSSH and not hidden in the NAT'ing process. 

Firewall rules are aged, with rules older than 1h (default) removed using a lazy cleanup mechanism that runs when new rules are added. All existing rules are removed at startup.

There is a reporting mechanism to Microsoft PowerBI streaming service for building dashboards.
