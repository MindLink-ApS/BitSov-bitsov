# Node logging: journal-only by default

The node's tracing subscriber writes to stdout. It does not open `node.log`.
Under systemd that same output belongs in the journal; redirecting it to
`node.log` duplicates the journal and creates an unbounded file outside the
node's control. The shipped [user service example](konsensus.service) explicitly
uses `StandardOutput=journal` and `StandardError=journal`, with no shell wrapper
or file redirection. Foreground CLI runs continue to log to stdout.

For an existing installation, keep its binary, configuration, identity and data
paths. Change its unit's output/error settings to the values above and remove
any `>> node.log`, `tee`, `StandardOutput=append:...` or `nohup` logging wrapper.
After reloading the user units and restarting the service, verify new events
with `journalctl --user -u konsensus.service`. Substitute the installed unit name.
An old `node.log` is not removed automatically: archive or delete it only after
verifying that no process writes to it. These are deployment instructions;
upgrading the binary alone cannot change an existing supervisor's redirection.

Journald owns rotation. On a systemd host, a reasonable small-node starting
point is this administrator-managed `/etc/systemd/journald.conf.d/size.conf`:

```ini
[Journal]
SystemMaxUse=100M
SystemMaxFileSize=10M
SystemMaxFiles=10
RuntimeMaxUse=50M
RuntimeMaxFileSize=10M
RuntimeMaxFiles=5
```

These bounds apply to the host journal, including other services; review them
with the operator before installation. Journald rotates/vacuums archived files;
active journal files can temporarily exceed retention targets. Neither this
example nor the node silently changes host logging policy.

`ldk_node.log` and the append-only security audit log are separate outputs, not
`node.log`; this change does not rotate or remove those files. No new log fields
are added. Backend error details are not included in readiness refusal reasons.
The logging regression test captures subprocess stdout and verifies that logging
creates no files in its working directory.
