# SOAR Integration (Shuffle) and Detection Engineering Lessons Learned

## 1. Alert pipeline

```
Wazuh Manager --(integration block, level >= 7)--> Shuffle webhook --> Http node --> Slack #soc-alerts
```

Shuffle runs on the CTI laptop in Docker (WSL2). Wazuh runs on the desktop. They communicate over the home LAN: a Windows port proxy forwards port 3001 to the WSL2 address, and a firewall rule allows it.

Wazuh side (`/var/ossec/etc/ossec.conf`):

```xml
<integration>
  <name>shuffle</name>
  <hook_url>http://LAPTOP_IP:3001/api/v1/hooks/WEBHOOK_ID</hook_url>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

Shuffle Http node: `POST` to the Slack incoming webhook with header `Content-Type: application/json` and this body:

```json
{
  "text": "*Wazuh Alert*\n*Rule:* $exec.all_fields.rule.id - $exec.all_fields.rule.description\n*Level:* $exec.all_fields.rule.level\n*Agent:* $exec.all_fields.agent.name\n*Log:* $exec.all_fields.full_log"
}
```

Wazuh's built-in Shuffle integration nests the original alert under `all_fields`, so the path is `$exec.all_fields.rule.id`, not `$exec.rule.id`. This was found by temporarily sending `{"text": "$exec"}` and reading the raw payload in Slack.

Secrets (Slack webhook URL, Shuffle credentials) are kept out of this repository.

### Shuffle deployment issues

- **Orborus swarm error** (`network shuffle_swarm_executions not found`): Docker is not in swarm mode. Set `SHUFFLE_SWARM_CONFIG=` (empty) in `docker-compose.yml` and recreate the `orborus` service.
- **OpenSearch bind-mount error** after a Docker Desktop restart: `docker compose down`, remove the `shuffle-database` volume, `chown -R 1000:1000 shuffle-database`, `docker compose up -d`. The workflow trigger survives, and the Http node configuration should be checked afterwards.
- `vm.max_map_count=262144` must be set again after every WSL restart.
- OpenCTI, MISP and Shuffle cannot all run at once within a 10 GB WSL memory limit. OpenCTI and MISP have `restart: always`, so they must be stopped before starting Shuffle.

## 2. Detection engineering lessons learned

These were found while trying to get a live alert from the pfSense-to-Wazuh rules (100020-100025).

1. **`xmllint` was a false alarm.** It reports "extra content" for multiple top-level `<group>` blocks, but Wazuh accepts them. `wazuh-analysisd -t` and `ossec.log` showed no rule loading errors. Use Wazuh's own tools for validation.
2. **pfSense does not log `pass` rules by default.** Traffic allowed by a rule without "Log packets" enabled never reaches `filter.log`, so Wazuh cannot see it.
3. **`syslogd` on pfSense can stop forwarding while the process stays alive.** `service syslogd restart` fixed it. Confirm with `tcpdump -i any -n udp port 514` on the manager.
4. **Live pfSense syslog has no hostname field**: `<134>Sep 27 18:17:12 filterlog[PID]: ...`. A hand-written test line containing `pfSense` as the hostname is not representative. Always test with the exact bytes captured by `tcpdump -A`.
5. **A broken stock decoder can capture your logs.** The FreePBX decoder (`0495-freepbs_decoders.xml`) matched hostname-less filterlog lines before the pfSense decoders. It was excluded with `decoder_exclude` and `rule_exclude` (`0715-freepbx_rules.xml`), after which the custom `pfsense-filterlog` decoder matched. The rules' `decoded_as` must match the decoder that actually wins, which is confirmed in logtest Phase 2.
6. **Open issue: ICMP lines.** The custom `pfsense-filterlog-ip4` child decoder expects numeric source and destination ports after the destination IP. ICMP lines contain text there (`request`), so the child decoder is expected not to extract `dstip` for ICMP. This comes from reading the regex and was not confirmed live. A fix would add a separate ICMP child decoder.
7. **Open issue: live end-to-end test for 100022/100023** was not completed. `wazuh-logtest` also hung during the last attempts, and the cause was not found.

## 3. Known tuning items

- Rule 510 (rootcheck "Generic" signature) produces a burst of level 7 alerts on every manager restart, which floods Slack. Raise the integration level or exclude the rule.
- The MITRE field in the Slack message shows raw lists. Use `.0` on `rule.mitre.technique` and `rule.mitre.id` to take the first element.
- Known false positives: rule 92213 (`__PSScriptPolicyTest_*.ps1` created by PowerShell itself) and rule 61634 (`backgroundTaskHost.exe` from the Your Phone app).
