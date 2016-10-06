# Graylog-Juniper-RFC-3164-GrokPattern
This extractor is designed for Juniper JunOS devices using "default-log-log" (RFC 3164 compliant) logging.

## Example Juniper JunOS traffig logs
Nov 4 16:23:09 cixi RT_FLOW : RT_FLOW_SESSION_CREATE: session created 50.0.0.100/24065->30.0.0.100/768 icmp 50.0.0.100/24065->30.0.0.100/768 None None 1 alg-policy untrust trust 100000165 N/A(N/A) reth2.0 UNKNOWN UNKNOWN UNKNOWN

## Grok extractor
grok_pattern: %{WORD:state}: session closed %{WORD:reason}: %{IP:src_addr}/%{NUMBER:src_port}->%{IP:dst_addr}/%{NUMBER:dst_port} %{WORD:service} %{IP:src_addr_nat}/%{NUMBER:src_port_nat}->%{IP:dst_addr_nat}/%{NUMBER:dst_port_nat} %{WORD:src_nat_rule} %{WORD:dst_nat_rule} %{NUMBER:proto_id} %{WORD:policy} %{WORD:src_zone} %{WORD:dst_zone} %{NUMBER:session_id} %{NUMBER}\(%{NUMBER}\) %{NUMBER}\(%{NUMBER}\) %{NUMBER} %{WORD:application} %{WORD:nested-application} %{WORD}\(%{WORD}\) %{WORD:interface}
