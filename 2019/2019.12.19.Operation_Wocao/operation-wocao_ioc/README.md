Operation Wocao - Indicators of Compromise
==========================================

This repository contains the indicators of compromise related to the Operation Wocao report.

> Operation Wocao (我操, “Wǒ cāo”, used as “shit” or “damn”) is the name that Fox-IT uses to describe the hacking activities of a Chinese based hacking group. 

The full report can be found here:

 * [https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/](https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/)

### Available IOCs
| Filename                          | Description                                                                   |
|-----------------------------------|-------------------------------------------------------------------------------|
| [ips.txt](ips.txt)                | The various IPs obversed, either as C2 or as operator IPs.                    |
| [hashes.txt](hashes.txt)          | The hashes for various malicious scripts and binaries.                        |
 
### Available signatures
| Filename                          | Description                                                                   |
|-----------------------------------|-------------------------------------------------------------------------------|
| [yara.yar](yara.yar)              | Contains Yara signatures to detect various malicious scripts and binaries.    |
| [suricata.rules](suricata.rules)  | Contains Suricata signatures to detect XServer and other malicious traffic.   |

### Context for IP addresses
| IP                | Hoster                | Active period | Description |
|-------------------|-----------------------|---------------|-------------|
| 185.244.150.236   | Host Sailor           | 2018          | Identified in the memory dump of a compromised machine. Used as a command line argument for a PowerShell backdoor. Also used to access webshells. |
| 217.182.129.156   | OVH                   | 2018-2019     | Back-connect used by the agent backdoor. Identified based on compromised machines connecting to this IP with a known suspicious client hello value in the TLS handshake. IP is hardcoded. |
| 23.254.211.108    | Hostwinds             | 2018-2019     | Used to connect to a VPN concentrator with stolen credentials. |
| 108.61.179.160    | Choopa / Vultr        | 2018-2019     | Used to connect to a VPN concentrator with stolen credentials. |
| 198.46.140.26     | ColoCrossing          | 2018-2019     | Used to connect to a VPN concentrator with stolen credentials. |
| 31.222.185.215    | Rackspace             | 2018-2019     | Used to access webshells. |
| 45.77.229.10      | Choopa / Vultr        | 2018-2019     | Used to access webshells. |
| 46.101.153.58     | Digital Ocean         | 2018-2019     | Used to access webshells. |
| 62.141.37.236     | myLoc                 | 2018-2019     | Used to access webshells. |
| 95.179.161.243    | Vultr                 | 2018-2019     | Used to access webshells. |
| 138.68.144.161    | Digital Ocean         | 2018-2019     | Used to access webshells. |
| 185.191.228.108   | Cogent Communications | 2018-2019     | Used to access webshells. |
| 209.97.140.206    | Alameda               | 2018-2019     | Used to access webshells. |
| 46.182.106.190    | _Tor exit node_       | *             | Used to access webshells. |
| 141.255.162.36    | _Tor exit node_       | *             | Used to access webshells. |
| 185.220.101.0     | _Tor exit node_       | *             | Used to access webshells. |