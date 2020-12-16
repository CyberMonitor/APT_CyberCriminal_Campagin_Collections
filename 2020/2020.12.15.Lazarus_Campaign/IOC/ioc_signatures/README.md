# HvS IOC Signatures

## Purpose
Since HvS-Consulting is handling incidents for multiple years now, we collect sets of IOCs - mainly YARA rules - on a regular basis. Occasionally also sets are created by our team due to internal research. In order to help the community with **Threat Hunting** and **Incident Response**, we would like to share selected sets of IOCs from time to time in this repository. These IOCs have great value for threat hunting or the improvement of security monitoring within organizations.

Even if we try to avoid false positives by manual QA, those rules are not meant to be used in production without previous dry runs.

## Structure

As we focus on hunting and specific threat actors, we decided to create a directory per actor, containing various common IOC types like:
- YARA Rules* to find indicators in files, registry entries, event log messages, process memory, ... 
- CSV files with indicators including some context which should increase actionability in case of matches
- Lists e.g. of malicious IPs and Domains

\* Some rules might require [THORs](https://www.nextron-systems.com/thor/) or [LOKIs](https://github.com/Neo23x0/Loki) extensions of YARA to be fully supported.


## FAQ

### Is there a scheduled update interval of IOCs
No we release new IOCs only occasionally.

### How should false positives be reported?
You can just use the issues section of this repository.

### I want to know more about HvS-Consulting AG
More information can be found at our website [https://www.hvs-consulting.de](https://www.hvs-consulting.de)


## License

![Creative Commons License](https://i.creativecommons.org/l/by-nc/4.0/88x31.png)

All IOC sets, YARA rules and other information in this repository, except created by 3rd parties, are licensed under the [Creative Commons Attribution-NonCommercial 4.0 International License](http://creativecommons.org/licenses/by-nc/4.0/).