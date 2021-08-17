# Blue Team Resources
## Resources Pertaining To...
- [Threat Intelligence](#threat-intelligence)
- [Host Security](#host-security)
- [Network Security](#network-security)
- [SIEM Technology](#siem-technology)
- [Digital Forensics](#digital-forensics)
- [Useful Articles](#useful-articles)


## Threat Intelligence
See [awesome-threat-intelligence](https://github.com/hslatman/awesome-threat-intelligence).
- [Virus Share](https://virusshare.com/) - Because Sharing is Caring
- [Virus Total](https://www.virustotal.com/gui/) - Huge database full of known hashes and known hostnames being malicious
- [Totalhash](https://totalhash.cymru.com/) - Punch in your collected atomic indicators, hashes, etc
- [Abuse IPDB](https://www.abuseipdb.com/) - Check to see if that IP is known to be malicious
- [URL Void](https://www.urlvoid.com/) - URL reputation checker
- [Central Ops](https://centralops.net/) - whois/traceroute tool
- [Kaggle](https://www.kaggle.com/c/malware-classification) - 50,000 public databases, 400,000 public notebooks
- [RITA](https://www.activecountermeasures.com/free-tools/rita/)


## Host Security

### Windows Tools
See also [awesome-windows#security](https://github.com/Awesome-Windows/Awesome#security) and [awesome-windows-domain-hardening](https://github.com/PaulSec/awesome-windows-domain-hardening).
- [Harden Windows 10](https://www.hardenwindows10forsecurity.com/) - Walkthrough of hardening windows 10 and cool tools to do so
- [Sysinternalsuite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) - Utility to harden or find bad on Windows machines ⭐
- [HardenTools](https://github.com/securitywithoutborders/hardentools) - Utility that disables a number of risky Windows features.
- [NotRuler](https://github.com/sensepost/notruler) - Detect both client-side rules and VBScript enabled forms used by the [Ruler](https://github.com/sensepost/ruler) attack tool when attempting to compromise a Microsoft Exchange server.
- [Sandboxie](https://www.sandboxie.com/) - Free and open source general purpose Windows application sandboxing utility.
- [Sigcheck](https://docs.microsoft.com/en-us/sysinternals/downloads/sigcheck) - Audit a Windows host's root certificate store against Microsoft's [Certificate Trust List (CTL)](https://docs.microsoft.com/en-us/windows/desktop/SecCrypto/certificate-trust-list-overview).
- [Sticky Keys Slayer](https://github.com/linuz/Sticky-Keys-Slayer) - Establishes a Windows RDP session from a list of hostnames and scans for accessibility tools backdoors, alerting if one is discovered.
- [Windows Secure Host Baseline](https://github.com/nsacyber/Windows-Secure-Host-Baseline) - Group Policy objects, compliance checks, and configuration tools that provide an automated and flexible approach for securely deploying and maintaining the latest releases of Windows 10.
- [WMI Monitor](https://github.com/realparisi/WMI_Monitor) - Log newly created WMI consumers and processes to the Windows Application event log.

### macOS Tools 
- [BlockBlock](https://objective-see.com/products/blockblock.html) - Monitors common persistence locations and alerts whenever a persistent component is added, which helps to detect and prevent malware installation.
- [LuLu](https://objective-see.com/products/lulu.html) - Free macOS firewall.
- [Santa](https://github.com/google/santa) - Binary whitelisting/blacklisting system for macOS.
- [Stronghold](https://github.com/alichtman/stronghold) - Easily configure macOS security settings from the terminal.
- [macOS Fortress](https://github.com/essandess/macOS-Fortress) - Automated configuration of kernel-level, OS-level, and client-level security features including privatizing proxying and anti-virus scanning for macOS.


### Threat Hunting Tools
See also [awesome-threat-detection](https://github.com/0x4D31/awesome-threat-detection) or [Lenny Zeltser's list](https://zeltser.com/lookup-malicious-websites/)
- [CimSweep](https://github.com/PowerShellMafia/CimSweep) - Suite of CIM/WMI-based tools enabling remote incident response and hunting operations across all versions of Windows.
- [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) - PowerShell module for hunt teaming via Windows Event logs.
- [GRR Rapid Response](https://github.com/google/grr) - Incident response framework focused on remote live forensics consisting of a Python agent installed on assets and Python-based server infrastructure enabling analysts to quickly triage attacks and perform analysis remotely.
- [MozDef](https://github.com/mozilla/MozDef) - Automate the security incident handling process and facilitate the real-time activities of incident handlers.
- [PSHunt](https://github.com/Infocyte/PSHunt) - PowerShell module designed to scan remote endpoints for indicators of compromise or survey them for more comprehensive information related to state of those systems.
- [PSRecon](https://github.com/gfoss/PSRecon) - PSHunt-like tool for analyzing remote Windows systems that also produces a self-contained HTML report of its findings.
- [rastrea2r](https://github.com/rastrea2r/rastrea2r) - Multi-platform tool for triaging suspected IOCs on many endpoints simultaneously and that integrates with antivirus consoles.
- [Redline](https://www.fireeye.com/services/freeware/redline.html) - Freeware endpoint auditing and analysis tool that provides host-based investigative capabilities, offered by FireEye, Inc.

## Network Security 

See also [awesome-pcaptools](https://github.com/caesar0301/awesome-pcaptools).

- [ChopShop](https://github.com/MITRECND/chopshop) - Framework to aid analysts in the creation and execution of pynids-based decoders and detectors of APT tradecraft.
- [Maltrail](https://github.com/stamparm/maltrail) - Malicious network traffic detection system.
- [Moloch](https://github.com/aol/moloch) - Augments your current security infrastructure to store and index network traffic in standard PCAP format, providing fast, indexed access ⭐
- [OwlH](https://www.owlh.net/) - Helps manage network IDS at scale by visualizing Suricata, Zeek, and Moloch life cycles.
- [Respounder](https://github.com/codeexpress/respounder) - Detects the presence of the Responder LLMNR/NBT-NS/MDNS poisoner on a network.
- [Real Intelligence Threat Analysis (RITA)](https://github.com/activecm/rita) - Open source framework for network traffic analysis that ingests Zeek logs and detects beaconing, DNS tunneling, and more.
- [Snort](https://snort.org/) - Widely-deployed, Free Software IPS capable of real-time packet analysis, traffic logging, and custom rule-based triggers.
- [SpoofSpotter](https://github.com/NetSPI/SpoofSpotter) - Catch spoofed NetBIOS Name Service (NBNS) responses and alert to an email or log file.
- [Stenographer](https://github.com/google/stenographer) - Full-packet-capture utility for buffering packets to disk for intrusion detection and incident response purposes.
- [Suricata](https://suricata-ids.org/) - Free, cross-platform, IDS/IPS with on- and off-line analysis modes and deep packet inspection capabilities that is also scriptable with Lua.
- [hadoop-pcap](https://github.com/RIPE-NCC/hadoop-pcap) - Hadoop library to read packet capture (PCAP) files.
- [Apache Spot (incubating)](https://github.com/apache/incubator-spot) - Apache Spot is open source software for leveraging insights from flow and packet analysis.
- [NetworkMiner](https://www.netresec.com/?page=networkminer) - GUI friendly application which allows you to ingest raw pcap files ⭐
- [VAST](https://github.com/tenzir/vast) - Free and open-source network telemetry engine for data-driven security investigations.
- [Wireshark](https://www.wireshark.org) - Free and open-source packet analyzer useful for network troubleshooting or forensic netflow analysis ⭐
- [Zeek](https://zeek.org/) - Powerful network analysis framework focused on security monitoring, formerly known as Bro ⭐
- [netsniff-ng](http://netsniff-ng.org/) -  Free and fast GNU/Linux networking toolkit with numerous utilities such as a connection tracking tool (`flowtop`), traffic generator (`trafgen`), and autonomous system (AS) trace route utility (`astraceroute`)

## SIEM Technology
>Security Information and Event Management
- [RockNSM](https://rocknsm.io/) - Durable Network Security Monitoring sensor built with scalability, security, and hunt-centric tactics in mind ⭐
- [HELK](https://github.com/Cyb3rWard0g/HELK) - open source hunt platforms with advanced analytics capabilities such as SQL declarative language, graphing, structured streaming, and even machine learning via Jupyter notebooks and Apache Spark over an ELK stack
- [AlienVault OSSIM](https://www.alienvault.com/open-threat-exchange/projects) - Single-server open source SIEM platform featuring asset discovery, asset inventorying, behavioral monitoring, and event correlation, driven by AlienVault Open Threat Exchange (OTX).
- [Prelude SIEM OSS](https://www.prelude-siem.org/) - Open source, agentless SIEM with a long history and several commercial variants featuring security event collection, normalization, and alerting from arbitrary log input and numerous popular monitoring tools.
- [The Hive](https://thehive-project.org/) - Scalable 4-1 IR SIEM technology that has a powerful backend for automatic alerts.
- [OpenSOC](https://github.com/OpenSOC/opensoc) - OpenSOC integrates a variety of open source big data technologies in order to offer a centralized tool for security monitoring and analysis.
- [Wazuh](https://wazuh.com/) - Wazuh is a free, open source and enterprise-ready security monitoring solution for threat detection, integrity monitoring, incident response and compliance.

## Digital Forensics
- [Awesome Forensics](https://github.com/cugu/awesome-forensics)
- [Awesome Malware Analysis](https://github.com/rshipp/awesome-malware-analysis)
- [Awesome Incident Response](https://github.com/meirwah/awesome-incident-response)
- [DFIR Training](https://www.dfir.training/tools-sw-hw)
- [This Website is Huuuuuuuuge](https://www.amanhardikar.com/mindmaps/ForensicChallenges.html)
- [Binary Ninja](https://binary.ninja/) - New type of reversing platform
- [PowerForensics](https://github.com/Invoke-IR/PowerForensics) - All in one PowerShell-based platform to perform live hard disk forensic analysis.
- [Dr Fu's Security Blog](https://fumalwareanalysis.blogspot.com/p/malware-analysis-tutorials-reverse.html)
- [Lenny Zeltser](https://zeltser.com/start-learning-malware-analysis/)
- [MalwareTech](https://www.malwaretech.com/) - The creator of WannaCry
- [binarypig](https://github.com/endgameinc/binarypig) - Scalable Binary Data Extraction in Hadoop. Malware Processing and Analytics over Pig, Exploration through Django, Twitter Bootstrap, and Elasticsearch.
### Static/ Dynamic Analysis
- [Hybrid Analysis](https://www.hybrid-analysis.com/)

## Useful Articles
- [If you've ever wanted to mess around with a SIEM](https://www.hackingarticles.in/threat-hunting-log-monitoring-lab-setup-with-elk/)
- [If you've ever wanted to mess around with a SIEMv2](https://marcusedmondson.com/2020/08/14/threat-hunting-with-jupyter-notebooks-part-1-connect-to-elasticsearch/)
- [Spin Up Active Directory Quickly](https://medium.com/@clong/introducing-detection-lab-61db34bed6ae)
- [H.O.T Security](https://www.sans.org/white-papers/35377/)
- [De-Fanging Strings with FLOSS](https://medium.com/malware-buddy/reverse-engineering-tips-strings-deobfuscation-with-floss-9424417e285d)
- [Setting up Tripwire](https://www.howtoforge.com/tutorial/monitoring-and-detecting-modified-files-using-tripwire-on-centos-7/)
- [Canary Tokens](https://blog.thinkst.com/p/canarytokensorg-quick-free-detection.html)
- [Kerboroasting](https://adsecurity.org/?p=3458)
- [Honey Files](https://docs.rapid7.com/insightidr/honey-files/)
- [Start Learning Malware Analysis](https://zeltser.com/start-learning-malware-analysis/)
- [DFRWS Papers & Presentations](https://dfrws.org/presentation/)
