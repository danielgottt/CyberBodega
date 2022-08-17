<h1 align="center"> CyberBodega </h1>
<h3 align="center">A conglomeration of resources for any color of the rainbow</h3>

```python

     _________       ______                  ________      _________                    
     __  ____/____  ____  /______________    ___  __ )___________  /___________ ______ _
     _  /    __  / / /_  __ \  _ \_  ___/    __  __  |  __ \  __  /_  _ \_  __ `/  __ `/
     / /___  _  /_/ /_  /_/ /  __/  /        _  /_/ // /_/ / /_/ / /  __/  /_/ // /_/ / 
     \____/  _\__, / /_.___/\___//_/         /_____/ \____/\__,_/  \___/_\__, / \__,_/  
             /____/                                                     /____/                                                                 

                                          Continuously Updated Since 16 July 2020

```



# 🧐 WANT TO CONTRIBUTE? <img src='https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat'/>
<p> Please do! If you have an interesting resource to share open a pull request. All I ask is that you categorize and utilize markdown to create a link with a description. I understand that there may be some crossover for specific resources, there is no reason to argue semantics </p>

<p> It should look something like this </p>

```
- [Name of Resource](Link)Description
```


# Contents
- [Quick-Links](#quick-links)
- [Infosec-News](#infosec-news)
- [Interesting-Articles](#interesting-articles)
- [Research-Resources](#research-resources)
  - [Write-ups](#write-ups)
  - [Research-Sites](#research-sites)
  - [Cyber-Threat-Intelligence-Dump](#Cyber-Threat-Intelligence-Dump)
- [Training-Resources](#training-resources)
- [Blue-Team-Resources](#blue-team-resources)
  - [Utility](#utility)
  - [Network-Analysis](#network-analysis)
  - [Host-Analysis](#host-analysis)
  - [Detection](#detection)
  - [Malware-Analysis](#malware-analysis)
    - [Malware-IOC-Detection-Data-Dumps](#malware-ioc-detection-data-dumps)
- [Purple-Red-Team-Resources](#purple-red-team-resources)
  - [Command-and-Control](#command-and-control)
  - [Recon](#recon)
  - [Password-Tools](#password-tools)
  - [bin](#bin)
- [Cloud-Things](#cloud-things)
  - [tools](#tools)
- [Awesome-Lists](#awesome-lists)
- [Dump](#dump)

## Quick-Links
- [RSS/Twitter-Feed](https://www.netvibes.com/gottcyber1#News) Conglomeration of InfoSec RSS feeds
- [TweetDeck](https://tweetdeck.twitter.com/) Twitter has useful information? YEP

## Infosec-News
- [All InfoSec News](https://allinfosecnews.com/) An InfoSec & Cyber news aggregator
- [Security Soup](https://security-soup.net/) Infosec news, commentary, and research
- [Threatpost](https://threatpost.com/) Supposedly the first stop for security news
- [Week in 4N6](https://thisweekin4n6.com/) Your weekly roundup of Digital Forensics and Incident Response news
- [r/blueteamsec](https://www.reddit.com/r/blueteamsec/) Subreddit focused on technical intelligence, research and engineering
- [Krebson Security](https://krebsonsecurity.com/)
- [SANS Webcast](https://www.sans.org/webcasts/)
- [SANS Newsletter](https://www.sans.org/newsletters/)
- [Cyber Scoop](https://www.cyberscoop.com/)
- [SecurityFocus](https://www.securityfocus.com/)
- [Gibson Research Corporation](https://www.grc.com/intro.htm)
- [Security News Wire](https://securitynewswire.com/index.php/Home)
- [PortSwigger](https://portswigger.net/daily-swig)
- [Pentestmonkey](http://pentestmonkey.net/)
- [USCERT (CISA)](https://us-cert.cisa.gov/)
- [FIRST](https://www.first.org/)
- [BleepingComputer](https://www.bleepingcomputer.com/)
- [Schneier Security](https://www.schneier.com/)

## Interesting-Articles
- [vx-underground](https://www.vx-underground.org/) Really anything from here is pretty sweet
- [Cyb3rWard0g's Lab⭐](https://cyberwardog.blogspot.com/2017/02/setting-up-pentesting-i-mean-threat.html) Step by step guide on creating a lab enviorment in ESXi
- [SANS Reading Room](https://www.sans.org/white-papers/) See what white papers are top of mind for the SANS community
- [Black Hat Archives](https://www.blackhat.com/html/archives.html) Archive of computer security presentations is provided free of charge as a service to the international computer security community
- [If you've ever wanted to mess around with a SIEM](https://www.hackingarticles.in/threat-hunting-log-monitoring-lab-setup-with-elk/)  
- [Spin Up An AD Enviorment Quickly](https://medium.com/@clong/introducing-detection-lab-61db34bed6ae) 
- [Lenny Zeltser - Learn Malware Analysis](https://zeltser.com/start-learning-malware-analysis/)
- [PST, Want a Shell?](https://www.mandiant.com/resources/pst-want-shell-proxyshell-exploiting-microsoft-exchange-servers) Mandiant's write-up for ProxyShell
- [De-Fanging Strings with FLOSS](https://medium.com/malware-buddy/reverse-engineering-tips-strings-deobfuscation-with-floss-9424417e285d) Uncovering obfuscated strings with FLOSS
- [Setting up Tripwire](https://www.howtoforge.com/tutorial/monitoring-and-detecting-modified-files-using-tripwire-on-centos-7/) Detecting adversary activity via file changes (Honey Files)
- [PowerShell Process Hunting](https://www.sans.org/blog/process-threat-hunting-part-1/) Great review of ways to leverage PowerShell to do neat things
- [Canary Tokens](https://blog.thinkst.com/p/canarytokensorg-quick-free-detection.html) Painless way to help defenders discover they've been breached
- [Kerboroasting](https://adsecurity.org/?p=3458) Conversation about extracting service account credentials from Active Directory via kerb
- [Honey Files](https://docs.rapid7.com/insightidr/honey-files/) Honey files are designed to detect attackers who are accessing and removing files
- [CTI Self Study Plan](https://medium.com/katies-five-cents/a-cyber-threat-intelligence-self-study-plan-part-1-968b5a8daf9a) Katie Nickels discusses ways you can learn more about CTI
- [Start Learning Malware Analysis](https://zeltser.com/start-learning-malware-analysis/) 
- [DFRWS Papers & Presentations](https://dfrws.org/presentation/)
- [Detecting Meterpreter HTTP module Network Traffic](https://blog.didierstevens.com/2015/05/11/detecting-network-traffic-from-metasploits-meterpreter-reverse-http-module/) Didier Stevens discusses meterpreter network traffic
- [Hunting Linux Persistence Part 1](https://www.activecountermeasures.com/hunting-for-persistence-in-linux-part-1-auditd-sysmon-osquery-and-webshells/) Auditd, Sysmon, Osquery and Webshells
- [Adventures in Dynamic Evasion](https://posts.specterops.io/adventures-in-dynamic-evasion-1fe0bac57aa)
- [SSDs/The Challanges Presented to DFIR](https://repository.stcloudstate.edu/cgi/viewcontent.cgi?article=1051&context=msia_etds) 
- [Anti-Forensics](https://resources.infosecinstitute.com/topic/anti-forensics-part-1/#gref) 
- [Windows Artifacts DFIR](https://resources.infosecinstitute.com/topic/windows-systems-and-artifacts-in-digital-forensics-part-i-registry/) 
- [Windows Forensics](https://www.forensicfocus.com/articles/windows-forensics-and-security/) 
- [Linux Forensics](http://www.deer-run.com/~hal/LinuxForensicsForNon-LinuxFolks.pdf) 
- [Black Hat Stego Brief](https://www.blackhat.com/presentations/bh-usa-04/bh-us-04-raggo/bh-us-04-raggo-up.pdf) 
- [Unpacking Malware](https://marcoramilli.com/2020/10/09/how-to-unpack-malware-personal-notes/) 
- [Malware Reports](https://www.malwarearchaeology.com/analysis) 
- [Journey Into Incident Response](https://www.malwarearchaeology.com/analysis)
- [Deploying T-Pot Framework in the Cloud](https://www.stratosphereips.org/blog/2020/10/10/installing-t-pot-honeypot-framework-in-the-cloud)
- [Getting Started with RE/Malware Analysis](https://hshrzd.wordpress.com/how-to-start/)
- [OpBlueRaven](https://threatintel.blog/OPBlueRaven-Part2/) Details about PRODAFT & INVICTUS Threat Intelligence (PTI) team’s latest operation on different threat actors
- [TrendMicro; Analyzing Common Pentesting Tools](https://www.trendmicro.com/en_us/research/22/g/analyzing-penetration-testing-tools-that-threat-actors-use-to-br.html) Gives a great insight into common abused tools
- [Hunt & Hackett; Concealed code TTP's/Detection](https://www.huntandhackett.com/blog/concealed-code-execution-techniques-and-detection) Covers common defense evasion techniques and how to detect them
- [NCC Group; Detecting DNS Implants](https://research.nccgroup.com/2022/08/11/detecting-dns-implants-old-kitten-new-tricks-a-saitama-case-study/) Interesting TTP's leveraging DNS as a pure means of C2
- [Linux to ATT&CK](https://gist.github.com/timb-machine/05043edd6e3f71569f0e6d2fe99f5e8c) Mapped markdown file listing common Linux malware TTP's mapped to ATT&CK
- [Datadog; AWS Threat Detection](https://securitylabs.datadoghq.com/articles/cyber-attack-simulation-with-stratus-red-team/) Intro to Stratus Red Team, the Atmoic red team for cloud enviorments
- [Nextron Systems; Writing YARA rules](https://www.nextron-systems.com/2015/02/16/write-simple-sound-yara-rules/) Part 1 of a 4 part series on writing effective YARA rules

## Research-Resources
### Write-ups
- [Unit 42](https://unit42.paloaltonetworks.com/)
- [Google Security Blog](https://security.googleblog.com/)
- [Trellix Blog](https://www.trellix.com/en-us/about/newsroom/stories.html)
- [The DFIR Report](https://thedfirreport.com/)
- [Sophos X-Ops](https://news.sophos.com/en-us/tag/sophos-x-ops/)
- [Intel471](https://intel471.com/blog/)

### Research-Sites
- [Exploit DB](https://www.exploit-db.com/)
- [Shodan](https://www.shodan.io/) 
- [National Vulnerability Database](https://nvd.nist.gov/)
- [CVE Proof of Concepts](https://github.com/qazbnm456/awesome-cve-poc) 
- [OWASP](https://owasp.org/projects/) 
- [OSINT Framework](https://osintframework.com/)
- [OpenThreatResearch](https://blog.openthreatresearch.com/)
- [BellingCat](https://www.bellingcat.com/) 
- [Zoomeye](https://www.zoomeye.org/) 
- [Spyse](https://spyse.com/) 

### Cyber-Threat-Intelligence-Dump
- [Unit 42 Atom](https://unit42.paloaltonetworks.com/atoms/) Threat group information
- [CrowdStrike Adversary](https://adversary.crowdstrike.com/en-US/) APT/Adversary group list
- [SOC Radar](https://labs.socradar.com/apt-feeds/) APT IoC feeds from several public and private sources and sensors
- [APT Campaigns](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections) Collection of APT and cybercriminals campaign
- [Yet Another Google Doc.1](https://docs.google.com/spreadsheets/u/0/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/pubhtml) APT Groups and Operations
- [Yet Another Google Doc.2](https://docs.google.com/document/u/1/d/e/2PACX-1vR2TWm68bLidO3e2X0wTCqs0609vo5RXB85f6VL_Zm79wtTK59xADKh6MG0G7hSBZi8cPOiQVWAIie0/pub) Raw intel dump into a word doc
- [Cyber Campaigns](http://www.cybercampaigns.net/) List of multiple cyber-espionage and cyber-attack campaigns
- [APT Secure List](https://apt.securelist.com/) Targeted cyberattack logbook
- [Dragos Threat Activity](https://www.dragos.com/threat-activity-groups/) Dragos threat activity groups
- [Google Threat Analysis](https://blog.google/threat-analysis-group/) Googles TAG (Threat analysis group) 
- [Microsoft Threat Intel](https://www.microsoft.com/security/blog/microsoft-security-intelligence/) Microsoft threat intel team
- [APT Map](https://github.com/andreacristaldi/APTmap) Graphical map of known Advanced Persistent Threats
- [MITRE APT Groups](https://attack.mitre.org/groups/) MITRE attack groups
- [APT Netlify](https://aptmap.netlify.app/) Yet another threat actor map
- [Alienvault OTX Groups](https://otx.alienvault.com/browse/global/adversaries?include_inactive=0&sort=-modified&page=1) AlienVault open threat exchange
- [Unit 42 Playbooks](https://pan-unit42.github.io/playbook_viewer/) Playbooks for certain threat groups

## Training-Resources
- [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/) BlueYard - BlueTeam Challenges
- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/) Infected PCAP's for review
- [EVTX/PCAP Attack Samples](https://github.com/sbousseaden/) Infected PCAP's and EVTX logs for review
- [Open Security Training](https://opensecuritytraining.info/Training.html) Free training for a variety of computer security classes
- [TryHackMe](https://tryhackme.com/) Hands-on cyber security training
- [HackSplaining](https://www.hacksplaining.com/lessons) Number of free training lessons for free
- [Codewars](https://www.codewars.com/) Programming challanges
- [MalwareUnicorn](https://malwareunicorn.org/#/workshops) Free reverse engineering workshops
- [Free Ivy Leauge Courses](https://www.freecodecamp.org/news/ivy-league-free-online-courses-a0d7ae675869/) List of Ivy league courses you can take online for free (CS50)
- [LetsDefend](https://letsdefend.io/) Free-ish training simulating the SOC life. Great for people interested in journying into a IR/SOC enviorment  
- [DC540 Reversing Course](https://github.com/sharpicx/reversing-course) Free reverse engineering course
- [Low Level Programming](https://github.com/sharpicx/lowlevel-programming) Low level programming course
- [FreeCodeCamp](https://www.freecodecamp.org/) Free and online, self paced courses to prepare you for a role in programming
- [SocVel](https://www.socvel.com/challenges/) Free live DFIR challenges

## Blue-Team-Resources
- [EricZimmerman](https://github.com/EricZimmerman)
### Utility
- [Cyber Chef](https://gchq.github.io/CyberChef/) Web app for analysing and decoding data
- [LOLBAS](https://lolbas-project.github.io/) Windows LOLBins and how they are abused
- [GTFOBins](https://gtfobins.github.io/) Unix LOLBins and how they are abused
- [MITRE ATT&CK](https://attack.mitre.org/) Globally-accessible knowledge base of adversary tactics and techniques
- [MITRE D3FEND](https://d3fend.mitre.org/) Knowledge graph of countermeasures to ATT&CK TTP's
- [Wazuh](https://wazuh.com/) Open source unified XDR and SIEM protection for endpoints and cloud workloads
- [MozDef](https://github.com/mozilla/MozDef) Enterprise defense platform
- [Stronghold](https://github.com/alichtman/stronghold) A way to securely configure your Mac
- [ChopShop](https://github.com/MITRECND/chopshop) Framework to aid analysts in the creation and execution of pynids based decoders and detectors of APT tradecraft
- [RockNSM](https://rocknsm.io/) An open source Network Security Monitoring platform
- [HELK](https://github.com/Cyb3rWard0g/HELK) Open source hunt platforms with advanced analytics
- [AlienVault OSSIM](https://www.alienvault.com/open-threat-exchange/projects) Feature-rich open source SIEM w/ collection, normalization and correlation
- [Prelude](https://www.prelude-siem.org/) Universal SIEM
- [TheHive](https://thehive-project.org/) Open source and free Security Incident Response Platform
- [OpenEDR](https://github.com/ComodoSecurity/openedr) Free and open source EDR
- [OpenSOC](https://github.com/OpenSOC/opensoc) Open source big data technologies in order to offer a centralized tool for security monitoring and analysis
- [Munin](https://github.com/Neo23x0/munin) Online Hash Checker for Virustotal and Other Services
- [Threat Hunt Mind Maps](https://github.com/christophetd/mindmaps) Mindmaps for cloud security, threat hunting and incident response
- [Hybrid-Analysis](https://www.hybrid-analysis.com/) Free malware analysis service
- [Manalyzer](https://www.manalyzer.org/) Free service which performs static analysis on PE executables to detect undesirable behavior
- [URLScan](https://urlscan.io/) Free URL/website scanner
- [Intezer Analyze](https://analyze.intezer.com/) Free IOC/malware scanner
- [AnyRun](https://app.any.run/) Interactive malware analysis
- [JoeSandbox](https://www.joesandbox.com/#windows) Malware anaylsis
- [IRIS-H](https://iris-h.services/pages/dashboard#/pages/dashboard) Online automated static analysis of files stored in a directory-based or strictly structured formats
- [Yoroi](https://yomi.yoroi.company/upload) Free file analyzer
- [Har-Sai](https://har-sia.info/index-en.html) Lookup things related to a specific CVE
- [Rastrea2r](https://github.com/rastrea2r/rastrea2r) Multi-platform open source tool that allows incident responders and SOC analysts to triage suspect systems and hunt for Indicators of Compromise (IOCs) across thousands of endpoints in minutes
- [HijackLibs](https://github.com/wietze/hijacklibs) Aims to keep a record of publicly disclosed DLL Hijacking opportunities
- [Diaphore](https://github.com/joxeankoret/diaphora) Program diffing tool working as an IDA plugin

### Network-Analysis
- [Arkime](https://github.com/arkime) Open source full packet capturing, indexing and database system. It rebuilds sessions automatically!
- [Wireshark](https://www.wireshark.org/) Tride and true network protocol analyzer
- [Zeek](https://zeek.org/) An Open Source Network Security Monitoring Tool
- [Google Stenographer](https://github.com/google/stenographer) Stenographer is a full-packet-capture utility for buffering packets to disk. Allows you to rip out 
- [PcapXray](https://github.com/Srinivas11789/PcapXray) A tool to visualize Packet Capture offline as a Network Diagram
- [RITA](https://www.activecountermeasures.com/free-tools/rita/) Open-source framework for detecting command and control communication through network traffic analysis
- [Whats that C2/Exfil?](https://github.com/silence-is-best/c2db) Github repo full of known c2 and exfil traffic keywords 
- [Incubating](https://github.com/apache/incubator-spot) Open source software for leveraging insights from flow and packet analysis
- [Network Miner](https://www.netresec.com/?page=networkminer) Open source Network Forensic Analysis Tool
- [VAST](https://github.com/tenzir/vast) Network telemetry engine for data-driven security investigations
- [NetSniff](http://netsniff-ng.org/) Free Linux networking toolkit
- [SpoofSpotter](https://github.com/NetSPI/SpoofSpotter) A tool to catch spoofed NBNS responses
- [Grass Marlin🦅](https://github.com/nsacyber/GRASSMARLIN) Network situational awareness of ICS and SCADA networks
- [SELKS](https://github.com/StamusNetworks/SELKS) Open source Debian-based IDS/IPS/Network Security Monitoring platform
- [SiLK](https://tools.netsa.cert.org/silk/) Collection of traffic analysis tools

### Host-Analysis
- [Volatility](https://github.com/volatilityfoundation/volatility) Python tool used for the extraction of digital artifacts from volatile memory (RAM) samples
- [Velociraptor](https://github.com/Velocidex/velociraptor) Tool for collecting host based state information using The Velociraptor Query Language (VQL) queries
- [Hayabusa](https://github.com/Yamato-Security/hayabusa) Windows event log fast forensics timeline generator and threat hunting tool (Sigma compatible)
- [Osquery](https://osquery.io/) Tool that provides performant endpoint visibility
- [Sysinternalsuite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) Suite of tools providing a multitude of capabiltiies for defenders or attackers
- [Sticky Keys Slayer](https://github.com/linuz/Sticky-Keys-Slayer) Scans for accessibility tools backdoors via RDP
- [CimSweep](https://github.com/PowerShellMafia/CimSweep) Suite of CIM/WMI-based tools that enable the ability to perform incident response and hunting operations remotely
- [Seatbelt](https://github.com/GhostPack/Seatbelt) Security oriented host-survey tool performing "safety checks" relevant from both offensive and defensive security perspectives
- [Live-Forensicator](https://github.com/Johnng007/Live-Forensicator) Assist's responders in carrying out live forensic investigations
- [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) PowerShell Module for Threat Hunting via Windows Event Logs
- [Chainsaw](https://github.com/countercept/chainsaw) Powerful ‘first-response’ capability to quickly identify threats within Windows event logs
- [Google Rapid Response](https://github.com/google/grr) Python agent that is installed on target systems, and python server infrastructure that can manage and talk to clients
- [PSHunt](https://github.com/Infocyte/PSHunt) Powershell Threat Hunting Module designed to scan remote endpoints
- [PSRecon](https://github.com/gfoss/PSRecon) Gathers data from a remote Windows host using PowerShell
- [Redline](https://fireeye.market/apps/211364) Free EDR, thats pretty cool
- [Power Forensics](https://github.com/Invoke-IR/PowerForensics) Inclusive framework for hard drive forensic analysis
- [Block Parse](https://github.com/matthewdunwoody/block-parser) PowerShell script block parser
- [Sysmon4Linux](https://github.com/Sysinternals/SysmonForLinux) The sysmon you love for a flavor of nix


### Detection
- [Sigma](https://github.com/SigmaHQ/sigma/blob/master/README.md) Sigma is a generic and open signature format that allows you to describe relevant log events in a straightforward manner
- [Yara](https://yara.readthedocs.io) Tool aimed at (but not limited to) helping malware researchers to identify and classify malware samples
- [Snort](https://snort.org/) Open source intrusion prevention and detection system
- [Suricata](https://suricata.readthedocs.io) High performance Network IDS, IPS and Network Security Monitoring engine
- [BlockBlock](https://objective-see.com/products/blockblock.html) Monitors common persistence locations and alerts whenever a persistent component is added
- [Santa](https://github.com/google/santa) Binary authorization system for macOS
- [MalTrail](https://github.com/stamparm/maltrail) Malicious traffic detection system

### Malware-Analysis
- [Remnux](https://remnux.org/)
- [Tools by hasherezade](https://hasherezade.github.io/) Linux toolkit for reverse-engineering and analyzing malicious software
- [IDA](https://hex-rays.com/ida-free/) Binary code analysis tool
- [FLARE Floss](https://github.com/mandiant/flare-floss) Automatically deobfuscate strings from malware binaries
- [BinaryNinja](https://binary.ninja/) Interactive disassembler, decompiler, and binary analysis platform
- [BinaryPig](https://github.com/endgameinc/binarypig) Malware Processing and Analytics
- [Ghidra🦅](https://ghidra-sre.org/) Software reverse engineering suite of tools
- [HxD](https://mh-nexus.de/en/hxd/) Carefully designed and fast hex editor 
- [Redare2](https://github.com/radareorg/radare2) Set of libraries, tools and plugins to ease reverse engineering tasks
- [TheMatrix](https://github.com/enkomio/thematrix) Project created to ease the malware analysis process
- [OllyDbg](https://www.ollydbg.de/) 32-bit assembler level analysing debugger
- [oletools](https://github.com/decalage2/oletools) Package of python tools to analyze files
- [The Sleuth Kit/Autopsy](https://www.sleuthkit.org/) Open Source Digital Forensics
- [Cuckoo Sandbox](https://cuckoosandbox.org/) Leading open source automated malware analysis system
- [Malcat](https://malcat.fr/) Feature-rich hexadecimal editor / disassembler for Windows and Linux

#### Malware-IOC-Detection-Data-Dumps
- [vx-underground samples](https://samples.vx-underground.org/samples/Families/) The largest collection of malware source code, samples, and papers on the internet
- [jstrosch Samples](https://github.com/jstrosch/malware-samples) Repository intended to provide access to a wide variety of malicious files and other artifacts
- [DigitalSide Threat-Intel Repo](https://osint.digitalside.it/) Repository that contains a set of Open Source Cyber Threat Intellegence information
- [MalwareBazar](https://bazaar.abuse.ch/browse/) Project from abuse.ch with the goal of sharing malware samples
- [DailyIOC](https://github.com/StrangerealIntel/DailyIOC) Analysis of malware and Cyber Threat Intel of APT and cybercriminals groups
- [Valhalla Yara Rules](https://valhalla.nextron-systems.com/)
- [Yara Rules Project](https://github.com/Yara-Rules)
- [Virustotal Yara](https://github.com/VirusTotal/yara)
- [Florian Roth](https://github.com/Neo23x0/signature-base)

## Purple-Red-Team-Resources
- [Metasploit Framework](https://github.com/rapid7/metasploit-framework) An exploit framework
- [APTSimulator](https://github.com/NextronSystems/APTSimulator) A Windows Batch script that creates files to make a system look as if it was compromised
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team/) Library of tests mapped to the MITRE ATT&CK® framework
- [Metta](https://github.com/uber-common/metta) Adversary simulation tool
- [Network Flight Simulator](https://github.com/alphasoc/flightsim) Lightweight utility used to generate malicious network traffic
- [Cladera Framework](https://github.com/mitre/caldera) Platform designed to easily automate adversary emulation, assist manual red-teams, and automate incident response
- [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) Collection of Microsoft PowerShell module's to aid in multiple phases of an assessment
- [Impacket](https://github.com/SecureAuthCorp/impacket) Impacket is a collection of Python classes for working with network protocols
- [sqlmap](https://github.com/sqlmapproject/sqlmap) Open source tool that automates the process of detecting and exploiting SQL injection flaws
- [Silver](https://github.com/BishopFox/sliver) Open source cross-platform adversary emulation/red team framework
- [Gobuster](https://github.com/OJ/gobuster) Gobuster is a tool used to brute-force subdomains, website URI's, open S3 buckets and more
- [Exegol](https://github.com/ShutdownRepo/Exegol) Exegol is a community-driven hacking environment, powerful and yet simple enough to be used by anyone in day to day engagements
- [EmpireProject](https://github.com/EmpireProject) Empire is a post-exploitation framework, which is sadly not maintained anymore
- [Reubeus](https://github.com/GhostPack/Rubeus) Rubeus is a C# toolset for raw Kerberos interaction and abuses
- [Responder](https://github.com/lgandx/Responder) Responder is an LLMNR, NBT-NS and MDNS poisoner
- [Inveigh](https://github.com/Kevin-Robertson/Inveigh) Inveigh is a cross-platform .NET IPv4/IPv6 machine-in-the-middle tool for penetration testers
- [ExploitDB](https://github.com/offensive-security/exploitdb) Archive of public exploits and corresponding vulnerable software
- [DumpsterFire](https://github.com/TryCatchHCF/DumpsterFire) Tool used for building repeatable, time-delayed, and distributed security events
- [Stratus Red Team](https://stratus-red-team.cloud/) Essentially Atmoic red team, but focused on cloud

### Command-and-Control
- [C2 Matrix](https://www.thec2matrix.com/matrix) Find the best C2 framework for your needs based on your target environment
- [Cobalt Strike](https://www.cobaltstrike.com/) Post-exploitation agent and covert channels to emulate a quiet long-term embedded actor in your customer’s network
- [Brute Ratel C4](https://bruteratel.com/) Customized Command and Control Center for Red Team and Adversary Simulation
- [PoshC2](https://github.com/nettitude/PoshC2) Proxy aware C2 framework

### Recon
- [Photon Crawler](https://github.com/s0md3v/Photon) Incredibly fast crawler designed for OSINT
- [Subcrawl](https://github.com/hpthreatresearch/subcrawl) Developed to find, scan and analyze open directories
- [MASSCAN](https://github.com/robertdavidgraham/masscan) An Internet-scale port scanner
- [Nmap](https://nmap.org/) Open source utility for network discovery and security auditing
- [Angry IP Scanner](https://angryip.org/) Fast and friendly network scanner
- [Google Dorking](https://www.exploit-db.com/google-hacking-database) Technique that uses Google Search and other Google applications to find security holes
- [Github Dorking](https://github.com/techgaun/github-dorks) Technique that uses Github to find interesting things
- [Shoder](https://github.com/idanbuller/IP-Tools/blob/master/shoder.py) PoC leveraging shodan's pythons library

### Password-Tools
- [Cain & Abel](https://web.archive.org/web/20160214132154/http://www.oxid.it/cain.html) Password recovery tool for Microsoft Operating Systems
- [Hashcat](https://hashcat.net/hashcat/) Advanced password recovery tool for most operating systems
- [John](https://www.openwall.com/john/) Open Source password security auditing and password recovery tool
- [Mimikatz](https://github.com/ParrotSec/mimikatz) Extract plaintexts passwords, hashs, PIN codes and kerberos tickets from memory

### bin
- [NYAN-x-CAT Repo](https://github.com/NYAN-x-CAT)
- [Sulealothman Repo](https://github.com/sulealothman/MysteryLegacyPenetrationTools)
- [Matterpreter Repo](https://github.com/matterpreter?tab=repositories)

## Cloud-Things
- [Azure AD IR Guide](https://misconfig.io/azure-ad-incident-response-life-cycle-tools/)

### Tools
- [Basic Blob Finder](https://github.com/joswr1ght/basicblobfinder) POC tool to hunt for public Azure storage containers and enumerate the blobs
- [TeamFiltration](https://github.com/Flangvik/TeamFiltration) Framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts


## Awesome-Lists
- [Master List of all Awesome Distros](https://github.com/sindresorhus/awesome)
- [Awesome Threat Detection and Hunting](https://github.com/0x4D31/awesome-threat-detection)
- [Awesome Threat Intelligence](https://github.com/hslatman/awesome-threat-intelligence)
- [Awesome Malware Analysis](https://github.com/rshipp/awesome-malware-analysis)
- [Awesome PCAP Tools](https://github.com/caesar0301/awesome-pcaptools)
- [Awesome Threat Modeling](https://github.com/redshiftzero/awesome-threat-modeling)
- [Awesome CTF](https://github.com/apsdehal/awesome-ctf)
- [Awesome Cyber Skills](https://github.com/joe-shenouda/awesome-cyber-skills)
- [Awesome Personal Security](https://github.com/Lissy93/personal-security-checklist)
- [Awesome Hacking](https://github.com/carpedm20/awesome-hacking)
- [Awesome Honeypots](https://github.com/paralax/awesome-honeypots)
- [Awesome Pentest Tools](https://github.com/enaqx/awesome-pentest)
- [Awesome Pentest Cheat Sheets](https://github.com/coreb1t/awesome-pentest-cheat-sheets)
- [Awesome Incident Response](https://github.com/meirwah/awesome-incident-response)
- [Awesome Web Hacking](https://github.com/infoslack/awesome-web-hacking)
- [Awesome Hacking](https://github.com/carpedm20/awesome-hacking)
- [Awesome Industrial Control System Security](https://github.com/mpesen/awesome-industrial-control-system-security)
- [Awesome YARA](https://github.com/InQuest/awesome-yara)
- [Awesome Container Security](https://github.com/kai5263499/container-security-awesome)
- [Awesome Crypto Papers](https://github.com/pFarb/awesome-crypto-papers)
- [Awesome Shodan Search Queries](https://github.com/jakejarvis/awesome-shodan-queries)
- [Awesome Anti Forensics](https://github.com/remiflavien1/awesome-anti-forensic)
- [Awesome Security Talks and Videos](https://github.com/PaulSec/awesome-sec-talks)

## Dump
- [Pexpect](https://github.com/pexpect/pexpect) Python module for spawning child applications; controlling them; and responding to expected patterns in their output
- [Unofficial OSCP Tool Distro](https://falconspy.medium.com/unofficial-oscp-approved-tools-b2b4e889e707)
- [Florian Roth's BlueLedger](https://github.com/Neo23x0/BlueLedger) A list of some interesting community support projects
- [Clair](https://github.com/quay/clair) Open source project for the static analysis of vulnerabilities in application containers
- [Chef InSpec](https://www.inspec.io/?azure-portal=true) Audit and automated testing framework
- [Lynis](https://cisofy.com/lynis/) Security auditing tool for *nix and macOS
- [CIS CAT](https://github.com/CISecurity/SecureSuiteResourceGuide/blob/master/docs/CIS-CAT/CIS-CATAssessorGuide.md)






