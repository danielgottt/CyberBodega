
                      _______     ______  ______ _____        ____   ____  _____  ______ _____          
                     / ____\ \   / /  _ \|  ____|  __ \      |  _ \ / __ \|  __ \|  ____/ ____|   /\    
                    | |     \ \_/ /| |_) | |__  | |__) |     | |_) | |  | | |  | | |__ | |  __   /  \   
                    | |      \   / |  _ <|  __| |  _  /      |  _ <| |  | | |  | |  __|| | |_ | / /\ \  
                    | |____   | |  | |_) | |____| | \ \      | |_) | |__| | |__| | |___| |__| |/ ____ \ 
                     \_____|  |_|  |____/|______|_|  \_\     |____/ \____/|_____/|______\_____/_/    \_\
>A collection of awesome resources, tools, and opportunities for defensive cyberspace operations

[Cybersecurity blue teams](https://en.wikipedia.org/wiki/Blue_team_(computer_security)) are groups of individuals who identify security flaws in information technology systems, verify the effectiveness of security measures, and monitor the systems to ensure that implemented defensive measures remain effective in the future. While not exclusive, this list is heavily biased towards [Free Software](https://www.gnu.org/philosophy/free-sw.html) projects and against proprietary products or corporate services. For offensive TTPs, please see [awesome-pentest](https://github.com/fabacab/awesome-pentest).

## Table Of Contents

- [Setup](#setup)
  - [Virtual Machine Applications](#virtual-machine-applications)
  - [Virtual Machine Resources](#virtual-machine-resources)
  - [CTF Websites and Wargames](#ctf-websites-and-wargames)
  - [Resources](#resources)
  - [Simulation Training](#simulation-training)
  - [Malware Databases](#malware-databases-and-cyber-news)
  - [Cyber Resources and News](#cyber-resources-and-news)
  - [Threat Intelligence](#threat-intelligence)
  - [Websites Providing Cyber Training](#websites-providing-cyber-training)
  - [macOS-based Defense](#macOS-based-defenses)
  - [Windows-based Defense](#Windows-based-defenses)
  - [Network Security Monitoring](#network-security-monitoring)
  - [Security Information and Event Management](#security-information-and-event-management)
  - [Open Source System Administrator Tools](#Open-Source-System-Administrator-Tools)
  - [Threat hunting tools](#Threat-hunting-tools)
  - [Docker Images for Penetration Testing & Security](#Docker-Images-for-Penetration-Testing-&-Security)
  - [Big Data](#Big-Data)
  - [Digital Forensics](#Digital-Forensics)
  - [Cyber Security Books](#Cyber-Security-Books)
  - [Other Security Awesome Lists](#Other-Security-Awesome-Lists)
  
# Setup
>Tools used to create/attempt CTF challenges

## Virtual machine Applications
- [Oracle VM VirtualBox](https://www.virtualbox.org/) - Oracle VM VirtualBox is a free and open-source hosted hypervisor
- [VMware Workstation 15](https://www.vmware.com/products/workstation-player/workstation-player-evaluation.html) - VMware Workstation is a hosted hypervisor that runs on x64 versions of Windows and Linux operating systems
- [VMware Fusion](https://www.vmware.com/products/fusion/fusion-evaluation.html) - VMware Fusion is a software hypervisor developed by VMware for Macintosh computers.
- [VMWare ESXi](https://www.vmware.com/products/esxi-and-esx.html) - VMware ESXi is an enterprise-class, type-1 hypervisor developed by VMware for deploying and serving virtual computers.
- [Docker](https://www.docker.com/products/docker-desktop) - Docker is a set of platform as a service products that uses OS-level virtualization to deliver software in packages called containers 
- [Kubernetes](https://kubernetes.io/) - An open-source system for automating deployment, scaling, and management of containerized applications

## Virtual Machine Resources
- [Windows 10](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/quick-start/enable-hyper-v) - Pretty self explanatory
- [Kali Linux](https://www.kali.org/downloads/) - If you want to be a l33t h@ck3r
- [Parrot](https://parrotlinux.org/) - Another pentesting toolkit
- [Metasploitable](https://sourceforge.net/projects/metasploitable/files/Metasploitable2/) - A very vulnerable machine to test your payloads on
- [SIFT](https://digital-forensics.sans.org/community/downloads) - SANS DFIR virtual machine
- [Tsuruigi](https://tsurugi-linux.org/) - An aditional DFIR virtual machine
- [Any Linux Flavor](https://www.linux.org/pages/download/) - Click here to find any flavor of linux
- [VulnHub](https://www.vulnhub.com/) - A website dedicated to custom virtual machines to pwn
- [RedHunt OS](https://github.com/redhuntlabs/RedHunt-OS) - Ubuntu-based Open Virtual Appliance (`.ova`) preconfigured with several threat emulation tools as well as a defender's toolkit.
- [Computer Aided Investigative Environment (CAINE)](https://caine-live.net/) - Italian GNU/Linux live distribution that pre-packages numerous digital forensics and evidence collection tools.
- [Security Onion](https://securityonion.net/) - Free and open source GNU/Linux distribution for intrusion detection, enterprise security monitoring, and log management.
- [Android Tamer](https://androidtamer.com/) - Based on Debian.
- [BackBox](https://backbox.org/) - Based on Ubuntu.
- [BlackArch Linux](https://blackarch.org/) - Based on Arch Linux.
- [Fedora Security Lab](https://labs.fedoraproject.org/security/) - Based on Fedora.
- [Pentoo](http://www.pentoo.ch/) - Based on Gentoo.
- [URIX OS](http://urix.us/) - Based on openSUSE.
- [Wifislax](http://www.wifislax.com/) - Based on Slackware.

## CTF Websites and Wargames
- [HackTheBox](https://www.hackthebox.eu/login) - Popular CTF website
- [TryHackMe](https://tryhackme.com/login) - Up and coming CTF website
- [OverTheWire](https://overthewire.org/wargames/) - Wargame community that help you to learn and practice security concepts in the form of fun-filled games
- [SANS Holiday Hack Challenges](https://www.holidayhackchallenge.com/past-challenges/index.html) - SANS annual CTF challenges for worthy opponents
- [CryptoPals](https://cryptopals.com/) - A collection of 48 exercises that demonstrate attacks on real-world crypto
- [Ethernaut](https://ethernaut.openzeppelin.com/) - Web3/Solidity based wargame inspired on overthewire
- [Netresec](https://www.netresec.com/?page=PcapFiles) - Network analysis pcap challenges
- [Forensic Puzzles](http://forensicscontest.com/puzzles) - Networking forensic challenges
- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/) - Website dedicated to network analysis pcap traffic
- [CTFd](https://github.com/isislab/CTFd) - Platform to host jeopardy style CTFs from ISISLab, NYU Tandon.
- [echoCTF.RED](https://github.com/echoCTF/echoCTF.RED) - Develop, deploy and maintain your own CTF infrastructure.
- [FBCTF](https://github.com/facebook/fbctf) - Platform to host Capture the Flag competitions from Facebook.
- [Haaukins](https://github.com/aau-network-security/haaukins)- A Highly Accessible and Automated Virtualization Platform for Security Education.
- [HackTheArch](https://github.com/mcpa-stlouis/hack-the-arch) - CTF scoring platform.
- [Mellivora](https://github.com/Nakiami/mellivora) - A CTF engine written in PHP.
- [MotherFucking-CTF](https://github.com/andreafioraldi/motherfucking-ctf) - Badass lightweight plaform to host CTFs. No JS involved.
- [NightShade](https://github.com/UnrealAkama/NightShade) - A simple security CTF framework.
- [OpenCTF](https://github.com/easyctf/openctf) - CTF in a box. Minimal setup required.
- [PicoCTF](https://github.com/picoCTF/picoCTF) - The platform used to run picoCTF. A great framework to host any CTF.
- [PyChallFactory](https://github.com/pdautry/py_chall_factory) - Small framework to create/manage/package jeopardy CTF challenges.
- [RootTheBox](https://github.com/moloch--/RootTheBox) - A Game of Hackers (CTF Scoreboard & Game Manager).
- [Scorebot](https://github.com/legitbs/scorebot) - Platform for CTFs by Legitbs (Defcon).
- [SecGen](https://github.com/cliffe/SecGen) - Security Scenario Generator. Creates randomly vulnerable virtual machines.
- [Challenges & CTFs](https://aboutdfir.com/education/challenges-ctfs/) - AboutDFIR's list of Challenges & CTFs
- [Forensics CTFs](https://github.com/apsdehal/awesome-ctf/blob/master/README.md#forensics)
- [Precision Widgets of North Dakota Intrusion](https://betweentwodfirns.blogspot.com/2017/11/dfir-ctf-precision-widgets-of-north.html)

# Resources

## Simulation Training
- [APTSimulator](https://github.com/NextronSystems/APTSimulator) - Toolset to make a system look as if it was the victim of an APT attack.
- [Atomic Red Team](https://atomicredteam.io/) - Library of simple, automatable tests to execute for testing security controls.
- [DumpsterFire](https://github.com/TryCatchHCF/DumpsterFire) - Modular, menu-driven, cross-platform tool for building repeatable, time-delayed, distributed security events for Blue Team drills and sensor/alert mapping.
- [Metta](https://github.com/uber-common/metta) - Automated information security preparedness tool to do adversarial simulation.
- [Network Flight Simulator (`flightsim`)](https://github.com/alphasoc/flightsim) - Utility to generate malicious network traffic and help security teams evaluate security controls and audit their network visibility.


## Malware Databases
- [National Vulnerability Database](https://nvd.nist.gov/) - U.S. government repository of standards-based vulnerability management data
- [OWASP](https://owasp.org/projects/) - Open Source Foundation for Application Security
- [Exploit Database](https://www.exploit-db.com/) - Exploits, Shellcode, 0days, Remote Exploits, Local Exploits, Web Apps, Vulnerability Reports, Security Articles, Tutorials and more
- [MITRE ATT&CK](https://attack.mitre.org/) - Globally-accessible knowledge base of adversary tactics and techniques based on real-world observations
- [Virus Share](https://virusshare.com/) - Because Sharing is Caring
- [Kaggle](https://www.kaggle.com/c/malware-classification) - 50,000 public databases, 400,000 public notebooks
- [Virus Total](https://www.virustotal.com/gui/) - Huge database full of known hashes and known hostnames being malicious
## Cyber Resources and News
- [Threatpost](https://threatpost.com/) - Independent news site which is a leading source of information about IT and business security
- [CISO MAG](https://www.cisomag.com/) - Publication features news, comprehensive analysis, cutting-edge features & contributions from cybersecurity thought leaders
- [OSINT](https://osintframework.com/) - Collection of tools to collect public information by category
- [SANS Newsletter](https://www.sans.org/newsletters/) - Semiweekly high-level executive summary of the most important cyber news articles
- [Pentestmonkey](http://pentestmonkey.net/) - Website dedicated to providing free custom pentesting scripts
- [Gibson Research Corporation](https://www.grc.com/intro.htm) - Dude named Steve who just really likes to do cyber stuff
- [National Security Agency](https://apps.nsa.gov/iaarchive/library/reports/#libraryMenu) -Hosts a library collection full of unique reports and tech tips
- [FIRST](https://www.first.org/) - A global forum full of incident response, security techniques and write ups
- [Lenny Seltzer](https://zeltser.com/automated-malware-analysis/) - Runs a website dedicated to providing resources to Digital forensics individuals

## Websites Providing Cyber Training

- [SANS](https://www.sans.org/) - The go to website for cyber security training
- [FEDVTE](https://fedvte.usalearning.gov/) - A ton of free cyber security videos that can count towards CEU's
- [Cybrary](https://www.cybrary.it/) - Videos on demand related to Cyber security
- [Pluralsight](https://www.pluralsight.com/) - Very similar to Cybrary with videos on demand
- [Udemy](https://www.udemy.com/) - Another video on demand website but you pay only for the classes you want
- [SkillSoft](https://www.skillsoft.com/courses) - On demand courses you can pay for
- [Kode Kloud](https://kodekloud.com/) - Courses specific to DevOps

## macOS-based defenses

- [BlockBlock](https://objective-see.com/products/blockblock.html) - Monitors common persistence locations and alerts whenever a persistent component is added, which helps to detect and prevent malware installation.
- [LuLu](https://objective-see.com/products/lulu.html) - Free macOS firewall.
- [Santa](https://github.com/google/santa) - Binary whitelisting/blacklisting system for macOS.
- [Stronghold](https://github.com/alichtman/stronghold) - Easily configure macOS security settings from the terminal.
- [macOS Fortress](https://github.com/essandess/macOS-Fortress) - Automated configuration of kernel-level, OS-level, and client-level security features including privatizing proxying and anti-virus scanning for macOS.

## Windows-based defenses

See also [awesome-windows#security](https://github.com/Awesome-Windows/Awesome#security) and [awesome-windows-domain-hardening](https://github.com/PaulSec/awesome-windows-domain-hardening).

- [HardenTools](https://github.com/securitywithoutborders/hardentools) - Utility that disables a number of risky Windows features.
- [NotRuler](https://github.com/sensepost/notruler) - Detect both client-side rules and VBScript enabled forms used by the [Ruler](https://github.com/sensepost/ruler) attack tool when attempting to compromise a Microsoft Exchange server.
- [Sandboxie](https://www.sandboxie.com/) - Free and open source general purpose Windows application sandboxing utility.
- [Sigcheck](https://docs.microsoft.com/en-us/sysinternals/downloads/sigcheck) - Audit a Windows host's root certificate store against Microsoft's [Certificate Trust List (CTL)](https://docs.microsoft.com/en-us/windows/desktop/SecCrypto/certificate-trust-list-overview).
- [Sticky Keys Slayer](https://github.com/linuz/Sticky-Keys-Slayer) - Establishes a Windows RDP session from a list of hostnames and scans for accessibility tools backdoors, alerting if one is discovered.
- [Windows Secure Host Baseline](https://github.com/nsacyber/Windows-Secure-Host-Baseline) - Group Policy objects, compliance checks, and configuration tools that provide an automated and flexible approach for securely deploying and maintaining the latest releases of Windows 10.
- [WMI Monitor](https://github.com/realparisi/WMI_Monitor) - Log newly created WMI consumers and processes to the Windows Application event log.
- [Hack Windows With These Tools](https://github.com/Hack-with-Github/Windows) - Collection of tools to hack windows

## Network Security Monitoring

See also [awesome-pcaptools](https://github.com/caesar0301/awesome-pcaptools).

- [ChopShop](https://github.com/MITRECND/chopshop) - Framework to aid analysts in the creation and execution of pynids-based decoders and detectors of APT tradecraft.
- [Maltrail](https://github.com/stamparm/maltrail) - Malicious network traffic detection system.
- [Moloch](https://github.com/aol/moloch) - Augments your current security infrastructure to store and index network traffic in standard PCAP format, providing fast, indexed access.
- [OwlH](https://www.owlh.net/) - Helps manage network IDS at scale by visualizing Suricata, Zeek, and Moloch life cycles.
- [Respounder](https://github.com/codeexpress/respounder) - Detects the presence of the Responder LLMNR/NBT-NS/MDNS poisoner on a network.
- [Real Intelligence Threat Analysis (RITA)](https://github.com/activecm/rita) - Open source framework for network traffic analysis that ingests Zeek logs and detects beaconing, DNS tunneling, and more.
- [Snort](https://snort.org/) - Widely-deployed, Free Software IPS capable of real-time packet analysis, traffic logging, and custom rule-based triggers.
- [SpoofSpotter](https://github.com/NetSPI/SpoofSpotter) - Catch spoofed NetBIOS Name Service (NBNS) responses and alert to an email or log file.
- [Stenographer](https://github.com/google/stenographer) - Full-packet-capture utility for buffering packets to disk for intrusion detection and incident response purposes.
- [Suricata](https://suricata-ids.org/) - Free, cross-platform, IDS/IPS with on- and off-line analysis modes and deep packet inspection capabilities that is also scriptable with Lua.
- [VAST](https://github.com/tenzir/vast) - Free and open-source network telemetry engine for data-driven security investigations.
- [Wireshark](https://www.wireshark.org) - Free and open-source packet analyzer useful for network troubleshooting or forensic netflow analysis.
- [Zeek](https://zeek.org/) - Powerful network analysis framework focused on security monitoring, formerly known as Bro.
- [netsniff-ng](http://netsniff-ng.org/) -  Free and fast GNU/Linux networking toolkit with numerous utilities such as a connection tracking tool (`flowtop`), traffic generator (`trafgen`), and autonomous system (AS) trace route utility (`astraceroute`)

## Security Information and Event Management

- [RockNSM](https://rocknsm.io/) - Durable Network Security Monitoring sensor built with scalability, security, and hunt-centric tactics in mind
- [HELK](https://github.com/Cyb3rWard0g/HELK) - open source hunt platforms with advanced analytics capabilities such as SQL declarative language, graphing, structured streaming, and even machine learning via Jupyter notebooks and Apache Spark over an ELK stack
- [AlienVault OSSIM](https://www.alienvault.com/open-threat-exchange/projects) - Single-server open source SIEM platform featuring asset discovery, asset inventorying, behavioral monitoring, and event correlation, driven by AlienVault Open Threat Exchange (OTX).
- [Prelude SIEM OSS](https://www.prelude-siem.org/) - Open source, agentless SIEM with a long history and several commercial variants featuring security event collection, normalization, and alerting from arbitrary log input and numerous popular monitoring tools.


## Threat hunting Tools

(Also known as *hunt teaming* and *threat detection*.)

See also [awesome-threat-detection](https://github.com/0x4D31/awesome-threat-detection).

- [CimSweep](https://github.com/PowerShellMafia/CimSweep) - Suite of CIM/WMI-based tools enabling remote incident response and hunting operations across all versions of Windows.
- [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) - PowerShell module for hunt teaming via Windows Event logs.
- [GRR Rapid Response](https://github.com/google/grr) - Incident response framework focused on remote live forensics consisting of a Python agent installed on assets and Python-based server infrastructure enabling analysts to quickly triage attacks and perform analysis remotely.
- [MozDef](https://github.com/mozilla/MozDef) - Automate the security incident handling process and facilitate the real-time activities of incident handlers.
- [PSHunt](https://github.com/Infocyte/PSHunt) - PowerShell module designed to scan remote endpoints for indicators of compromise or survey them for more comprehensive information related to state of those systems.
- [PSRecon](https://github.com/gfoss/PSRecon) - PSHunt-like tool for analyzing remote Windows systems that also produces a self-contained HTML report of its findings.
- [PowerForensics](https://github.com/Invoke-IR/PowerForensics) - All in one PowerShell-based platform to perform live hard disk forensic analysis.
- [rastrea2r](https://github.com/rastrea2r/rastrea2r) - Multi-platform tool for triaging suspected IOCs on many endpoints simultaneously and that integrates with antivirus consoles.
- [Redline](https://www.fireeye.com/services/freeware/redline.html) - Freeware endpoint auditing and analysis tool that provides host-based investigative capabilities, offered by FireEye, Inc.

## Docker Images for Penetration Testing & Security
- `docker pull kalilinux/kali-linux-docker` [official Kali Linux](https://hub.docker.com/r/kalilinux/kali-linux-docker/)
- `docker pull owasp/zap2docker-stable` - [official OWASP ZAP](https://github.com/zaproxy/zaproxy)
- `docker pull wpscanteam/wpscan` - [official WPScan](https://hub.docker.com/r/wpscanteam/wpscan/)
- `docker pull remnux/metasploit` - [docker-metasploit](https://hub.docker.com/r/remnux/metasploit/)
- `docker pull citizenstig/dvwa` - [Damn Vulnerable Web Application (DVWA)](https://hub.docker.com/r/citizenstig/dvwa/)
- `docker pull wpscanteam/vulnerablewordpress` - [Vulnerable WordPress Installation](https://hub.docker.com/r/wpscanteam/vulnerablewordpress/)
- `docker pull hmlio/vaas-cve-2014-6271` - [Vulnerability as a service: Shellshock](https://hub.docker.com/r/hmlio/vaas-cve-2014-6271/)
- `docker pull hmlio/vaas-cve-2014-0160` - [Vulnerability as a service: Heartbleed](https://hub.docker.com/r/hmlio/vaas-cve-2014-0160/)
- `docker pull opendns/security-ninjas` - [Security Ninjas](https://hub.docker.com/r/opendns/security-ninjas/)
- `docker pull diogomonica/docker-bench-security` - [Docker Bench for Security](https://hub.docker.com/r/diogomonica/docker-bench-security/)
- `docker pull ismisepaul/securityshepherd` - [OWASP Security Shepherd](https://hub.docker.com/r/ismisepaul/securityshepherd/)
- `docker pull danmx/docker-owasp-webgoat` - [OWASP WebGoat Project docker image](https://hub.docker.com/r/danmx/docker-owasp-webgoat/)
- `docker-compose build && docker-compose up` - [OWASP NodeGoat](https://github.com/owasp/nodegoat#option-3---run-nodegoat-on-docker)
- `docker pull citizenstig/nowasp` - [OWASP Mutillidae II Web Pen-Test Practice Application](https://hub.docker.com/r/citizenstig/nowasp/)
- `docker pull bkimminich/juice-shop` - [OWASP Juice Shop](https://hub.docker.com/r/bkimminich/juice-shop)

## Big Data

- [data_hacking](https://github.com/ClickSecurity/data_hacking) - Examples of using IPython, Pandas, and Scikit Learn to get the most out of your security data.
- [hadoop-pcap](https://github.com/RIPE-NCC/hadoop-pcap) - Hadoop library to read packet capture (PCAP) files.
- [Workbench](http://workbench.readthedocs.org/) - A scalable python framework for security research and development teams.
- [OpenSOC](https://github.com/OpenSOC/opensoc) - OpenSOC integrates a variety of open source big data technologies in order to offer a centralized tool for security monitoring and analysis.
- [Apache Metron (incubating)](https://github.com/apache/incubator-metron) - Metron integrates a variety of open source big data technologies in order to offer a centralized tool for security monitoring and analysis.
- [Apache Spot (incubating)](https://github.com/apache/incubator-spot) - Apache Spot is open source software for leveraging insights from flow and packet analysis.
- [binarypig](https://github.com/endgameinc/binarypig) - Scalable Binary Data Extraction in Hadoop. Malware Processing and Analytics over Pig, Exploration through Django, Twitter Bootstrap, and Elasticsearch.

## Threat intelligence
See [awesome-threat-intelligence](https://github.com/hslatman/awesome-threat-intelligence).

## Open Source System Administrator Tools
See [awesome-sysadmin#monitoring](https://github.com/n1trux/awesome-sysadmin#monitoring)

## Cyber Security Books
See [Click Here](https://github.com/Hack-with-Github/Free-Security-eBooks)

# Digital Forensics

### Distributions

- [bitscout](https://github.com/vitaly-kamluk/bitscout) - LiveCD/LiveUSB for remote forensic acquisition and analysis
- [SANS Investigative Forensics Toolkit (sift)](https://github.com/teamdfir/sift) - Linux distribution for forensic analysis
- [Tsurugi Linux](https://tsurugi-linux.org/) - Linux distribution for forensic analysis

### Frameworks

- [dff](https://github.com/arxsys/dff) - Forensic framework
- [dexter](https://github.com/coinbase/dexter) - Dexter is a forensics acquisition framework designed to be extensible and secure
- [IntelMQ](https://github.com/certtools/intelmq) - IntelMQ collects and processes security feeds
- [Kuiper](https://github.com/DFIRKuiper/Kuiper) - Digital Investigation Platform
- [Laika BOSS](https://github.com/lmco/laikaboss) - Laika is an object scanner and intrusion detection system
- [PowerForensics](https://github.com/Invoke-IR/PowerForensics) - PowerForensics is a framework for live disk forensic analysis
- :star: [The Sleuth Kit](https://github.com/sleuthkit/sleuthkit) - Tools for low level forensic analysis
- [turbinia](https://github.com/google/turbinia) - Turbinia is an open-source framework for deploying, managing, and running forensic workloads on cloud platforms
- [IPED - Indexador e Processador de Evidências Digitais](https://github.com/sepinf-inc/IPED) - Brazilian Federal Police Tool for Forensic Investigations

### Live Forensics

- [grr](https://github.com/google/grr) - GRR Rapid Response: remote live forensics for incident response
- [Linux Expl0rer](https://github.com/intezer/linux-explorer) - Easy-to-use live forensics toolbox for Linux endpoints written in Python & Flask
- [mig](https://github.com/mozilla/mig) - Distributed & real time digital forensics at the speed of the cloud
- [osquery](https://github.com/osquery/osquery) - SQL powered operating system analytics

### Acquisition

- [artifactcollector](https://github.com/forensicanalysis/artifactcollector) - A customizable agent to collect forensic artifacts on any Windows, macOS or Linux system
- [ArtifactExtractor](https://github.com/Silv3rHorn/ArtifactExtractor) - Extract common Windows artifacts from source images and VSCs
- [AVML](https://github.com/microsoft/avml) - A portable volatile memory acquisition tool for Linux
- [Belkasoft RAM Capturer](https://belkasoft.com/ram-capturer) - Volatile Memory Acquisition Tool
- [DFIR ORC](https://dfir-orc.github.io/) - Forensics artefact collection tool for systems running Microsoft Windows
- [FastIR Collector](https://github.com/SekoiaLab/Fastir_Collector) - Collect artifacts on windows
- [LiME](https://github.com/504ensicsLabs/LiME) - Loadable Kernel Module (LKM), which allows the acquisition of volatile memory from Linux and Linux-based devices, formerly called DMD
- [Velociraptor](https://github.com/Velocidex/velociraptor) - Velociraptor is a tool for collecting host based state information using Velocidex Query Language (VQL) queries

### Imaging

- [dc3dd](https://sourceforge.net/projects/dc3dd/) - Improved version of dd
- [dcfldd](http://dcfldd.sourceforge.net) - Different improved version of dd (this version has some bugs!, another version is on github [adulau/dcfldd](https://github.com/adulau/dcfldd))
- [FTK Imager](https://accessdata.com/product-download/ftk-imager-version-3-4-3/) - Free imageing tool for windows
- [Guymager](https://guymager.sourceforge.io/) - Open source version for disk imageing on linux systems

### Carving

- [bstrings](https://github.com/EricZimmerman/bstrings) - Improved strings utility
- [bulk_extractor](https://github.com/simsong/bulk_extractor) - Extracts information such as email addresses, creditcard numbers and histrograms from disk images
- [floss](https://github.com/fireeye/flare-floss) - Static analysis tool to automatically deobfuscate strings from malware binaries
- :star: [photorec](https://www.cgsecurity.org/wiki/PhotoRec) - File carving tool
- [swap_digger](https://github.com/sevagas/swap_digger) - A bash script used to automate Linux swap analysis, automating swap extraction and searches for Linux user credentials, Web form credentials, Web form emails, etc.

### Memory Forensics

- [inVtero.net](https://github.com/ShaneK2/inVtero.net) - High speed memory analysis framework
  developed in .NET supports all Windows x64, includes code integrity and write support
- [KeeFarce](https://github.com/denandz/KeeFarce) - Extract KeePass passwords from memory
- [MemProcFS](https://github.com/ufrisk/MemProcFS) - An easy and convenient way of accessing physical memory as files a virtual file system.
- [Rekall](https://github.com/google/rekall) - Memory Forensic Framework
- [volatility](https://github.com/volatilityfoundation/volatility) - The memory forensic framework
- [VolUtility](https://github.com/kevthehermit/VolUtility) - Web App for Volatility framework

### Windows Artifacts

- [Beagle](https://github.com/yampelo/beagle) -  Transform data sources and logs into graphs
- [FRED](https://www.pinguin.lu/fred) - Cross-platform microsoft registry hive editor
- [LogonTracer](https://github.com/JPCERTCC/LogonTracer) - Investigate malicious Windows logon by visualizing and analyzing Windows event log
- [python-evt](https://github.com/williballenthin/python-evt) - Pure Python parser for classic Windows Event Log files (.evt)
- [RegRipper3.0](https://github.com/keydet89/RegRipper3.0) - RegRipper is an open source Perl tool for parsing the Registry and presenting it for analysis.

#### NTFS/MFT Processing

- [MFT-Parsers](http://az4n6.blogspot.com/2015/09/whos-your-master-mft-parsers-reviewed.html) - Comparison of MFT-Parsers
- [MFTEcmd](https://binaryforay.blogspot.com/2018/06/introducing-mftecmd.html) - MFT Parser by Eric Zimmerman
- [MFTExtractor](https://github.com/aarsakian/MFTExtractor) - MFT-Parser
- [NTFS journal parser](http://strozfriedberg.github.io/ntfs-linker/)
- [NTFS USN Journal parser](https://github.com/PoorBillionaire/USN-Journal-Parser)
- [RecuperaBit](https://github.com/Lazza/RecuperaBit) - Reconstruct and recover NTFS data
- [python-ntfs](https://github.com/williballenthin/python-ntfs) - NTFS analysis

### OS X Forensics

- [mac_apt (macOS Artifact Parsing Tool)](https://github.com/ydkhatri/mac_apt) - Extracts forensic artifacts from disk images or live machines
- [OSXAuditor](https://github.com/jipegit/OSXAuditor)
- [OSX Collect](https://github.com/Yelp/osxcollector)

### Mobile Forensics

- [ALEAPP](https://github.com/abrignoni/ALEAPP) - An Android Logs Events and Protobuf Parser
- [ArtEx](https://www.doubleblak.com/index.php) - Artifact Examiner for iOS Full File System extractions
- [iLEAPP](https://github.com/abrignoni/iLEAPP) - An iOS Logs, Events, And Plists Parser
- [MEAT](https://github.com/jfarley248/MEAT) - Perform different kinds of acquisitions on iOS devices

### Docker Forensics

- [dof (Docker Forensics Toolkit)](https://github.com/docker-forensics-toolkit/toolkit) - Extracts and interprets forensic artifacts from disk images of Docker Host systems
- [Docker Explorer](https://github.com/google/docker-explorer) Extracts and interprets forensic artifacts from disk images of Docker Host systems

### Internet Artifacts

- [chrome-url-dumper](https://github.com/eLoopWoo/chrome-url-dumper) - Dump all local stored infromation collected by Chrome
- [hindsight](https://github.com/obsidianforensics/hindsight) - Internet history forensics for Google Chrome/Chromium
- [unfurl](https://github.com/obsidianforensics/unfurl) - Extract and visualize data from URLs

### Timeline Analysis

- [DFTimewolf](https://github.com/log2timeline/dftimewolf) - Framework for orchestrating forensic collection, processing and data export using GRR and Rekall
- :star: [plaso](https://github.com/log2timeline/plaso) - Extract timestamps from various files and aggregate them
- [Timeline Explorer](https://binaryforay.blogspot.com/2017/04/introducing-timeline-explorer-v0400.html) - Timeline Analysis tool for CSV and Excel files. Built for SANS FOR508 students
- [timeliner](https://github.com/airbus-cert/timeliner) - A rewrite of mactime, a bodyfile reader
- [timesketch](https://github.com/google/timesketch) - Collaborative forensic timeline analysis

### Disk image handling

- [Disk Arbitrator](https://github.com/aburgh/Disk-Arbitrator) - A Mac OS X forensic utility designed to help the user ensure correct forensic procedures are followed during imaging of a disk device
- [imagemounter](https://github.com/ralphje/imagemounter) - Command line utility and Python package to ease the (un)mounting of forensic disk images
- [libewf](https://github.com/libyal/libewf) - Libewf is a library and some tools to access the Expert Witness Compression Format (EWF, E01)
- [PancakeViewer](https://github.com/forensicmatt/PancakeViewer) - Disk image viewer based in dfvfs, similar to the FTK Imager viewer
- [xmount](https://www.pinguin.lu/xmount) - Convert between different disk image formats

### Decryption

- [hashcat](https://hashcat.net/hashcat/) - Fast password cracker with GPU support
- [John the Ripper](https://www.openwall.com/john/) - Password cracker

### Management

- [dfirtrack](https://github.com/stuhli/dfirtrack) - Digital Forensics and Incident Response Tracking application, track systems
- [Incidents](https://github.com/veeral-patel/incidents) - Web application for organizing non-trivial security investigations. Built on the idea that incidents are trees of tickets, where some tickets are leads

### Picture Analysis

- [sherloq](https://github.com/GuidoBartoli/sherloq) - An open-source digital photographic image forensic toolset

## Learn Forensics

- [Forensic challenges](https://www.amanhardikar.com/mindmaps/ForensicChallenges.html) - Mindmap of forensic challenges
- [Training material](https://www.enisa.europa.eu/topics/trainings-for-cybersecurity-specialists/online-training-material/technical-operational) - Online training material by European Union Agency for Network and Information Security for different topics (e.g. [Digital forensics](https://www.enisa.europa.eu/topics/trainings-for-cybersecurity-specialists/online-training-material/technical-operational/#digital_forensics), [Network forensics](https://www.enisa.europa.eu/topics/trainings-for-cybersecurity-specialists/online-training-material/technical-operational/#network_forensics))

### Books

*more at [Recommended Readings](http://dfir.org/?q=node/8) by Andrew Case*

- [Network Forensics: Tracking Hackers through Cyberspace](https://www.pearson.com/us/higher-education/program/Davidoff-Network-Forensics-Tracking-Hackers-through-Cyberspace/PGM322390.html) - Learn to recognize hackers’ tracks and uncover network-based evidence
- [The Art of Memory Forensics](https://www.memoryanalysis.net/amf) - Detecting Malware and Threats in Windows, Linux, and Mac Memory
- [The Practice of Network Security Monitoring](https://nostarch.com/nsm) - Understanding Incident Detection and Response

### File System

- [Digital Forensic Challenge Images](https://www.ashemery.com/dfir.html) - Two DFIR challenges with images
- [Digital Forensics Tool Testing Images](http://dftt.sourceforge.net)
- [FAU Open Research Challenge Digital Forensics](https://openresearchchallenge.org/digitalForensics/appliedforensiccomputinggroup)
- [The CFReDS Project](https://www.cfreds.nist.gov)
  - [Hacking Case (4.5 GB NTFS Image)](https://www.cfreds.nist.gov/Hacking_Case.html)

### Twitter

- [@4n6ist](https://twitter.com/4n6ist)
- [@aheadless](https://twitter.com/aheadless)
- [@AppleExaminer](https://twitter.com/AppleExaminer) - Apple OS X & iOS Digital Forensics
- [@carrier4n6](https://twitter.com/carrier4n6) - Brian Carrier, author of Autopsy and the Sleuth Kit
- [@CindyMurph](https://twitter.com/CindyMurph) - Detective & Digital Forensic Examiner
- [@forensikblog](https://twitter.com/forensikblog) - Computer forensic geek
- [@HECFBlog](https://twitter.com/HECFBlog) - SANS Certified Instructor
- [@Hexacorn](https://twitter.com/Hexacorn) - DFIR+Malware
- [@hiddenillusion](https://twitter.com/hiddenillusion)
- [@iamevltwin](https://twitter.com/iamevltwin) - Mac Nerd, Forensic Analyst, Author & Instructor of SANS FOR518
- [@jaredcatkinson](https://twitter.com/jaredcatkinson) - PowerShell Forensics
- [@maridegrazia](https://twitter.com/maridegrazia) - Computer Forensics Examiner
- [@sleuthkit](https://twitter.com/sleuthkit)
- [@williballenthin](https://twitter.com/williballenthin)
- [@XWaysGuide](https://twitter.com/XWaysGuide)

Vendors:

- [@Belkasoft](https://twitter.com/Belkasoft)
- [@blackbagtech](https://twitter.com/blackbagtech)


### Blogs

- [thisweekin4n6.wordpress.com](thisweekin4n6.wordpress.com) - Weekly updates for forensics

### Other

- [/r/computerforensics/](https://www.reddit.com/r/computerforensics/) - Subreddit for computer forensics
- [/r/LearnDigitalForensics](https://www.reddit.com/r/LearnDigitalForensics/) - Subreddit for learning Digital Forensics
- [ForensicPosters](https://github.com/Invoke-IR/ForensicPosters) - Posters of file system structures
- [SANS Posters](https://www.sans.org/security-resources/posters/) - Free posters provided by SANS

## Other Security Awesome Lists

- [Android Security Awesome](https://github.com/ashishb/android-security-awesome) - A collection of android security related resources.
- [Awesome ARM Exploitation](https://github.com/HenryHoggard/awesome-arm-exploitation) - A curated list of ARM exploitation resources.
- [Awesome CTF](https://github.com/apsdehal/awesome-ctf) - A curated list of CTF frameworks, libraries, resources and software.
- [Awesome Cyber Skills](https://github.com/joe-shenouda/awesome-cyber-skills) - A curated list of hacking environments where you can train your cyber skills legally and safely.
- [Awesome Personal Security](https://github.com/Lissy93/personal-security-checklist) - A curated list of digital security and privacy tips, with links to further resources.
- [Awesome Hacking](https://github.com/carpedm20/awesome-hacking) - A curated list of awesome Hacking tutorials, tools and resources.
- [Awesome Honeypots](https://github.com/paralax/awesome-honeypots) - An awesome list of honeypot resources.
- [Awesome Malware Analysis](https://github.com/rshipp/awesome-malware-analysis) - A curated list of awesome malware analysis tools and resources.
- [Awesome PCAP Tools](https://github.com/caesar0301/awesome-pcaptools) - A collection of tools developed by other researchers in the Computer Science area to process network traces.
- [Awesome Pentest](https://github.com/enaqx/awesome-pentest) - A collection of awesome penetration testing resources, tools and other shiny things.
- [Awesome Linux Containers](https://github.com/Friz-zy/awesome-linux-containers) - A curated list of awesome Linux Containers frameworks, libraries and software.
- [Awesome Incident Response](https://github.com/meirwah/awesome-incident-response) - A curated list of resources for incident response.
- [Awesome Web Hacking](https://github.com/infoslack/awesome-web-hacking) - This list is for anyone wishing to learn about web application security but do not have a starting point.
- [Awesome Hacking](https://github.com/carpedm20/awesome-hacking) - A curated list of awesome Hacking tutorials, tools and resources
- [Awesome Electron.js Hacking](https://github.com/doyensec/awesome-electronjs-hacking) - A curated list of awesome resources about Electron.js (in)security
- [Awesome Threat Intelligence](https://github.com/hslatman/awesome-threat-intelligence) - A curated list of threat intelligence resources.
- [Awesome Threat Modeling](https://github.com/redshiftzero/awesome-threat-modeling) - A curated list of Threat Modeling resources.
- [Awesome Pentest Cheat Sheets](https://github.com/coreb1t/awesome-pentest-cheat-sheets) - Collection of the cheat sheets useful for pentesting
- [Awesome Industrial Control System Security](https://github.com/mpesen/awesome-industrial-control-system-security) - A curated list of resources related to Industrial Control System (ICS) security.
- [Awesome YARA](https://github.com/InQuest/awesome-yara) - A curated list of awesome YARA rules, tools, and people.
- [Awesome Threat Detection and Hunting](https://github.com/0x4D31/awesome-threat-detection) - A curated list of awesome threat detection and hunting resources.
- [Awesome Container Security](https://github.com/kai5263499/container-security-awesome) - A curated list of awesome resources related to container building and runtime security
- [Awesome Crypto Papers](https://github.com/pFarb/awesome-crypto-papers) - A curated list of cryptography papers, articles, tutorials and howtos.
- [Awesome Shodan Search Queries](https://github.com/jakejarvis/awesome-shodan-queries) - A collection of interesting, funny, and depressing search queries to plug into Shodan.io.
- [Awesome Anti Forensics](https://github.com/remiflavien1/awesome-anti-forensic) - A collection of awesome tools used to counter forensics activities.
- [Awesome Security Talks & Videos](https://github.com/PaulSec/awesome-sec-talks) - A curated list of awesome security talks, organized by year and then conference. 


### Other Common Awesome Lists

Other amazingly awesome lists:

- [awesome-awesomeness](https://github.com/bayandin/awesome-awesomeness) - awesome-* or *-awesome lists.
- [lists](https://github.com/jnv/lists) - The definitive list of (awesome) lists curated on GitHub.
- [Movies For Hacker](https://github.com/k4m4/movies-for-hackers) - A curated list of movies every hacker & cyberpunk must watch.
