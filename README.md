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
<p> Please do! If you have an interesting resource to share open a pull request. All I ask is that you categorize and utilize markdown to create a link with a description </p>

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
  - [/usr/bin](#/usr/bin)
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
- [SANS Reading Room](https://www.sans.org/white-papers/)
- [Black Hat Archives](https://www.blackhat.com/html/archives.html) 
- [If you've ever wanted to mess around with a SIEM](https://www.hackingarticles.in/threat-hunting-log-monitoring-lab-setup-with-elk/)  
- [Spin Up An AD Enviorment Quickly](https://medium.com/@clong/introducing-detection-lab-61db34bed6ae) 
- [H.O.T Security](https://www.sans.org/white-papers/35377/)
- [Lenny Zeltser - Learn Malware Analysis](https://zeltser.com/start-learning-malware-analysis/) 
- [De-Fanging Strings with FLOSS](https://medium.com/malware-buddy/reverse-engineering-tips-strings-deobfuscation-with-floss-9424417e285d)
- [Setting up Tripwire](https://www.howtoforge.com/tutorial/monitoring-and-detecting-modified-files-using-tripwire-on-centos-7/) 
- [Canary Tokens](https://blog.thinkst.com/p/canarytokensorg-quick-free-detection.html) 
- [Kerboroasting](https://adsecurity.org/?p=3458)
- [Honey Files](https://docs.rapid7.com/insightidr/honey-files/)
- [CTI Self Study Plan](https://medium.com/katies-five-cents/a-cyber-threat-intelligence-self-study-plan-part-1-968b5a8daf9a)
- [Start Learning Malware Analysis](https://zeltser.com/start-learning-malware-analysis/) 
- [DFRWS Papers & Presentations](https://dfrws.org/presentation/)
- [Detecting Meterpreter HTTP module Network Traffic](https://blog.didierstevens.com/2015/05/11/detecting-network-traffic-from-metasploits-meterpreter-reverse-http-module/)
- [Hunting Linux Persistence Part 1](https://www.activecountermeasures.com/hunting-for-persistence-in-linux-part-1-auditd-sysmon-osquery-and-webshells/)
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

## Research-Resources
### Write-ups
- [Unit 42](https://unit42.paloaltonetworks.com/)
- [Google Security Blog](https://security.googleblog.com/)
- [Trellix Blog](https://www.trellix.com/en-us/about/newsroom/stories.html)
- [The DFIR Report](https://thedfirreport.com/) Solid DFIR writeups
- [Sophos X-Ops](https://news.sophos.com/en-us/tag/sophos-x-ops/)
- [Intel 471](https://intel471.com/blog/)

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
- [Unit 42 Atom](https://unit42.paloaltonetworks.com/atoms/)
- [CrowdStrike Adversary](https://adversary.crowdstrike.com/en-US/) 
- [SOC Radar](https://labs.socradar.com/apt-feeds/) 
- [APT Campaigns](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections) 
- [APT Map](https://aptmap.netlify.app/) 
- [Yet Another Google Doc.1](https://docs.google.com/spreadsheets/u/0/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/pubhtml) 
- [Yet Another Google Doc.2](https://docs.google.com/document/d/1oYX3uN6KxIX_StzTH0s0yFNNoHDnV8VgmVqU5WoeErc/edit) 
- [Yet Another Google Doc.3](https://docs.google.com/document/u/1/d/e/2PACX-1vR2TWm68bLidO3e2X0wTCqs0609vo5RXB85f6VL_Zm79wtTK59xADKh6MG0G7hSBZi8cPOiQVWAIie0/pub) 
- [Yet Another Google Doc.4](https://docs.google.com/spreadsheets/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/edit#gid=361554658) 
- [Cyber Campaigns](http://www.cybercampaigns.net/) 
- [APT Secure List](https://apt.securelist.com/) 
- [Dragos Threat Activity](https://www.dragos.com/threat-activity-groups/) 
- [Google Threat Analysis](https://blog.google/threat-analysis-group/) 
- [TheRecord Nation State](https://therecord.media/news/nation-state/) 
- [Microsoft Threat Intel](https://www.microsoft.com/security/blog/microsoft-security-intelligence/) 
- [Record Future APT](https://www.recordedfuture.com/blog/) 
- [APT Map](https://andreacristaldi.github.io/APTmap/#50) 
- [Mitre APT Groups](https://attack.mitre.org/groups/) 
- [APT Netlify](https://aptmap.netlify.app/) 
- [Alienvault OTX Groups](https://otx.alienvault.com/browse/global/adversaries?include_inactive=0&sort=-modified&page=1) 

## Training-Resources
- [Blue Team CTF's](https://cyberdefenders.org/blueteam-ctf-challenges/)
- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/) Infected PCAP's for review
- [EVTX/PCAP Attack Samples](https://github.com/sbousseaden/) Infected PCAP's and EVTX logs for review
- [Open Security Training](https://opensecuritytraining.info/Training.html) 
- [TryHackMe](https://tryhackme.com/)
- [HackSplaining](https://www.hacksplaining.com/lessons)
- [Codewars](https://www.codewars.com/) Programming challanges
- [MalwareUnicorn](https://malwareunicorn.org/#/workshops)
- [Free Ivy Leauge Courses](https://www.freecodecamp.org/news/ivy-league-free-online-courses-a0d7ae675869/) List of Ivy leauge courses you can take online for free (CS50)
- [LetsDefend](https://letsdefend.io/) Free-ish training simulating the SOC life. Great for people interested in journying into a IR/SOC enviorment  
- [DC540 Reversing Course](https://github.com/sharpicx/reversing-course)
- [Low Level Programming](https://github.com/sharpicx/lowlevel-programming)
- [FreeCodeCamp](https://www.freecodecamp.org/) Free and online, self paced courses to prepare you for a role in programming

## Blue-Team-Resources
- [EricZimmerman](https://github.com/EricZimmerman)
### Utility
- [Cyber Chef](https://gchq.github.io/CyberChef/)
- [LOLBAS](https://lolbas-project.github.io/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [MITRE D3FEND](https://d3fend.mitre.org/)
- [Google Stenographer](https://github.com/google/stenographer)
- [Wazuh](https://wazuh.com/)
- [MozDef](https://github.com/mozilla/MozDef)
- [Sticky Keys Slayer](https://github.com/linuz/Sticky-Keys-Slayer)
- [Stronghold](https://github.com/alichtman/stronghold)
- [ChopShop](https://github.com/MITRECND/chopshop)
- [RockNSM](https://rocknsm.io/)
- [HELK](https://github.com/Cyb3rWard0g/HELK)
- [AlienVault OSSIM](https://www.alienvault.com/open-threat-exchange/projects)
- [Prelude](https://www.prelude-siem.org/)
- [TheHive](https://thehive-project.org/)
- [OpenEDR](https://github.com/ComodoSecurity/openedr)
- [OpenSOC](https://github.com/OpenSOC/opensoc)
- [Munin - Auto Hash Checker](https://github.com/Neo23x0/munin)
- [Threat Hunt Mind Maps](https://github.com/christophetd/mindmaps)
- [Hybrid-Analysis](https://www.hybrid-analysis.com/)
- [Manalyzer](https://www.manalyzer.org/)
- [URLScan](https://urlscan.io/)
- [Intezer Analyze](https://analyze.intezer.com/)
- [AnyRun](https://app.any.run/)
- [JoeSandbox](https://www.joesandbox.com/#windows)
- [IRIS-H](https://iris-h.services/pages/dashboard#/pages/dashboard)
- [Yoroi](https://yomi.yoroi.company/upload)
- [Har-Sai](https://har-sia.info/index-en.html) Lookup things related to a specific CVE

### Network-Analysis
- [Arkime](https://github.com/arkime) Open source full packet capturing, indexing and database system. It rebuilds sessions automatically!
- [Wireshark](https://www.wireshark.org/) Tride and true network protocol analyzer
- [Zeek](https://zeek.org/)
- [RITA](https://www.activecountermeasures.com/free-tools/rita/)
- [Whats that C2/Exfil?](https://github.com/silence-is-best/c2db)
- [Incubating](https://github.com/apache/incubator-spot)
- [Network Miner](https://www.netresec.com/?page=networkminer)
- [VAST](https://github.com/tenzir/vast)
- [NetSniff](http://netsniff-ng.org/)
- [Grass Marlin🦅](https://github.com/nsacyber/GRASSMARLIN)
- [SELKS](https://github.com/StamusNetworks/SELKS)

### Host-Analysis
- [Volatility](https://github.com/volatilityfoundation/volatility)
- [Velociraptor](https://github.com/Velocidex/velociraptor)
- [Osquery](https://osquery.io/)
- [Sysinternalsuite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)
- [CimSweep](https://github.com/PowerShellMafia/CimSweep)
- [Seatbelt](https://github.com/GhostPack/Seatbelt) Security oriented host-survey tool performing "safety checks" relevant from both offensive and defensive security perspectives
- [Live-Forensicator](https://github.com/Johnng007/Live-Forensicator)
- [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI)
- [Chainsaw](https://github.com/countercept/chainsaw)
- [Google Rapid Response](https://github.com/google/grr)
- [PSHunt](https://github.com/Infocyte/PSHunt)
- [PSRecon](https://github.com/gfoss/PSRecon)
- [Rastrea2r](https://github.com/rastrea2r/rastrea2r)
- [Redline](https://www.fireeye.com/services/freeware/redline.html)
- [Power Forensics](https://github.com/Invoke-IR/PowerForensics)
- [Block Parse](https://github.com/matthewdunwoody/block-parser) PowerShell script block parser

### Detection
- [Sigma](https://github.com/SigmaHQ/sigma/blob/master/README.md) Sigma is a generic and open signature format that allows you to describe relevant log events in a straightforward manner
- [Yara](https://yara.readthedocs.io) 
- [Snort](https://snort.org/)
- [Suricata](https://suricata.readthedocs.io)
- [WMI Monitor](https://github.com/realparisi/WMI_Monitor)
- [NotRuler](https://github.com/sensepost/notruler)
- [BlockBlock](https://objective-see.com/products/blockblock.html)
- [Santa](https://github.com/google/santa)
- [MalTrail](https://github.com/stamparm/maltrail)
- [OwlH](https://www.owlh.net/)
- [SpoofSpotter](https://github.com/NetSPI/SpoofSpotter)
- [Event Query Language](https://eql.readthedocs.io/en/latest/)

### Malware-Analysis
- [Remnux](https://remnux.org/)
- [Tools by hasherezade](https://hasherezade.github.io/)
- [IDA](https://hex-rays.com/ida-free/)
- [FLARE Floss](https://github.com/mandiant/flare-floss)
- [BinaryNinja](https://binary.ninja/)
- [BinaryPig](https://github.com/endgameinc/binarypig)
- [Ghidra🦅](https://ghidra-sre.org/)
- [HxD](https://mh-nexus.de/en/hxd/)
- [Redare2](https://github.com/radareorg/radare2)
- [TheMatrix](https://github.com/enkomio/thematrix) Project created to ease the malware analysis process
- [OllyDbg](https://www.ollydbg.de/)
- [oletools](https://github.com/decalage2/oletools)
- [The Sleuth Kit/Autopsy](https://www.sleuthkit.org/)
- [Sandboxie](https://www.sandboxie.com/)
- [Cuckoo Sandbox](https://cuckoosandbox.org/)

#### Malware-IOC-Detection-Data-Dumps
- [vx-underground samples](https://samples.vx-underground.org/samples/Families/)
- [jstrosch Samples](https://github.com/jstrosch/malware-samples)
- [DigitalSide Threat-Intel Repo](https://osint.digitalside.it/)
- [MalwareBazar](https://bazaar.abuse.ch/browse/)
- [DailyIOC](https://github.com/StrangerealIntel/DailyIOC)
- [Valhalla Yara Rules](https://valhalla.nextron-systems.com/)
- [Yara Rules Project](https://github.com/Yara-Rules)
- [Virustotal Yara](https://github.com/VirusTotal/yara)
- [Florian Roth](https://github.com/Neo23x0/signature-base)

## Purple-Red-Team-Resources
- [Photon Crawler](https://hakin9.org/photon-incredibly-fast-crawler-designed-for-osint/") 
- [Subcrawl](https://github.com/hpthreatresearch/subcrawl") 
- [Unofficial OWASP Tool Distro](https://falconspy.medium.com/unofficial-oscp-approved-tools-b2b4e889e707)
- [APTSimulator](https://github.com/NextronSystems/APTSimulator)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team/)
- [Metta](https://github.com/uber-common/metta)
- [Metasploit Framework](https://github.com/rapid7/metasploit-framework)
- [Network Flight Simulator](https://github.com/alphasoc/flightsim)
- [Cladera Framework](https://github.com/mitre/caldera)
- [Impacket](https://github.com/SecureAuthCorp/impacket)
- [Cobalt Strike](https://www.cobaltstrike.com/)
- [Brute Ratel C4](https://bruteratel.com/)
- [Exegol](https://github.com/ShutdownRepo/Exegol)
- [EmpireProject](https://github.com/EmpireProject)
- [Reubeus](https://github.com/GhostPack/Rubeus)
- [Responder](https://github.com/lgandx/Responder)
- [Inveigh](https://github.com/Kevin-Robertson/Inveigh)
- [ExploitDB](https://github.com/offensive-security/exploitdb)
- [DumpsterFire](https://github.com/TryCatchHCF/DumpsterFire)

### /usr/bin
- [NYAN-x-CAT Repo](https://github.com/NYAN-x-CAT)
- [Sulealothman Repo](https://github.com/sulealothman/MysteryLegacyPenetrationTools)
- [Matterpreter Repo](https://github.com/matterpreter?tab=repositories)

## Cloud-Things
- [Azure AD IR Guide](https://misconfig.io/azure-ad-incident-response-life-cycle-tools/)

### Tools
- [Basic Blob Finder](https://github.com/joswr1ght/basicblobfinder) POC tool to hunt for public Azure storage containers and enumerate the blobs


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







