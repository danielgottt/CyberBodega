# https://danielgottt.github.io/CyberBodega/

I like to share resources and information I learn through this github page! Enjoy!!

### UPDATE: I am working diligently on finding a better solution to display the information on this page. There will be more updates in the future!

* [Getting Started](./getting_started.md)
* [Cyber Resources](./cyber_resources.md)
* [Training](./training.md)
* [Blue Team Resources](./blue_team_resources.md)
* [Red Team Resources](./red_team_resources.md)
* [Awesome Lists](./awesome_lists.md)

## Table Of Contents

- [Setup](#setup)
  - [Virtual Machine Applications](#virtual-machine-applications)
  - [Virtual Machine Resources](#virtual-machine-resources)
  - [CTF Websites and Wargames](#ctf-websites-and-wargames)
- [Resources](#resources)
  - [Cyber Scholarships](#cyber-scholarships)
  - [Malware and Intel Databases](#malware-and-intel-databases)
  - [Cyber Resources and News](#cyber-resources-and-news)
  - [Threat Intelligence](#threat-intelligence)
  - [Open Source Intelligence](#osint)
  - [Websites Providing Cyber Training](#websites-providing-cyber-training)
- [Host Security](#Host_Security)
  - [macOS-based Defense](#macOS-based-defenses)
  - [Windows-based Defense](#Windows-based-defenses)
  - [Threat hunting tools](#Threat-hunting-tools)
- [Network Security](#Network-Security)
  - [Network Security Monitoring](#network-security-monitoring)
  - [Security Information and Event Management](#security-information-and-event-management)
- [Etcetera](#Etcetera)
  - [Open Source System Administrator Tools](#Open-Source-System-Administrator-Tools)
  - [Simulation Training](#simulation-training)
  - [Docker Images for Penetration Testing & Security](#Docker-Images-for-Penetration-Testing-&-Security)
  - [Big Data](#Big-Data)
  - [Other Security Awesome Lists](#Other-Security-Awesome-Lists)
- [Digital Forensics](#Digital-Forensics)
  

# Etcetera
>Everything Else
## Simulation Training
- [APTSimulator](https://github.com/NextronSystems/APTSimulator) - Toolset to make a system look as if it was the victim of an APT attack.
- [Atomic Red Team](https://atomicredteam.io/) - Library of simple, automatable tests to execute for testing security controls.
- [DumpsterFire](https://github.com/TryCatchHCF/DumpsterFire) - Modular, menu-driven, cross-platform tool for building repeatable, time-delayed, distributed security events for Blue Team drills and sensor/alert mapping.
- [Metta](https://github.com/uber-common/metta) - Automated information security preparedness tool to do adversarial simulation.
- [Network Flight Simulator (`flightsim`)](https://github.com/alphasoc/flightsim) - Utility to generate malicious network traffic and help security teams evaluate security controls and audit their network visibility.
- [Cladera Framework](https://github.com/mitre/caldera)

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

## Open Source System Administrator Tools
See [awesome-sysadmin#monitoring](https://github.com/n1trux/awesome-sysadmin#monitoring)

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


