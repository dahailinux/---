# 信息安全框架-生产服务器部分
信息安全框架-生产服务器部分

网站安全系统架构							
					
![image](https://github.com/dahailinux/---/assets/54297681/dca40627-2b32-4233-adec-7bf1fbe57855)

No.	Name	requirements					
1	超级系统监控	监控操作系统上所有行为	随便一个ping命令就知道怎么导致的，出现了rootkit能立刻发现		Skyline Etsy	Rappor	psacct
2	超级网络监控	监控网络上所有数据包	发现一切网络行为，除了加密数据都能捕获到数据；	NTA系统	ELKB	NIDS	Moloch
3	cdn/游戏盾	主用(Cloudflare)、备用(Toffs)、灾备(自建)/国内301服务器防被墙	加速乐，CF，Akamai、Incapsula/vishnuplus/greypanel灰域/toffs/华为云/阿里云等国外节点CDN/cp cdn/vietnam cdn/乐速海盟/aws/；	知道创宇渠道直接买代码，租机器；机房选择：Nexusguard/aws/阿里云/谷歌云/azure/倾城高防/环网高防机房/创科/腾佑/E升网络/温州IDC/丰网/众生/龙宇信通/乐速海盟/幸尚/佛山高仿/疯猫网络/集众力科/广东天盈/南方互联/香港葵芳	自建CDN：fikker/cdnplus/cdnbest/cdnfly	CDN监控：监控宝/听云/IP地址库/dnsdun/cloudxns/dnspod/全速云/nexusguard	
4	防火墙	保护端口/一定要有防端口扫描的功能，扫端口就有可能发现漏洞并渗透	应用应用层防护，除了加密数据搞不定，比如dns隧道防护，smb攻击防护，端口扫描防护等各应用层的防御，有完善的攻击库；	TIP威胁情报系统，收集日志、SOC、态势感知，通过情报平台的信息，联动防火墙、交换机和NIDS联动阻断	palo alto， check point, forti.	ClearOS、Endian、SmoothWall、Shorewall、IPFire、Iptables、OPNsense、Untangle 、Perimeter 、pfSense	OpenSnitch/EBPFSnitch基于一个程序做策略的firewall
5	NIPS	网络入侵	新一代防火墙	AgentSmith-HIDS：Hids和Nids结合产品，而且是开源的			
6	waf	aihttps/nginx_lua，使用modesecurity的商业规则；	imperva，F5，软WAF，nsfocus	国产启明星辰最好	对未知web威胁采用自动学习方式和威胁情报方式	Cyberpanel是软WAF，统一控制面板，集成modsecurity付费规则库；	
7	NIDS	内网发起的安全威胁：Moloch	绿盟态势感知	深信服安全感知sip	内核级的病毒只有网络端才能看到连接状态	要求所有网络流量必须经过ids，即使二层交换机之间的通信；	OSquery/Wazuh/onionsecurity/Samhain
8	蜜罐	主动防御，保护真实服务器	McAfee	长亭(D-sensor)伪装欺骗系统	低交互、高交互蜜罐：知道创于	Manuka	
9	HIDS	SWATCH/LIDS/Tripwire/fail2ban	安骑士/云锁/安全狗/OSsec(Wazuh)/ossim/sophos/LogRhythm/QRadar/ArcSight/SIEMonster/Prelude、sqreen/illumio、osquery脸书开源产品、	Falcon CrowdStrike，很好的杀软，Elkeid是字节跳动的HIDS产品，开源的安骑士；	购买管家服务24小时实时相应	Falcon/watchdog(系统死机自动重启)、tripwire(文件md5监控，文件夹md5监控防止增加文件；)	EDR/aide/swatch/lids
10	RASP	应用程序加固	micro focus 	防御反序列化		云防护系统	
11	日志系统	不被黑客篡改，根据时间点重放所有行为；	splunk	SIEM安全运营平台: OSsec(Wazuh)/ossim/	日志集中管理，日志关联，还原完整攻击链；	集中化安全告警平台	
12	云安全	CWPP/CASB/CSPM	Netflix、Capital One和Lyft/Aqua Security	容器安全/k8s安全/虚拟机容器逃逸很常见	安全组/VPC/DDos防护/云WAF/IAM/主机安全产品/SSL证书/云数据库审计系统/态势感知/账户监管/合规性检查/操作审核/风险审核	把云安全日志 传到存储桶里然后使用wazuh进行处理和报警，展示到elk	
13	监控文件被篡改	Security monkey 					
14	主机加固	主机安全规范/主机加固checklist	对docker宿主机进行安全加固/Docker服务安全加固	Linux操作系统加固，setfacl	Grsecurity	 lsm（进程白名单）	apparmor可以限制进程的网络访问
15	K8s安全	Docker的最佳安全实践(docker和CIS共同定制)	镜像安全扫描器：Clair/docker-bench-secruity	https://www.freebuf.com/column/152398.html	腾讯云容器安全服务，tcss	容器和镜像安全扫描	Trivy、Claire、Anchore Engine、Quay、Docker hub 和 GCR
16	移动安全框架	（MobSF）是针对Android和iOS移动应用程序的自动化恶意软件分析、安全评估和渗透测试框架					
17	安全风险管理程序	GRC	为企业安全系统建立标准化模板，构建GRC统一服务平台，在软件上帮组企业做安全系统				
18	IAST精准漏扫	默安-雳鉴IAST	新思Seeker软件	开源网安SecZone VulHunter	墨云VackBot等，国外：Contrast Security等		
19	Devsecops	悬镜Xmirror	和开发同步进行、敏捷开发；	灰盒测试技术	自动化软件开发和发布流程		
20	基线检查	青藤CIS	cis benchmark: cis-cat pro/cis controls指导手册	MBSA/SRAY/NESSUS/SquirrelForOracle			
21	开发安全	安全开发周期SDL	SoneQube/Dependabot/npm audit				
22	app安全	ssl pinning	加固防逆向	请求做双向加密，不允许中间人看请求信息	保护SDK和access key，用阿里云服务防止外泄	APP漏扫挖掘	一定要加密和加壳
23	沙箱系统	cuckoo					
24	Nta	无独立产品，结合ids、siem、沙箱等系统增加一个功能；	核心在于上述分析分析不是简单的基于规则匹配，而是高级的数据分析（Analytics），基于如ML和AI技术对流量进行画像，找到异常的流量	colasoft、安天/国外代表 Cisco 主导的 OpenSOC/Metron，Darktrace、AppNeta、CA Technologies、Corvil、Genie Networks	siem做了所有日志系统检测，他做了所有流量检测，互相配合	网络攻击payload的还原提取和性质分析，解析应用层文件和“沙箱系统”进行对接检测；	
25	ndr	产品是必要的，流量分析,适用于混合云,知道创宇；		Ioc 情报威胁平台：CrowdStrike、FireEye、Talos和Kaspersky	系统文件完整性检测 tripwire		
26	数据库审计	即使被入侵也拿不走数据	天融信/绿盟/启明星辰/深信服	sql注入报警	yearning	arkcontrol	
27	数据库透明加密	主动防御		重要字段加密	dbms内核层加密	dbms外层加密	
28	数据库漏扫	数据库堡垒机		xsecure-DBscan	cyberark		
29	数据库防火墙	刷库脱裤撞库		虚拟补丁	Xsecure-DBfirewall		
30	数据脱敏	数据库被盗也没事		测试环境信息打乱顺序			
31	git代码泄露	防止员工网上发布代码	Hawkeye				
32	自动漏扫系统	主动防御	awvs	metasploit厂家Rapid7	dast, sast, iast, 黑白灰扫描方式	Openvas/Nexpose	
33	代码审计	主动防御	Gerrit	 fortify SCA和Cxsuite，360代码卫士属于国产。seay	Raptor、vcg	奇安信、匠迪技术、SECZONE（开源网安）、三零卫士	
34	0day搜索	主动防御	Tor黑市	大数据安全情报中心来防御	SElinux	openrasp	Apparmor
35	堡垒机/特权账号管理平台	ssh安全/数据库/web平台登录	商业：齐治堡垒机，Citrix XenApp	流程管理:cyberark	支持RDS协议，有虚拟应用功能，不用登录机器就能使用应用发布软件来运维工作	开源软件：Jumpserver、Teleport、GateOne、CrazyEye	
36	漏洞预警平台	付费漏洞通告平台（Risk Based Security平台、蓝队云服务、阿里云先知、启明星辰的安全通告）	SRC平台或雇国际黑客定期渗透测试	confluence/OpenCVE（开源平台）	"全球免费漏洞库  https://cassandra.cerias.purdue.edu/CVE_changes/today.html
https://www.cnvd.org.cn/flaw/list.htm
https://nvd.nist.gov/"	最新漏洞通告预警网站	Qualys,Inc.是一家世界领先的提供漏洞管理与合规性解决方案SaaS服务的提供商
36	漏洞管理平台	洞察』是宜信公司开源漏洞管理平台，被OWASP收录	天境漏洞管理平台	Nessus/Tenable/	vms		
37	DOH防域名劫持	利用https转换成dns进行解析，客户端指向https的cdn就行了	DOH				
38	Rootkit检测程序	有些长期存在系统中的rootkit是无法查找的，只有执行时会触发报警，但是不容易找源文件，用杀毒软件保护住内核就问题不大了；	HIDS属于用户态，杀软属于内核态，病毒一旦进入内核就防不住了，所以必须守住内核这一层；	保护内核不被入侵,壳外程序都能检测到,内核二进制程序无法监测	卡巴斯基rootkit杀软	lsmod	监控目录，shell脚本集成到zabbix对目录下增加的文件或子目录出现变动就发邮件；
39	大数据威胁情报中心	用来防御未知威胁：0day和APT	安全情报中心发来的最新安全知识的收集和共享，自己经验总结；				
40	SOC/SIEM	安全运营中心：日志统一管理及基于时间统一调用查看，监控报警平台统一，各安全系统统一管理，日志可视化；	OSSIM、Elastic SIEM、Opensoc、ngsoc、Panther、splunk、logrhythm	所有运维系统，应用系统，中间件，网络系统，安全系统统一审计平台；	通过 对日志的汇总和梳理，快速串联黑客的完整攻击链，完成运营工作	Google Rapid Response（事件响应平台）	联合查询原理：在各日志中记录特殊的标记，用户ID，IP，时间，设备ID；
41	SOAR	soc + 自动相应 + 内容分享沟通平台	绿盟科技	安全运营平台的趋势			
42	补丁服务器	Satellite补丁服务器	Qualys：免费补丁扫描系统				
43	渗透平台	半自动 & 自动化	安恒信息、安络科技、四叶草安全、四维创智、雨人网安、锦行科技、安百科技、悬镜 AI、安络科技				
44	SDL	悬镜 AI、SECZONE（开源网安）、微软、华为、默安科技、海云安		Secureheaders			
45	网络和主机基线配置核查系统：安恒信息、思福迪、绿盟科技、启明星辰、聚铭网络						
46	网络电子取证系统	远程电子数据取证	bro：单台机器入侵分析（zeek）	procdump抓取内存快照	Wireshark& Tshark	FEX imager/datanumen disk image	dd/magnet ram capture
47	攻防实验室・线上：安恒信息、南京赛宁、西普、安码科技、益安在线	Vulhub，靶机平台					
48	公有云	阿里云、腾讯云、aws、azure、Googlecloud、香港nexusguard					
49	账密安全	密码服务器：Bitwarden，Psono，Teampass，统一密码管理；	密钥管理服务器，配置文件和客户端读取密钥（阿里云也有KMS系统）	密码服务器（统一管理），keepass（分散管理），密码后面自己加上后缀，比如kobe。这样密码更安全，被偷也不怕；	John the Ripper（shadow密码爆破）/zinaer系统	单点登录统一身份验证，使用SAML2.0/OAuth2.0/OIDC/CAS协议对接云平台，大部分云平台都支持；	keeper/lastpass/dashlne/1password
50	标准/规范	等保/合规性评估/基线检测/CIS基准	Wazuh cis-cat/信息安全指南, 合规性遵从：FISMA，STIG，HIPPA，CIS，SCAP	openscap(是nist的实现)(做合规检测)oscap-docker做docker的扫描；	风险管理框架（RMF）、网络安全框架（CSF）、隐私框架（PF）	NIST，STIG，CIS，Sarbanes-Oxley Act [SOX]和HIPAA	信息安全标准 CCS、 COBIT 5、ISA 62443-3-3:2013、ISO/IEC 27001:2013、NIST SP 800-53 Rev. 4 CM-8, STIG
51	访问控制	Openldap协议的、saml协议的、Oauth的、CAS协议、OIDC协议等	Yapi 是开源ldap服务器	AAA服务器	单点登录系统SSO	NAC系统	JWT
	LSM	SELinux  AppArmor Smack  Tomoyo Capabilities Domain 					
	指纹扫描系统	企业内网资产扫描Foeye	web网站暴露资产和指纹扫描系统FORadar	FOFA、SODAN			
	安全论坛	https://www.shentoushi.top/secworld	Nosec	90sec	t00ls		
52	物理攻击	用usbguard来防止badusb攻击					
53	人的社工	职责分离、双人审计，DLP系统
