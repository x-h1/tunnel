#!/bin/bash
wget https://raw.githubusercontent.com/x-h1/tunnel/master/gh -O /root/.gh
source /root/.gh
clear
# // FONT color configuration | RECOD COMUNITY
Green="\e[92;1m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}--->${FONT}"
ERROR="${RED}[ERROR]${FONT}"
GRAY="\e[1;30m"
NC='\e[0m'
red='\e[1;31m'
green='\e[0;32m'
green() { echo -e "\\033[32;1m${*}\\033[0m"; }
red() { echo -e "\\033[31;1m${*}\\033[0m"; }
export OKEY="[${GREEN} OKEY ${NC}]";
###########
KANAN="\033[1;32m<\033[1;33m<\033[1;31m<\033[1;31m$NC"
KIRI="\033[1;32m>\033[1;33m>\033[1;31m>\033[1;31m$NC"
###########
start=$(date +%s)
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1
sleep 2
apt update -y
apt install curl -y
apt install sudo -y
# // configuration GET | RECOD COMUNITY
NAMES=$(whoami)
IMP="wget -q -O"
CHATID=""
LOCAL_DATE="/usr/bin/"
MYIP=$(curl -sS ipv4.icanhazip.com)
CITY=$(curl -s ipinfo.io/city)
ORGME=$(curl -s ipinfo.io/org)
TIME=$(date +'%Y-%m-%d %H:%M:%S')
tokgit="" 
GITHUB_CMD="https://tunnel-e7c.pages.dev"
NAMECOM=$(curl -sS https://raw.githubusercontent.com/zhets/izinsc/main/ip | grep $MYIP | awk '{print $2}')
url_izin="https://raw.githubusercontent.com/zhets/izinsc/main/ip"
OS=$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')
dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
Date_list=$(date +"%Y-%m-%d" -d "$dateFromServer")

secs_to_human() {
echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}

INS="apt-get install -y"
start=$(date +%s)
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
function print_ok() {
echo -e "${BLUE}[XD TUNNEL]${FONT}${KIRI}${YELLOW} $1 ${FONT}"
sleep 4
}

function print_error() {
echo -e "${ERROR} ${REDBG} $1 ${FONT}"
sleep 2
}

function is_root() {
if [[ 0 == "$UID" ]]; then
cd /root
print_ok "Root user Start installation process"
else
echo -e " ┌─────────────────────────────────────────────────────────┐"
echo -e "─│                        ${BLUE}WELCOME TO${NC}                       │─"
echo -e "─│    ${YELLOW}┌─┐┬ ┬┌┬┐┌─┐┌─┐┌─┐┬─┐┬┌─┐┌┬┐  ┌─┐┬─┐┌─┐┌┬┐┬┬ ┬┌┬┐${NC}    │─"
echo -e "─│    ${YELLOW}├─┤│ │ │ │ │└─┐│  ├┬┘│├─┘ │   ├─┘├┬┘├┤ │││││ ││││${NC}    │─"
echo -e "─│    ${YELLOW}┴ ┴└─┘ ┴ └─┘└─┘└─┘┴└─┴┴   ┴   ┴  ┴└─└─┘┴ ┴┴└─┘┴ ┴${NC}    │─"
echo -e " └─────────────────────────────────────────────────────────┘"
echo -e "                     ${Green}INFORMASI AUTOSCRIPT${NC}"
echo -e "─────────────────────────────────────────────────────────────"
echo -e "                       ${BLUE}IP${NC} ${YELLOW}$MYIP${NC}"
echo -e "             ${RED}VPS anda belum memiliki akses [root]${NC}"
echo -e "     ${RED}Untuk Saat ini anda belum bisa melakukan instalasi"
echo -e "   ${RED}Silahkan root terlebih dahulu VPS anda, agar AutoScript"
echo -e "            ${RED}dapat dijalankan di VPS anda saat ini."
echo -e "                        ${BLUE}[XDVPN TUNNELING]${NC}"
echo -e "─────────────────────────────────────────────────────────────"
echo -e "                       ${YELLOW}KONTAK REGISTRASI${NC}"
echo -e "                         ${BLUE}|Telegram: @xdxl_store${NC}"
echo -e "─────────────────────────────────────────────────────────────"
echo -e " "
rm *
exit 0
fi

}
judge() {
if [[ 0 -eq $? ]]; then
print_ok "$1 ${FONT}"
sleep 1
fi
}
function nginx_install() {
# // Checking System
if [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "ubuntu" ]]; then
judge "Setup nginx $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
# // sudo add-apt-repository ppa:nginx/stable -y 
sudo apt-get install nginx -y 
elif [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "debian" ]]; then
judge "Setup nginx $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
apt -y install nginx 
else
judge "${ERROR} Your OS Is Not Supported ( ${YELLOW}$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')${FONT} )"
# // exit 1
fi

}
function LOGO() {
echo -e "
 ┌─────────────────────────────────────────────────────────┐
─│                        ${BLUE}WELCOME TO${NC}                       │─
─│    ${YELLOW}┌─┐┬ ┬┌┬┐┌─┐┌─┐┌─┐┬─┐┬┌─┐┌┬┐  ┌─┐┬─┐┌─┐┌┬┐┬┬ ┬┌┬┐${NC}    │─
─│    ${YELLOW}├─┤│ │ │ │ │└─┐│  ├┬┘│├─┘ │   ├─┘├┬┘├┤ │││││ ││││${NC}    │─
─│    ${YELLOW}┴ ┴└─┘ ┴ └─┘└─┘└─┘┴└─┴┴   ┴   ┴  ┴└─└─┘┴ ┴┴└─┘┴ ┴${NC}    │─
 └─────────────────────────────────────────────────────────┘"

}
function soket() {
clear
judge "Instalasi SSH WebSocket"
cd
wget ${XDVPN}/python.zip
cd /usr/sbin
unzip python.zip
rm python.zip
cd
wget -O /etc/systemd/system/tunws@.service "${GITHUB_REPO}/tunws.service" >/dev/null 2>&1
chmod +x /usr/sbin/socdb.py
chmod +x /usr/sbin/soceb.py
chmod +x /usr/sbin/soced.py
chmod +x /usr/sbin/soceg.py
chmod +x /usr/sbin/socep.py
chmod +x /usr/sbin/socey.py
chmod +x /usr/sbin/sochs.py
chmod +x /usr/sbin/socpn.py
chmod +x /usr/sbin/soctt.py
chmod +x /etc/systemd/system/tunws@.service
chmod +x /usr/sbin/tunws.conf

}
function install_xray() {
clear 
judge "Instalasi Core Xray 1.7.5 Version"
curl -s ipinfo.io/city >>/etc/xray/city
curl -s ipinfo.io/org | cut -d " " -f 2-10 >>/etc/xray/isp
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version 1.7.5
curl https://rclone.org/install.sh | bash
printf "q\n" | rclone config
cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/yha.pem
wget -O /root/.config/rclone/rclone.conf "${GITHUB_REPO}/rclone.conf" >/dev/null 2>&1
wget -O /etc/xray/config.json "${GITHUB_REPO}/config.json" >/dev/null 2>&1 
wget -O /usr/bin/xray/xray "${GITHUB_REPO}/xray.linux.64bit" >/dev/null 2>&1
wget -q -O /etc/ipserver "${GITHUB_REPO}/ipserver" && bash /etc/ipserver >/dev/null 2>&1
chmod +x /usr/bin/xray/xray
cat >/etc/msmtprc <<EOF
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt

account default
host smtp.gmail.com
port 587
auth on
user kimunakiko@gmail.com
from kimunakiko@gmail.com
password nzlm dtag qpbl mrmf
logfile ~/.msmtp.log

EOF

rm -rf /etc/systemd/system/xray.service.d
cat >/etc/systemd/system/xray.service <<EOF
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
#ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
ExecStart=/usr/bin/xray/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target

EOF

}
function download_config() {
cd
rm -rf *
wget -O /etc/haproxy/haproxy.cfg "${GITHUB_REPO}/haproxy.cfg" >/dev/null 2>&1
wget -O /etc/nginx/conf.d/xray.conf "${GITHUB_REPO}/xray.conf" >/dev/null 2>&1
wget -O /etc/nginx/nginx.conf "${GITHUB_REPO}/nginx.conf" >/dev/null 2>&1
wget -O /etc/versisc "${GITHUB_CMD}/Sandi/versi" >/dev/null 2>&1
wget ${GITHUB_REPO}/xdxl.zip >/dev/null 2>&1
unzip xdxl.zip
rm xdxl.zip
chmod +x *
mv * /usr/bin/
cd

cat >/root/.profile <<END
# ~/.profile: executed by Bourne-compatible login shells.
if [ "$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi
mesg n || true
welcomesc
END

   cat >/etc/cron.d/xp_all <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		2 0 * * * root /usr/bin/xp
	END
    chmod 644 /root/.profile
    
    cat >/etc/cron.d/xp_reco <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		0 */48 * * * root /usr/bin/xpreco
	END
	
    cat >/etc/cron.d/clearlog <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		*/15 * * * * root /usr/bin/clelog
	END

    cat >/etc/cron.d/daily_reboot <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		0 1 * * * root /sbin/reboot
	END
 
    cat >/etc/cron.d/res <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		0 */9 * * * /usr/bin/resall
	END

    service cron restart
    cat >/home/daily_reboot <<-END
		5
	END

    cat >/etc/systemd/system/rc-local.service <<-END
		[Unit]
		Description=/etc/rc.local
		ConditionPathExists=/etc/rc.local
		[Service]
		Type=forking
		ExecStart=/etc/rc.local start
		TimeoutSec=0
		StandardOutput=tty
		RemainAfterExit=yes
		SysVStartPriority=99
		[Install]
		WantedBy=multi-user.target
	END

echo "/bin/false" >>/etc/shells
echo "/usr/sbin/nologin" >>/etc/shells
cat >/etc/rc.local <<-END
		#!/bin/sh -e
		# rc.local
		# By default this script does nothing.
		iptables -I INPUT -p udp --dport 5300 -j ACCEPT
		iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
		systemctl restart netfilter-persistent
		systemctl restart udp-custom
		exit 0
	END
chmod +x /etc/rc.local
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local
apt install squid -y
wget -q -O /etc/squid/squid.conf "${GITHUB_CMD}/squid/squid.conf" >/dev/null 2>&1
wget -q -O /etc/default/dropbear "${GITHUB_CMD}/squid/dropbear" >/dev/null 2>&1
wget -q -O /etc/ssh/sshd_config "${GITHUB_CMD}/squid/sshd_config" >/dev/null 2>&1
wget -q -O /etc/Hkvpn.txt "${GITHUB_CMD}/squid/banner" >/dev/null 2>&1
wget ${GITHUB_REPO}/bbrku.sh >/dev/null 2>&1 && chmod +x bbrku.sh && ./bbrku.sh
AUTOREB=$(cat /home/daily_reboot)
SETT=11
if [ $AUTOREB -gt $SETT ]; then
TIME_DATE="PM"
else
TIME_DATE="AM"
fi
}
function acme() {
clear
judge "Instalasi SSL certificate script"
rm -rf /root/.acme.sh
mkdir /root/.acme.sh
curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
chmod +x /root/.acme.sh/acme.sh
/root/.acme.sh/acme.sh --upgrade --auto-upgrade
/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
/root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
# // Success
echo -e "${OKEY} Your Domain : $domain";
sleep 2;
judge "SSL Certificate"
clear;
}
function slowdns(){
judge "Instalasi slowdns"
wget -q -O /etc/nameserver "${GITHUB_REPO}/nameserver" && bash /etc/nameserver >/dev/null 2>&1
judge "Successfully installed slowdns"
}
function ins_vnstat(){
clear
judge "Menginstall Vnstat"
# setting vnstat
# // Installing Vnstat 2.9
apt -y install vnstat > /dev/null 2>&1
/etc/init.d/vnstat restart
apt -y install libsqlite3-dev > /dev/null 2>&1
wget https://humdi.net/vnstat/vnstat-2.6.tar.gz
tar zxvf vnstat-2.6.tar.gz
cd vnstat-2.6
./configure --prefix=/usr --sysconfdir=/etc && make && make install
cd
vnstat -u -i $NET
sed -i 's/Interface "'""eth0""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat
/etc/init.d/vnstat restart
/etc/init.d/vnstat status
rm -f /root/vnstat-2.6.tar.gz
rm -rf /root/vnstat-2.6
judge "Successfully installed Vnstat"
}
function ins_udpmod() {
clear
judge "Instalasi UDP Custom Pro Mod"
cd
mkdir -p /etc/alfudp
mkdir -p /etc/UDPCustom
sudo touch /etc/UDPCustom/udp-custom
sudo apt install -y dos2unix
sudo apt install -y neofetch
wget "${GITHUB_REPO}/udp-custom-linux-amd64" -O /etc/alfudp/udp-custom >/dev/null 2>&1
chmod +x /etc/alfudp/udp-custom
wget -O /etc/udpgw "${GITHUB_REPO}/udpgw" >/dev/null 2>&1
mv /etc/udpgw /bin
chmod +x /bin/udpgw
wget -O /etc/udpgw.service "${GITHUB_REPO}/udpgw.service" >/dev/null 2>&1
wget -O /etc/udp-custom.service "${GITHUB_REPO}/udp-custom.service" >/dev/null 2>&1
mv /etc/udpgw.service /etc/systemd/system
mv /etc/udp-custom.service /etc/systemd/system
chmod 640 /etc/systemd/system/udpgw.service
chmod 640 /etc/systemd/system/udp-custom.service
systemctl daemon-reload
systemctl enable udpgw
systemctl start udpgw
systemctl enable udp-custom
systemctl start udp-custom
wget "${GITHUB_REPO}/udp.json" -O /etc/alfudp/config.json >/dev/null 2>&1
chmod +x /etc/alfudp/config.json
judge "Successfully installed UDP Custom"
}
function ins_limit() {
clear
judge "Instalasi Limit Qouta & IP"
cd
wget ${GITHUB_REPO}/limitbos && chmod +x limitbos && ./limitbos >/dev/null 2>&1
rm -rf limitbos
judge "Successfully installed Limit Qouta & IP"
}
function configure_nginx() {
# // nginx config | XDVPN COMUNITY
clear
cd
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
clear
judge "Nginx configuration"
}
function ALFVPNSCRIPT() {
echo ""
}
xlosx() {
    IZIN=$(curl -sS $url_izin | awk '{print $2}' | grep $MYIP)
    if [ "$MYIP" = "$IZIN" ]; then
        ALFVPNSCRIPT
    else
        clear
        echo -e " ┌─────────────────────────────────────────────────────────┐"
        echo -e "─│                        ${BLUE}WELCOME TO${NC}                       │─"
        echo -e "─│    ${YELLOW}┌─┐┬ ┬┌┬┐┌─┐┌─┐┌─┐┬─┐┬┌─┐┌┬┐  ┌─┐┬─┐┌─┐┌┬┐┬┬ ┬┌┬┐${NC}    │─"
        echo -e "─│    ${YELLOW}├─┤│ │ │ │ │└─┐│  ├┬┘│├─┘ │   ├─┘├┬┘├┤ │││││ ││││${NC}    │─"
        echo -e "─│    ${YELLOW}┴ ┴└─┘ ┴ └─┘└─┘└─┘┴└─┴┴   ┴   ┴  ┴└─└─┘┴ ┴┴└─┘┴ ┴${NC}    │─"
        echo -e " └─────────────────────────────────────────────────────────┘"
        echo -e "                    MODE INSTALASI SCRIPT"
        echo -e "─────────────────────────────────────────────────────────────"
        echo -e "   ${BLUE}[1]${NC} ${RED}•${NC} GUNAKAN ${BLUE}LISENSI${NC} MODE"
        echo -e "   ${BLUE}[2]${NC} ${RED}•${NC} GUNAKAN ${BLUE}TRIAL${NC} MODE"
        echo -e "─────────────────────────────────────────────────────────────"
        read -p "Select From Options [1-2] : " modins
        case $modins in
        1) clear ; PelangganRegistrasiPr ;;
        2) clear ; PelangganRegistrasiTr ;;
        *) clear ; rm tunnel ; echo -e "${RED}Pilihan tidak difahami oleh sistem${NC}" ; echo -e "${YELLOW}Silahkan ulangi kembali instalasi Script${NC}" ; echo " " ; exit 0 ;;
        esac
    fi
}
function restart_system() {
TIMES="10"
KEY=""
URL="https://api.telegram.org/bot$KEY/sendMessage"
ISPX=$(cat /etc/xray/isp)
ididnem=$(curl -sS $url_izin | grep $MYIP | awk '{print $6}')
TEXT="
<code>───────────────────────</code>
<b>  ✨ AUTOSCRIPT XDTUNNEL ✨️</b>
<code>───────────────────────</code>
<code>Client ID :</code> <code>${ididnem}</code>
<code>Domain    :</code> <code>${domain}</code>
<code>IP VPS    :</code> <code>${MYIP}</code>
<code>Linux     :</code> <code>$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')</code>
<code>Nama ISP  :</code> <code>${ISPX}</code>
<code>Area ISP  :</code> <code>${CITY}</code>
<code>Status    :</code> <code>${tipee}</code>
<code>Waktu     :</code> <code>$(date +'%H:%M:%S')</code>
<code>Tanggal   :</code> <code>$(date +'%Y-%m-%d')</code>
<code>MasaAktif :</code> <code>${exp9} Hari</code>
<code>Exp Sc    :</code> <code>${exp10}</code>
<code>Status Sc :</code> <code>${insstatus}</code>
<code>Order By  :</code> <code>${order}</code>
<code>───────────────────────</code>
<code>Notifikasi Otomatis Dari
Installer Autosc</code>
"
    curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
    cp /etc/openvpn/*.ovpn /var/www/html/
    sed -i "s/xxx/${domain}/g" /var/www/html/index.html
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/${MYIP}/g" /etc/squid/squid.conf
    chown -R www-data:www-data /etc/msmtprc    
    cd
    curl https://raw.githubusercontent.com/xxxserxxx/gotop/master/scripts/download.sh | bash && chmod +x gotop && sudo mv gotop /usr/local/bin/
    systemctl daemon-reload
    systemctl enable client
    systemctl enable server
    systemctl enable tunws@sochs
    clear
    clear
    LOGO
    echo "   ┌─────────────────────────────────────────────────────┐"
    echo "   │       >>> Service & Port                            │"
    echo "   │   - Open SSH                : 443, 80, 22           │"
    echo "   │   - UDP Custom HC           : 1-65535               │"
    echo "   │   - DNS [SLOWDNS]           : 443, 80, 53           │"
    echo "   │   - Dropbear                : 443, 109, 143         │"
    echo "   │   - Dropbear Websocket      : 443, 109              │"
    echo "   │   - SSH Websocket SSL       : 443                   │"
    echo "   │   - SSH Websocket           : 80                    │"
    echo "   │   - OpenVPN SSL             : 443                   │"
    echo "   │   - OpenVPN Websocket SSL   : 443                   │"
    echo "   │   - OpenVPN TCP             : 443, 1194             │"
    echo "   │   - OpenVPN UDP             : 2200                  │"
    echo "   │   - Nginx Webserver         : 443, 80, 81           │"
    echo "   │   - Haproxy Loadbalancer    : 443, 80               │"
    echo "   │   - DNS Server              : 443, 53               │"
    echo "   │   - DNS Client              : 443, 88               │"
    echo "   │   - OpenVPN Websocket SSL   : 443                   │"
    echo "   │   - XRAY [DNST / SLOWDNS]   : 443, 53               │"
    echo "   │   - XRAY Vmess TLS          : 443                   │"
    echo "   │   - XRAY Vmess gRPC         : 443                   │"
    echo "   │   - XRAY Vmess None TLS     : 80                    │"
    echo "   │   - XRAY Vless TLS          : 443                   │"
    echo "   │   - XRAY Vless gRPC         : 443                   │"
    echo "   │   - XRAY Vless None TLS     : 80                    │"
    echo "   │   - Trojan gRPC             : 443                   │"
    echo "   │   - Trojan WS               : 443                   │"
    echo "   │   - Shadowsocks WS          : 443                   │"
    echo "   │   - Shadowsocks gRPC        : 443                   │"
    echo "   │                                                     │"
    echo "   │      >>> Server Information & Other Features        │"
    echo "   │   - Timezone                : Asia/Jakarta (GMT +7) │"
    echo "   │   - Autoreboot On           : $AUTOREB:00 $TIME_DATE GMT +7        │"
    echo "   │   - Auto Delete Expired Account                     │"
    echo "   │   - Fully automatic script                          │"
    echo "   │   - VPS settings                                    │"
    echo "   │   - Admin Control                                   │"
    echo "   │   - Backup Data & Restore Data                      │"
    echo "   │   - Full Orders For Various Services                │"
    echo "   └─────────────────────────────────────────────────────┘"
    secs_to_human "$(($(date +%s) - ${start}))"
    judge "Restart ALL Service & Reboot"
    sleep 3
    systemctl daemon-reload
    systemctl enable tunws@sochs >> /dev/null 2>&1
    systemctl start tunws@sochs >> /dev/null 2>&1
#    systemctl enable tunws@soctt >> /dev/null 2>&1
#    systemctl start tunws@soctt >> /dev/null 2>&1
    systemctl restart nginx
    systemctl restart xray
    systemctl restart rc-local
    systemctl restart client
    systemctl restart server
    systemctl restart tunws@sochs
#    systemctl restart tunws@soctt
    systemctl restart udpgw
    systemctl restart udp-custom
    systemctl restart badvpn1
    systemctl restart badvpn2
    systemctl restart badvpn3
    systemctl restart openvpn
    systemctl restart cron
    systemctl restart haproxy
    systemctl restart squid
    systemctl restart ssh
    systemctl restart dropbear
    reboot
}
function make_folder_xray() {
# // Make Folder Xray to accsess
mkdir -p /etc/bot
mkdir -p /etc/xray
mkdir -p /etc/sshku
mkdir -p /etc/vmess
mkdir -p /etc/vless
mkdir -p /etc/trojan
mkdir -p /etc/shadowsocks
mkdir -p /etc/limit
mkdir -p /etc/limit/vmess
mkdir -p /etc/limit/vless
mkdir -p /etc/limit/trojan
mkdir -p /etc/limit/shadowsocks
mkdir -p /etc/limit/vmess/ip
mkdir -p /etc/limit/vless/ip
mkdir -p /etc/limit/trojan/ip
mkdir -p /etc/limit/shadowsocks/ip
mkdir -p /usr/bin/xray
mkdir -p /var/log/xray
chmod +x /var/log/xray
touch /etc/xray/domain
touch /etc/shadowsocks/.shadowsocks.db
touch /etc/trojan/.trojan.db
touch /etc/vless/.vless.db
touch /etc/vmess/.vmess.db
touch /etc/sshku/.sshku.db
touch /etc/bot/.bot.db
touch /var/log/xray/access.log
touch /var/log/xray/error.log
echo "& plughin Account" >>/etc/vmess/.vmess.db
echo "& plughin Account" >>/etc/vless/.vless.db
echo "& plughin Account" >>/etc/trojan/.trojan.db
echo "& plughin Account" >>/etc/shadowsocks/.shadowsocks.db
echo "& plughin Account" >>/etc/vmess/vmess.txt
echo "& plughin Account" >>/etc/vless/vless.txt
echo "& plughin Account" >>/etc/trojan/trojan.txt
echo "& plughin Account" >>/etc/shadowsocks/shadowsocks.txt
echo "& plughin Account" >>/etc/vmess/kovm.txt
echo "& plughin Account" >>/etc/vless/kovl.txt
echo "& plughin Account" >>/etc/trojan/kotr.txt
echo "& plughin Account" >>/etc/shadowsocks/koss.txt 
echo "& plughin Account" >>/etc/vmess/recovm.txt
echo "& plughin Account" >>/etc/vless/recovl.txt
echo "& plughin Account" >>/etc/trojan/recotr.txt
echo "& plughin Account" >>/etc/shadowsocks/recoss.txt
rm -rf /etc/bot/.bot.db

}

function dependency_install() {
echo ""
echo "Please wait to install Package..."
apt-get update
clear
judge "Update configuration"
clear
judge "Instalasi openvpn easy-rsa"
source <(curl -sL ${GITHUB_CMD}/BadVPN/ins-badvpn)
clear
judge "Instalasi vpn"
wget -O /etc/pam.d/common-password "${GITHUB_CMD}/Sandi/common-password" >/dev/null 2>&1
chmod +x /etc/pam.d/common-password
source <(curl -sL ${GITHUB_CMD}/OpenVPN/openvpn)

DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/altgr select The default for the keyboard layout"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/compose select No compose key"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/ctrl_alt_bksp boolean false"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layoutcode string de"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select English"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/modelcode string pc105"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/model select Generic 105-key (Intl) PC"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/optionscode string "
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/store_defaults_in_debconf_db boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/switch select No temporary switch"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/toggle select No toggling"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_layout boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_options boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_layout boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_options boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variantcode string "
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variant select English"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/xkb-keymap select "
clear
judge "Instalasi dropbear"
apt-get install dropbear -y

}
function install_sc() {
dependency_install
acme
nginx_install
configure_nginx
download_config
install_xray
soket
slowdns
ins_vnstat
ins_udpmod
ins_limit
restart_system
}
function add_domain() {
clear
echo -e " ┌─────────────────────────────────────────────────────────┐"
echo -e "─│                        ${BLUE}WELCOME TO${NC}                       │─"
echo -e "─│    ${YELLOW}┌─┐┬ ┬┌┬┐┌─┐┌─┐┌─┐┬─┐┬┌─┐┌┬┐  ┌─┐┬─┐┌─┐┌┬┐┬┬ ┬┌┬┐${NC}    │─"
echo -e "─│    ${YELLOW}├─┤│ │ │ │ │└─┐│  ├┬┘│├─┘ │   ├─┘├┬┘├┤ │││││ ││││${NC}    │─"
echo -e "─│    ${YELLOW}┴ ┴└─┘ ┴ └─┘└─┘└─┘┴└─┴┴   ┴   ┴  ┴└─└─┘┴ ┴┴└─┘┴ ┴${NC}    │─"
echo -e " └─────────────────────────────────────────────────────────┘"
echo -e "               ${Green}SILAHKAN PILIH SUBDOMAIN VPS ANDA${NC}"
echo -e "─────────────────────────────────────────────────────────────"
echo -e "   ${BLUE}[1]${NC} ${RED}• ${NC}Gunakan Subdomain Pribadi"
echo -e "   ${BLUE}[2]${NC} ${RED}• ${NC}Gunakan Subdomain Otomatis"
echo -e "─────────────────────────────────────────────────────────────"
read -p "   Silahkan Pilih Nomor 1 atau 2 : " host
echo ""
if [[ $host == "1" ]]; then
echo -e "   ${Green}Silahkan masukkan Subdomain Anda ${NC}"
read -p "   Subdomain: " dompri
echo $dompri > /etc/xray/domain
echo ""
elif [[ $host == "2" ]]; then
# // String / Request Data
export Random_Number=$( </dev/urandom tr -dc 1-$( curl -s ${GITHUB_CMD}/domain/domen.txt | grep -E Jumlah | cut -d " " -f 2 | tail -n1 ) | head -c1 | tr -d '\r\n' | tr -d '\r');
export Domain_Hasil_Random=$( curl -s curl -s ${GITHUB_CMD}/domain/domen.txt | grep -E Domain$Random_Number | cut -d " " -f 2 | tr -d '\r' | tr -d '\r\n');
export DOMAIN_BARU="$(</dev/urandom tr -dc a-x1-9 | head -c5 | tr -d '\r' | tr -d '\r\n').${Domain_Hasil_Random}";
export EMAIL_CLOUDFLARE="padmasariyani678@gmail.com";
export API_KEY_CLOUDFLARE="855bd2da5b0769a7a7edd011eec29451c41b3";
# // DNS Only Mode
export ZONA_ID=$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones?name=${Domain_Hasil_Random}&status=active" -H "X-Auth-Email: ${EMAIL_CLOUDFLARE}" -H "X-Auth-Key: ${API_KEY_CLOUDFLARE}" -H "Content-Type: application/json" | jq -r .result[0].id );
export RECORD=$(curl -sLX POST "https://api.cloudflare.com/client/v4/zones/${ZONA_ID}/dns_records" -H "X-Auth-Email: ${EMAIL_CLOUDFLARE}" -H "X-Auth-Key: ${API_KEY_CLOUDFLARE}" -H "Content-Type: application/json" --data '{"type":"A","name":"'${DOMAIN_BARU}'","content":"'${MYIP}'","ttl":0,"proxied":false}' | jq -r .result.id);
export RESULT=$(curl -sLX PUT "https://api.cloudflare.com/client/v4/zones/${ZONA_ID}/dns_records/${RECORD}" -H "X-Auth-Email: ${EMAIL_CLOUDFLARE}" -H "X-Auth-Key: ${API_KEY_CLOUDFLARE}" -H "Content-Type: application/json" --data '{"type":"A","name":"'${DOMAIN_BARU}'","content":"'${MYIP}'","ttl":0,"proxied":false}');
# // Input Result To VPS
echo $DOMAIN_BARU >/etc/xray/domain
echo "subdomain : $DOMAIN_BARU"
fi
domain=$(cat /etc/xray/domain)

}
# // Prevent the default bin directory of some system xray from missing
clear
apete_apdet() {
apt-get update -y
apt-get upgrade -y
apt-get clean all
apt-get autoremove -y
apt install dnsutils
apt-get install net-tools
apt-get install tcpdump
apt-get install dsniff -y
apt install grepcidr
${INS} debconf-utils
sudo apt-get remove --purge exim4 -y
sudo apt-get remove --purge ufw firewalld -y
${INS} --no-install-recommends software-properties-common
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
${INS} htop lsof tar wget curl ruby zip unzip p7zip-full python3-pip python haproxy vnstat libc6 util-linux build-essential msmtp-mta ca-certificates bsd-mailx iptables iptables-persistent netfilter-persistent net-tools openssl ca-certificates gnupg gnupg2 ca-certificates lsb-release gcc make cmake git screen socat xz-utils apt-transport-https gnupg1 dnsutils cron bash-completion ntpdate chrony jq openvpn easy-rsa
${INS} libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools libevent-dev
apt -y install chrony
ntpdate pool.ntp.org
apt install zip -y
timedatectl set-ntp true
systemctl enable chronyd && systemctl restart chronyd
systemctl enable chrony && systemctl restart chrony
timedatectl set-timezone Asia/Jakarta
chronyc sourcestats -v
chronyc tracking -v
date
}
is_root
apete_apdet
clear
clear
LOGO
echo -e "    ${RED}JANGAN INSTALL SCRIPT INI MENGGUNAKAN KONEKSI VPN!!!${FONT}"
echo -e "          ${YELLOW}Gunakanlah SCRIPT ini dengan sewajarnya${FONT}"
echo -e "                      ${Green}[XDVPN TUNNELING]${FONT}"
echo ""
read -p " Lanjutkan untuk menginstall [y/n] : " menu_num

case $menu_num in
y)
make_folder_xray
add_domain
install_sc
;;
*)
echo -e "${RED}You wrong command !${FONT}"
rm *
;;
esac
