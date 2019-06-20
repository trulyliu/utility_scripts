#!/bin/bash



#===================== Tasks run as root========================================
#Fix locale missing issue
fix_missing_locale()
{
    apt-get update
    apt-get install -y locales sudo software-properties-common openssh-server coreutils
    locale-gen en_US.UTF-8 zh_CN.UTF-8
}

fix_timezone()
{
    timedatectl set-timezone Asia/Shanghai
    timedatectl set-local-rtc 0
    timedatectl set-ntp 1
}

##################link bash#############################
fix_sh()
{
    cd  /bin
    ln -sf bash sh
    cd
}

fix_netdevice_name()
{
    cat > /etc/systemd/network/99-default.link << ____HERE
[Link]
NamePolicy=kernel database onboard slot path
MACAddressPolicy=none
____HERE
}

update_hostname()
{
    MY_HOSTNAME=$1
    if [ -z "$MY_HOSTNAME" ]; then
        return
    fi

    if ! fgrep -q "$MY_HOSTNAME" /etc/hostname; then
      echo $MY_HOSTNAME > /etc/hostname
    fi
}

fix_sshd()
{
    #SSH, Do not allow password authentication
    if grep -q '^#\?PasswordAuthentication' /etc/ssh/sshd_config; then
        sed  -i '/^#\?PasswordAuthentication/c\PasswordAuthentication no' /etc/ssh/sshd_config
    else
        echo "PasswordAuthenticatio no" |tee -a  /etc/ssh/sshd_config
    fi
    if grep -q '^#\?GatewayPorts' /etc/ssh/sshd_config; then
        sed  -i '/^#\?GatewayPorts/c\GatewayPorts yes' /etc/ssh/sshd_config
    else
        echo "GatewayPorts yes" |tee -a  /etc/ssh/sshd_config
    fi
    systemctl restart ssh
}

rename_user()
{
    OLD_USER=$1
    NEW_USER=$2
    if [ -z "$OLD_USER" ] || [ -z "$NEW_USER" ]; then
        echo "old user = [$OLD_USER]  new user = [$NEW_USER]"
        return 1
    fi

    if [ "$OLD_USER" = "$NEW_USER" ]; then
        echo "$OLD_USER = $NEW_USER"
        return 1
    fi
    if ! getent passwd |fgrep -q -w $NEW_USER  && getent passwd |fgrep -q -w $OLD_USER ; then
        usermod -l $NEW_USER $OLD_USER
        usermod -d /home/$NEW_USER -m $NEW_USER
    fi

    if ! getent passwd |fgrep -q -w $NEW_USER ; then
        echo "rename user fail"
        return 1
    fi

    if [ $(id $NEW_USER -gn) != $NEW_USER ]; then
        groupmod -n $NEW_USER $(id $NEW_USER -gn)
    fi
}

add_user()
{
    MUSERNAME=$1
    getent passwd |fgrep -q -w $MUSERNAME  || useradd -m -k  /etc/skel/  -s /bin/bash $MUSERNAME
    getent passwd |fgrep -q -w $MUSERNAME  &&  { echo "$MUSERNAME      ALL=(ALL:ALL) NOPASSWD:ALL"  > /etc/sudoers.d/$MUSERNAME ; gpasswd -a $MUSERNAME adm; gpasswd -a $MUSERNAME dialout; gpasswd -a $MUSERNAME cdrom; gpasswd -a $MUSERNAME floppy; gpasswd -a $MUSERNAME sudo; gpasswd -a $MUSERNAME audio; gpasswd -a $MUSERNAME dip; gpasswd -a $MUSERNAME video; gpasswd -a $MUSERNAME plugdev; gpasswd -a $MUSERNAME netdev; gpasswd -a $MUSERNAME lxd; }
}

add_ssh_key_for_user()
{
    MUSERNAME=$1
    SSHKEY="$2"
    HOMEDIR=$(getent passwd |fgrep -w $MUSERNAME |awk -F: '{print $6}')
    [ -d $HOMEDIR ] && { [ -d $HOMEDIR/.ssh ] || mkdir -p -m 700 $HOMEDIR/.ssh && chown $MUSERNAME:$MUSERNAME $HOMEDIR/.ssh; }
    fgrep -q $(echo "$SSHKEY" |awk '{print $2}') $HOMEDIR/.ssh/authorized_keys 2>/dev/null || { printf '%s' "$SSHKEY" >> $HOMEDIR/.ssh/authorized_keys ; chmod 600 $HOMEDIR/.ssh/authorized_keys; }
}

enable_bbr()
{

fgrep -q -w tcp_bbr /etc/modules || { echo tcp_bbr |tee -a  /etc/modules; }

fgrep -q "#Add by qingchengl" /etc/sysctl.conf || tee -a /etc/sysctl.conf << ____HERE
#Add by qingchengl
# max open files
fs.file-max = 1024000
# max read buffer
net.core.rmem_max = 67108864
# max write buffer
net.core.wmem_max = 67108864
# default read buffer
net.core.rmem_default = 65536
# default write buffer
net.core.wmem_default = 65536
# max processor input queue
net.core.netdev_max_backlog = 4096
# max backlog
net.core.somaxconn = 4096

# resist SYN flood attacks
net.ipv4.tcp_syncookies = 1
# reuse timewait sockets when safe
net.ipv4.tcp_tw_reuse = 1
# turn off fast timewait sockets recycling
net.ipv4.tcp_tw_recycle = 0
# short FIN timeout
net.ipv4.tcp_fin_timeout = 30
# short keepalive time
net.ipv4.tcp_keepalive_time = 1200
# outbound port range
net.ipv4.ip_local_port_range = 10000 65000
# max SYN backlog
net.ipv4.tcp_max_syn_backlog = 4096
# max timewait sockets held by system simultaneously
net.ipv4.tcp_max_tw_buckets = 5000
# TCP receive buffer
net.ipv4.tcp_rmem = 4096 87380 67108864
# TCP write buffer
net.ipv4.tcp_wmem = 4096 65536 67108864
# turn on path MTU discovery
net.ipv4.tcp_mtu_probing = 1

net.ipv6.conf.all.accept_ra = 2
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr

____HERE

sysctl -p

}

install_zsh()
{
    #install vim, git, zsh, buyobu
    apt-get install vim git byobu zsh dialog openssl zsh-theme-powerlevel9k powerline fonts-powerline -y
    update-alternatives --set editor /usr/bin/vim.basic
    fgrep -q '/etc/profile.d' /etc/zsh/zprofile || tee -a /etc/zsh/zprofile  << ____HERE
if [ -d /etc/profile.d ]; then
  for i in /etc/profile.d/*.sh; do
    if [ -r \$i ]; then
      . \$i
    fi
  done
  unset i
fi
____HERE

}

install_other_software()
{
    # Install obfs
    apt-get install --no-install-recommends build-essential \
        autoconf libtool libssl-dev libpcre3-dev libc-ares-dev \
        libev-dev asciidoc xmlto automake build-essential curl -y
}

install_frp()
{
    MANAGE_PASS="$1"
    #golang
    echo 'PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go-bin-path.sh
    #install golang
    cd /tmp/
    wget https://dl.google.com/go/go1.11.4.linux-amd64.tar.gz
    cd /usr/local/
    tar zxf /tmp/go1.11.4.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin

    cd
    mkdir -p /etc/frp
    cat >/etc/frp/frps.ini << EOF
[common]
# A literal address or host name for IPv6 must be enclosed
# in square brackets, as in "[::1]:80", "[ipv6-host]:http" or "[ipv6-host%zone]:80"
bind_addr = 0.0.0.0
bind_port = 7000

vhost_http_port = 8090
vhost_https_port = 8091

dashboard_addr = 0.0.0.0
dashboard_port = 7500

dashboard_user = root
dashboard_pwd = $MANAGE_PASS

log_level = debug
log_file = /var/log/frps.log

# auth token
auth_token = $AUTH_TOKEN
# heartbeat configure, it's not recommended to modify the default value
# the default value of heartbeat_timeout is 90
# heartbeat_timeout = 90

# only allow frpc to bind ports you list, if you set nothing, there won't be any limit
allow_ports = 2000-3000,3001,3003,4000-50000
# pool_count in each proxy will change to max_pool_count if they exceed the maximum value
max_pool_count = 10
# max ports can be used for each client, default value is 0 means no limit
max_ports_per_client = 0

# authentication_timeout means the timeout interval (seconds) when the frpc connects frps
# if authentication_timeout is zero, the time is not verified, default is 900s
authentication_timeout = 900

# if subdomain_host is not empty, you can set subdomain when type is http or https in frpc's configure file
# when subdomain is test, the host used by routing is test.frps.com
subdomain_host = vultr.dbus.io

# if tcp stream multiplexing is used, default is true
tcp_mux = true

EOF


    cat > /etc/systemd/system/frp.service << EOF
[Unit]
Description=frp server
After=network.target auditd.service
StartLimitBurst=0
StartLimitInterval=0

[Service]
ExecStart=/root/bin/frps -c /etc/frp/frps.ini
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=process
RestartPreventExitStatus=255
RestartSec=30
Restart=always
Type=simple

[Install]
WantedBy=multi-user.target

EOF

    export PATH=/usr/local/go/bin:$PATH
    go get github.com/fatedier/frp
    cd ~/go/src/github.com/fatedier/frp
    make
    mv ./bin ~/
    cd

    systemctl daemon-reload
    systemctl enable frp
    systemctl restart frp
    systemctl status frp

}


install_oh_my_zsh()
{
    HOME=$(getent passwd |fgrep -w $(whoami) |awk -F: '{print $6}')
    cd $HOME
    wget https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh -O $HOME/install-zsh.sh
    sed -i '/env zsh/d' $HOME/install-zsh.sh
    sed  -i 's/\(chsh -s.*$\)/sudo \1 '$(whoami)'/g'   $HOME/install-zsh.sh
    /bin/sh ~/install-zsh.sh
    rm -rf ~/install-zsh.sh
    sed  -i '/^ZSH_THEME=/c\ZSH_THEME="pygmalion"' $HOME/.zshrc
    git clone git://github.com/zsh-users/zsh-autosuggestions  $HOME/.oh-my-zsh/plugins/zsh-autosuggestions
    if (! fgrep -q ' zsh-autosuggestions' $HOME/.zshrc); then
        sed -i '/^plugins=($/a \ \ zsh-autosuggestions' $HOME/.zshrc
        sed '/^plugins=([a-zA-Z \s-]*)$/c plugins=(git zsh-autosuggestions)' $HOME/.zshrc
    fi

    if (! fgrep -q ^ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE  $HOME/.zshrc); then
          echo 'ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE="fg=4"' |tee -a  $HOME/.zshrc
    fi

    if (! fgrep -q ^DISABLE_UNTRACKED_FILES_DIRTY  $HOME/.zshrc); then
         echo 'DISABLE_UNTRACKED_FILES_DIRTY="true"' |tee -a  $HOME/.zshrc
    fi
    if (! egrep -q ^"export PROMPT_EOL_MARK"  $HOME/.zshrc); then
         echo "export PROMPT_EOL_MARK=''" |tee -a  $HOME/.zshrc
    fi
    byobu-enable -l $(whoami)
}


enable_ss_service()
{
    apt-get install shadowsocks-libev kcptun simple-obfs -y --no-install-recommends

    NAMESERVER=$(cat /etc/resolv.conf |egrep ^nameserver |sed -n '1p' |awk '{print $2 }')
    [ cat /etc/resolv.conf | egrep ^nameserver | fgrep -q '127.0' ] && NAMESERVER="8.8.8.8"

    cat << ____HERE >  /etc/shadowsocks-libev/8080.json
{
    "server":["[::0]", "0.0.0.0"],
    "server_port":8080,
    "local_port":0,
    "password":"$AUTH_TOKEN",
    "timeout":60,
    "method":"aes-256-gcm",
    "fast_open":true,
    "nameserver":"$NAMESERVER",
    "plugin": "obfs-server",
    "plugin_opts": "obfs=http"

}
____HERE


    cat << ____HERE > /etc/shadowsocks-libev/8088.json
{
    "server":["[::0]", "0.0.0.0"],
    "server_port":8088,
    "local_port":0,
    "password":"$AUTH_TOKEN",
    "timeout":60,
    "fast_open":true,
    "nameserver":"$NAMESERVER",
    "method":"chacha20-ietf-poly1305"
}
____HERE

    cat << ____HERE > /etc/shadowsocks-libev/8388.json
{
    "server":["[::0]", "0.0.0.0"],
    "server_port":8388,
    "local_port":0,
    "password":"$AUTH_TOKEN",
    "timeout":60,
    "method":"chacha20-ietf-poly1305",
    "mode":"tcp_and_udp",
    "fast_open":true,
    "plugin":"obfs-server",
    "plugin_opts":"obfs=tls;failover=127.0.0.1:8443;fast-open"
}
____HERE
    systemctl disable shadowsocks-libev
    systemctl stop shadowsocks-libev
    systemctl enable shadowsocks-libev-server@8088.service
    systemctl enable shadowsocks-libev-server@8388.service
    systemctl enable shadowsocks-libev-server@8080.service
    systemctl restart shadowsocks-libev-server@8088.service
    systemctl restart shadowsocks-libev-server@8080.service
    systemctl restart shadowsocks-libev-server@8388.service
    systemctl status shadowsocks-libev-server@8088.service
    systemctl status shadowsocks-libev-server@8080.service
    systemctl status shadowsocks-libev-server@8388.service

}

setup_aws_ddns()
{
    #########################Set DDNS##########################################
    # DDNS
    cd
    wget https://github.com/trulyliu/route53-ddns/raw/master/route53.sh -O  /tmp/route53.sh
    [ -d /usr/local/bin ] || mkdir -p /usr/local/bin
    ln /tmp/route53.sh /usr/local/bin/
    unlink /tmp/route53.sh
    chmod +x  /usr/local/bin/route53.sh

    HOSTNAME=$(cat /etc/hostname)
    IPADDR=$(curl -s icanhazip.com -4)
    IPADDR6=$(curl -s icanhazip.com -6)

    cat << ____HERE > /etc/systemd/system/ddns.timer
[Unit]
Description=DDNS timer for $HOSTNAME
After=network-online.target
Wants=network-online.target

[Timer]
OnBootSec=5min
OnCalendar=*:0/2
Persistent=true

[Install]
WantedBy=timers.target
____HERE

    cat << ____HERE > /etc/systemd/system/ddns6.timer
[Unit]
Description=DDNS timer for $HOSTNAME
After=network-online.target
Wants=network-online.target

[Timer]
OnBootSec=5min
OnCalendar=*:0/2
Persistent=true

[Install]
WantedBy=timers.target
____HERE

    cat << ____HERE > /etc/systemd/system/ddns.service
[Unit]
Description=DDNS service for $HOSTNAME

[Service]
Type=oneshot
ExecStartPre=/bin/sh -c "sed -i '/RECORD_NAME/c RECORD_NAME='\"\$(cat /etc/hostname)\"    /etc/ddns/ddns.conf "
ExecStartPre=/bin/sh -c "sed -i '/RECORD_VALUE/c RECORD_VALUE='\"\$(curl -s icanhazip.com -4)\"    /etc/ddns/ddns.conf "
EnvironmentFile=/etc/ddns/ddns.conf
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=ddns
ExecStart=/usr/local/bin/route53.sh

[Install]
WantedBy=timers.target
____HERE


    cat << ____HERE > /etc/systemd/system/ddns6.service
[Unit]
Description=DDNS service for $HOSTNAME

[Service]
Type=oneshot
ExecStartPre=/bin/sh -c "sed -i '/RECORD_NAME/c RECORD_NAME='\"\$(cat /etc/hostname)\"    /etc/ddns/ddns6.conf "
ExecStartPre=/bin/sh -c "sed -i '/RECORD_VALUE/c RECORD_VALUE='\"\$(curl -s icanhazip.com -6)\"    /etc/ddns/ddns6.conf "
EnvironmentFile=/etc/ddns/ddns6.conf
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=ddns
ExecStart=/usr/local/bin/route53.sh

[Install]
WantedBy=timers.target
____HERE

    mkdir -p /etc/ddns/
    cat << ____HERE > /etc/ddns/ddns.conf
HOSTED_ZONE_ID=$HOSTED_ZONE_ID
AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY
RECORD_NAME=$HOSTNAME
RECORD_VALUE=$IPADDR
____HERE

    cat << ____HERE > /etc/ddns/ddns6.conf
HOSTED_ZONE_ID=$HOSTED_ZONE_ID
AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY
RECORD_TYPE="AAAA"
RECORD_NAME=$HOSTNAME
RECORD_VALUE=$IPADDR6
____HERE

    sudo systemctl enable ddns.timer
    sudo systemctl enable ddns6.timer
    sudo systemctl start ddns.timer
    sudo systemctl start ddns6.timer
    sudo systemctl enable ddns.service
    sudo systemctl enable ddns6.service
    sudo systemctl start ddns.service
    sudo systemctl start ddns6.service
}


setup_softether()
{
    HOSTNAME=$(cat /etc/hostname)
    VPN_SERVERPASS="$1"
#####################Softether VPN########################################
    apt-get install bridge-utils uml-utilities build-essential -y

    wget https://github.com/SoftEtherVPN/SoftEtherVPN_Stable/releases/download/v4.28-9669-beta/softether-vpnserver-v4.28-9669-beta-2018.09.11-linux-x64-64bit.tar.gz

    cd /opt/
    tar zxvf ~/softether-vpnserver-v4.28-9669-beta-2018.09.11-linux-x64-64bit.tar.gz
    unlink ~/softether-vpnserver-v4.28-9669-beta-2018.09.11-linux-x64-64bit.tar.gz
    cd /opt/vpnserver
    printf '1\n1\n1\n'  |make > /dev/null

    cat << ____HERE > /etc/systemd/system/vpnserver.service
# softether vpnserver
[Unit]
Documentation=man:systemd-sysv-generator(8)
Description=LSB: Start daemon at boot time
Before=multi-user.target
Before=graphical.target
Before=shutdown.target
After=remote-fs.target
After=systemd-journald-dev-log.socket
After=network-online.target
Wants=network-online.target
Conflicts=shutdown.target
StartLimitBurst=0xffffffff
StartLimitInterval=0

[Service]
Type=forking
Restart=always
RestartSec=30
IgnoreSIGPIPE=no
KillMode=process
GuessMainPID=yes
RemainAfterExit=yes
ExecStart=/opt/vpnserver/vpnserver start
ExecStop=/opt/vpnserver/vpnserver stop

[Install]
WantedBy=multi-user.target
____HERE


    cat << ____HERE > /tmp/servercmd
ServerPasswordSet $VPN_SERVERPASS
HubDelete Default
HubCreate dbus /PASSWORD:$VPN_SERVERPASS
Hub dbus
UserCreate trulyliu /GROUP: /REALNAME:QingchengLiu /NOTE:note
UserPasswordSet trulyliu /PASSWORD:$VPN_SERVERPASS
VpnAzureSetEnable no
VpnOverIcmpDnsEnable /ICMP:no /DNS:no
OpenVpnEnable no /PORTS:1194
BridgeCreate dbus /DEVICE:soft /TAP:yes
SecureNatEnable
Online
ServerCertRegenerate $HOSTNAME
SstpEnable yes
ListenerCreate 8443
ListenerCreate 993
ListenerDelete 443
ListenerDelete 1194
ListenerDelete 992
Flush
____HERE


    sudo systemctl enable vpnserver
    sudo systemctl start vpnserver
    sleep 3

    /opt/vpnserver/vpncmd 127.0.0.1:5555 /SERVER /IN:/tmp/servercmd > /dev/null
    sleep 3
    sudo systemctl stop vpnserver
    sleep 1
    rm /opt/vpnserver/backup.vpn_server.config/ -rf
    sed -i '/declare DDnsClient/,/^ *}$/{H;$!d} ; x ;  s/bool Disabled false/bool Disabled true/' /opt/vpnserver/vpn_server.config
    sleep 1
    sudo systemctl start vpnserver
}

dist_upgrade()
{
    apt-get update
    apt-get install -y linux-image-generic-hwe-18.04-edge linux-headers-generic-hwe-18.04-edge linux-tools-generic-hwe-18.04-edge 
}
