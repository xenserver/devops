#!/bin/bash
# This script is used for deploying default configuration for new machines that are managed by us.
# 
# What it installs and configures:
# * zabbix-agent
# * salt
# * tools: curl, wget, atop, htop, iotop, meld, git, mercurial
# * update and upgrade all packages on the machine
#
# As a rule, this script should be safe to run as many times we want.
#
# One line deployment:
# wget --no-check-certificate https://raw.githubusercontent.com/xenserver/devops/master/prepare.sh -v -O prepare.sh && chmod +x prepare.sh && ./prepare.sh; rm -rf prepare.sh

#-- code to detect OS
lowercase(){
    echo "$1" | sed "y/ABCDEFGHIJKLMNOPQRSTUVWXYZ/abcdefghijklmnopqrstuvwxyz/"
}

OS=`lowercase \`uname\``
KERNEL=`uname -r`
ARCH=`uname -m`

if [ "${OS}" == "windowsnt" ]; then
    OS=windows
elif [ "${OS}" == "darwin" ]; then
    OS=mac
    REV=`sw_vers | grep 'ProductVersion:' | grep -o '[0-9]*\.[0-9]*\.[0-9]*'`
else
    if [ "${OS}" = "sunos" ] ; then
        DIST=solaris
        ARCH=`uname -p`
        OSSTR="${OS} ${REV}(${ARCH} `uname -v`)"
    elif [ "${OS}" = "aix" ] ; then
        OSSTR="${OS} `oslevel` (`oslevel -r`)"
    elif [ "${OS}" = "linux" ] ; then
        if [ -f /etc/redhat-release ] ; then
            #DIST='redhat'
            DIST=`cat /etc/redhat-release |sed s/\ release.*//`
            PSUEDONAME=`cat /etc/redhat-release | sed s/.*\(// | sed s/\)//`
            REV=`cat /etc/redhat-release | sed s/.*release\ // | sed s/\ .*//`
        elif [ -f /etc/SuSE-release ] ; then
            DIST='suse'
            PSUEDONAME=`cat /etc/SuSE-release | tr "\n" ' '| sed s/VERSION.*//`
            REV=`cat /etc/SuSE-release | tr "\n" ' ' | sed s/.*=\ //`
        elif [ -f /etc/mandrake-release ] ; then
            DIST='mandrake'
            PSUEDONAME=`cat /etc/mandrake-release | sed s/.*\(// | sed s/\)//`
            REV=`cat /etc/mandrake-release | sed s/.*release\ // | sed s/\ .*//`
        elif [ -f /etc/UnitedLinux-release ] ; then
            DIST="${DIST}[`cat /etc/UnitedLinux-release | tr "\n" ' ' | sed s/VERSION.*//`]"
        else
            which lsb_release >/dev/null
            if [[ $? -eq 0 ]]; then
                DIST=`lsb_release -i | cut -f2`
                DIST=`lowercase $DIST`
                PSEUDONAME=`lsb_release --codename | cut -f2`
                REV=`lsb_release --release | cut -f2`
            fi
        fi
        
        OS_NAME=`lowercase $OS`
        DistroBasedOn=`lowercase $DistroBasedOn`
        readonly OS
        readonly DIST
        readonly PSEUDONAME
        readonly REV
        readonly KERNEL
        readonly ARCH
    fi

fi

# Platforms: osx, linux, windows
# OS: darwin, windowsnt, ubuntu, debian, redhat, mandrake, suse
# REV: 10.9, 12.04, ...
CN="$(tput setaf 9)"
CB="$(tput setaf 2)"
#COL_GREEN="$(tput setaf 2)"
echo "os=${CB}${OS}${CN} dist=${CB}${DIST}${CN} pseudoname=${CB}${PSEUDONAME}${CN} rev=${CB}${REV}${CN} arch=${CB}${ARCH}${CN} kernel=${CB}${KERNEL}${CN}"
#echo "os=${OS} dist=${DIST} pseudoname=${PSEUDONAME} rev=${REV} arch=${ARCH} kernel=${KERNEL}"
set -ex

#exit

cd /tmp
if [ "$DIST" = "ubuntu" ] || [ "$DIST" = "debian" ] ; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get -q -y install wget git mc goaccess etckeeper ncdu
    if [ "$DIST" = "ubuntu" ] ; then
        wget http://repo.zabbix.com/zabbix/2.2/ubuntu/pool/main/z/zabbix-release/zabbix-release_2.2-1+precise_all.deb
        dpkg -i zabbix-release_2.2-1+precise_all.deb
    else
        wget http://repo.zabbix.com/zabbix/2.2/debian/pool/main/z/zabbix-release/zabbix-release_2.2-1+wheezy_all.deb
        dpkg -i zabbix-release_2.2-1+wheezy_all.deb
    fi
    git --git-dir=/tmp/devops/.git reset --hard || echo ok
    git clone --depth=1 https://github.com/xenserver/devops.git /tmp/devops || git --git-dir=/tmp/devops/.git --work-tree=/tmp/devops pull --depth=1
    rsync -ahv /tmp/devops/etc/* /etc/

    # nginx, saltstack, jenkins, dell, webupdt8team (oracle)
    for KEY in 9BDB3D89CE49EC21 B09E40B0F2AE6AB9 1285491434D8786F C2518248EEA14886 ABF5BD827BD9BF62 9B7D32F2D50582E6 331D6DDE7F8840CE 
    do
       gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv $KEY && gpg --export --armor $KEY | sudo apt-key add - || echo "error"
    done

    mkdir -p /etc/zabbix
    # --no-check-certificate
    wget -O /etc/zabbix/zabbix_agentd.conf https://raw.githubusercontent.com/xenserver/devops/master/etc/zabbix/zabbix_agentd.conf
    apt-get -qq -y update
    apt-get -y install zabbix-agent tmux mercurial htop atop iotop salt-minion
else
    echo "WARN: Unable to install zabbix for this OS"
fi


# --- configuring exim4 if is not configured so the host can send emails
if [[ ! -f /etc/exim4/update-exim4.conf.conf ]]; then

cat >/etc/exim4/update-exim4.conf.conf <<ZZZ
dc_eximconfig_configtype='smarthost'
dc_local_interfaces='127.0.0.1 ; ::1'
dc_readhost=''
dc_relay_domains='*'
dc_minimaldns='false'
dc_relay_nets='localhost'
dc_smarthost='smtp.uk.xensource.com'
CFILEMODE='644'
dc_use_split_config='true'
dc_hide_mailname='false'
dc_mailname_in_oh='true'
dc_localdelivery='mail_spool'
message_body_visible=20000
tls_on_connect_ports=465
ZZZ
apt-get -y install exim4
update-exim4.conf
fi

