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

#-- code to detect OS
lowercase(){
    echo "$1" | sed "y/ABCDEFGHIJKLMNOPQRSTUVWXYZ/abcdefghijklmnopqrstuvwxyz/"
}

OS=`lowercase \`uname\``
KERNEL=`uname -r`
MACH=`uname -m`

if [ "${OS}" == "windowsnt" ]; then
    OS_NAME=windows
elif [ "${OS}" == "darwin" ]; then
    OS_NAME=mac
    REV=`sw_vers | grep 'ProductVersion:' | grep -o '[0-9]*\.[0-9]*\.[0-9]*'`
else
    OS_NAME=`uname`
    if [ "${OS}" = "SunOS" ] ; then
        OS_NAME=Solaris
        ARCH=`uname -p`
        OSSTR="${OS} ${REV}(${ARCH} `uname -v`)"
    elif [ "${OS}" = "AIX" ] ; then
        OSSTR="${OS} `oslevel` (`oslevel -r`)"
    elif [ "${OS}" = "Linux" ] ; then
        if [ -f /etc/redhat-release ] ; then
            DistroBasedOn='RedHat'
            DIST=`cat /etc/redhat-release |sed s/\ release.*//`
            PSUEDONAME=`cat /etc/redhat-release | sed s/.*\(// | sed s/\)//`
            REV=`cat /etc/redhat-release | sed s/.*release\ // | sed s/\ .*//`
        elif [ -f /etc/SuSE-release ] ; then
            DistroBasedOn='SuSe'
            PSUEDONAME=`cat /etc/SuSE-release | tr "\n" ' '| sed s/VERSION.*//`
            REV=`cat /etc/SuSE-release | tr "\n" ' ' | sed s/.*=\ //`
        elif [ -f /etc/mandrake-release ] ; then
            DistroBasedOn='Mandrake'
            PSUEDONAME=`cat /etc/mandrake-release | sed s/.*\(// | sed s/\)//`
            REV=`cat /etc/mandrake-release | sed s/.*release\ // | sed s/\ .*//`
        elif [ -f /etc/debian_version ] ; then
            DistroBasedOn='Debian'
            DIST=`cat /etc/lsb-release | grep '^DISTRIB_ID' | awk -F=  '{ print $2 }'`
            PSEUDONAME=`cat /etc/lsb-release | grep '^DISTRIB_CODENAME' | awk -F=  '{ print $2 }'`
            REV=`cat /etc/lsb-release | grep '^DISTRIB_RELEASE' | awk -F=  '{ print $2 }'`
        fi
        if [ -f /etc/UnitedLinux-release ] ; then
            DIST="${DIST}[`cat /etc/UnitedLinux-release | tr "\n" ' ' | sed s/VERSION.*//`]"
        fi
        OS_NAME=`lowercase $OS`
        DistroBasedOn=`lowercase $DistroBasedOn`
        readonly OS_NAME
        readonly DIST
        readonly DistroBasedOn
        readonly PSEUDONAME
        readonly REV
        readonly KERNEL
        readonly MACH
    fi

fi

# Platforms: osx, linux, windows
# OS: darwin, windowsnt, ubuntu, debian, redhat, mandrake, suse
# REV: 10.9, 12.04, ...
echo "OS_NAME: ${OS_NAME}"
echo "DistoBasedOn: ${DistroBaseOn}"
echo "PSEUDONAME: ${PSEUDONAME}"
echo "OS: ${OS}"
echo "DIST: ${DIST}"
echo "REV: ${REV}"

exit
set -ex

cd /tmp
 
[ -f /etc/dpkg/origins/ubuntu ] && wget http://repo.zabbix.com/zabbix/2.2/ubuntu/pool/main/z/zabbix-release/zabbix-release_2.2-1+precise_all.deb && dpkg -i zabbix-release_2.2-1+precise_all.deb
[ -f /etc/dpkg/origins/debian ] && wget http://repo.zabbix.com/zabbix/2.2/debian/pool/main/z/zabbix-release/zabbix-release_2.2-1+wheezy_all.deb && dpkg -i zabbix-release_2.2-1+wheezy_all.deb
 
apt-get -y update
apt-get -y install zabbix-agent
apt-get -y upgrade zabbix-agent
