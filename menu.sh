#!/bin/bash

# menu.sh V1.43.0 for Postfix
#
# Copyright (c) 2019-2020 NetCon Unternehmensberatung GmbH, https://www.netcon-consulting.com
#
# Authors:
# Marc Dierksen (m.dierksen@netcon-consulting.com)
# Uwe Sommer (u.sommer@netcon-consulting.com)
# Iyad Dassouki (i.dassouki@netcon-consulting.com)

###################################################################################################
# NetCon Postfix Made Easy
#
# This tool will help with various setup tasks for mailservers supporting the configuration of
# Postfix, Postfwd, OpenDKIM, SPF-check, Spamassassin, Rspamd and Fail2ban.
#
# Changelog:
# - added option for toggling tsocks proxy
# - added support for Rspamd cluster for Redhat
# - updated getspf script
#
###################################################################################################

declare -g -r LOG_MENU='menu.log'
declare -g -r VERSION_MENU="$(grep '^# menu.sh V' "$0" | awk '{print $3}')"
declare -g -r DIALOG='dialog'
declare -g -r LINK_GITHUB='https://raw.githubusercontent.com/netcon-consulting/pf-menu/master'
declare -g -r LINK_UPDATE="$LINK_GITHUB/menu.sh"
declare -g -r TITLE_MAIN="NetCon Postfix Made Easy $VERSION_MENU"
declare -g -r DIR_MAPS='/etc/postfix/maps'
declare -g -r DIR_CONFIG_SPAMASSASSIN='/etc/spamassassin'
declare -g DIR_LOG='/disk2/log'
[ -d "$DIR_LOG" ] || DIR_LOG='/var/log'
declare -g -r DIR_LOG_SPAMASSASSIN="$DIR_LOG/spamd"
declare -g -r DIR_LOG_POSTFIX="$DIR_LOG/postfix"
declare -g -r FILE_DHPARAM='/etc/postfix/dh2048.pem'
declare -g -r DIR_CONFIG_RSPAMD='/etc/rspamd'
declare -g -r FILE_RULES="$DIR_CONFIG_RSPAMD/local.d/spamassassin.rules"
declare -g -r DIR_LIB_RSPAMD='/var/lib/rspamd'
declare -g -r DIR_CONFIG_FAIL2BAN='/etc/fail2ban'
declare -g -r CRON_LOGMANAGER='/etc/cron.daily/log_manager.py'
declare -g -r SCRIPT_REBOOT='/etc/netcon-scripts/reboot-alert.sh'
declare -g -r CRONTAB_REBOOT='@reboot /etc/netcon-scripts/reboot-alert.sh'
declare -g -r SCRIPT_WLUPDATE='/etc/netcon-scripts/update_whitelist.sh'
declare -g -r CRONTAB_WLUPDATE='0 0,6,12,18 * * * /etc/netcon-scripts/update_whitelist.sh'
declare -g -r SCRIPT_PSWLUPDATE='/etc/netcon-scripts/getspf.sh'
declare -g -r CRONTAB_PSWLUPDATE='@daily /etc/netcon-scripts/getspf.sh -p -s /etc/postfix/maps/domains'
declare -g -r CRON_RULES='/etc/cron.daily/update_rules.sh'
declare -g -r CONFIG_SSH="$HOME/.ssh/config"
declare -g -r CONFIG_SSHD='/etc/ssh/sshd_config'
declare -g -r CONFIG_SNMP='/etc/snmp/snmpd.conf'
declare -g -r PYZOR_PLUGIN='/usr/share/rspamd/plugins/pyzor.lua'
declare -g -r PYZOR_DIR='/opt/pyzorsocket'
declare -g -r PYZOR_SCRIPT="$PYZOR_DIR/bin/pyzorsocket.py"
declare -g -r PYZOR_SERVICE='/etc/init.d/pyzorsocket'
declare -g -r PYZOR_USER='pyzorsocket'
declare -g -r RAZOR_PLUGIN='/usr/share/rspamd/plugins/razor.lua'
declare -g -r RAZOR_DIR='/opt/razorsocket'
declare -g -r RAZOR_SCRIPT="$RAZOR_DIR/bin/razorsocket.py"
declare -g -r RAZOR_SERVICE='/etc/init.d/razorsocket'
declare -g -r RAZOR_USER='razorsocket'
declare -g -r OLETOOLS_SCRIPT='/usr/local/bin/olefy.py'
declare -g -r OLETOOLS_SERVICE='/etc/systemd/system/olefy.service'
declare -g -r OLETOOLS_CONFIG='/etc/olefy.conf'
declare -g -r OLETOOLS_USER='olefy'
declare -g -r CONFIG_UPDATE='/etc/apt/apt.conf.d/50unattended-upgrades'
declare -g -r CONFIG_LOGWATCH='/etc/logwatch/conf/logwatch.conf'

###################################################################################################
# Distro settings
declare -g DISTRO INSTALLER

if [ -f '/etc/redhat-release' ]; then
    DISTRO='redhat'
    INSTALLER='yum'
elif [ -f '/etc/debian_version' ]; then
    DISTRO='debian'
    INSTALLER='apt'
elif [ -f '/etc/SUSE-brand' ]; then
    DISTRO='suse'
    INSTALLER='zypper'
fi

if [ "$DISTRO" = 'redhat' ]; then
    ###################################################################################################
    # Redhat specific parameters
    declare -g -r PACKAGE_SPAMASSASSIN='spamassassin GeoIP GeoIP-data perl-App-cpanminus perl-BSD-Resource perl-DBI perl-Encode-Detect perl-Geo-IP perl-LWP-UserAgent-Determined perl-Mail-DKIM perl-Net-CIDR perl-Digest-SHA perl-Net-Patricia spamassassin perl-Mail-SPF redis perl-Archive-Zip perl-Net-LibIDN perl-IO-Socket-INET6 perl-Geo-IP'

    declare -g -r PACKAGE_BIND='bind'
    declare -g -r SERVICE_BIND='named'

    declare -g -r PACKAGE_POSTFWD='perl-Sys-Syslog perl-Net-Server perl-Net-DNS'

    declare -g -r PACKAGE_SPF='pypolicyd-spf'

    declare -g -r PACKAGE_SNMP='net-snmp'
    declare -g -r FILE_SNMP='/etc/snmp/snmpd.conf'

    declare -g -r CONFIG_IPTABLES='/etc/sysconfig/iptables'

    declare -g -r CONFIG_REDIS='/etc/redis.conf'
elif [ "$DISTRO" = 'debian' ]; then
    ###################################################################################################
    # Debian specific parameters
    declare -g -r PACKAGE_SPAMASSASSIN='geoip-bin geoip-database geoip-database-extra cpanminus libbsd-resource-perl libdbi-perl libencode-detect-perl libgeo-ip-perl liblwp-useragent-determined-perl libmail-dkim-perl libnet-cidr-perl libdigest-sha-perl libnet-patricia-perl postfix-pcre sa-compile spamassassin spamc spf-tools-perl redis-server libarchive-zip-perl libio-string-perl libmaxmind-db-reader-perl libmaxmind-db-reader-xs-perl libnet-libidn-perl libio-socket-inet6-perl libgeoip2-perl'

    declare -g -r PACKAGE_BIND='bind9'
    declare -g -r SERVICE_BIND='bind9'

    declare -g -r PACKAGE_POSTFWD='libnet-server-perl libnet-dns-perl'

    declare -g -r PACKAGE_SPF='postfix-policyd-spf-python'

    declare -g -r PACKAGE_SNMP='snmpd libsnmp-dev'
    declare -g -r FILE_SNMP='/usr/share/snmp/snmpd.conf'

    declare -g -r CONFIG_IPTABLES='/etc/iptables/rules.v4'

    declare -g -r CONFIG_REDIS='/etc/redis/redis.conf'
elif [ "$DISTRO" = 'suse' ]; then
    ###################################################################################################
    # SUSE specific parameters
    declare -g -r PACKAGE_SPAMASSASSIN='spamassassin GeoIP GeoIP-data perl-App-cpanminus perl-BSD-Resource perl-DBI perl-Encode-Detect perl-Geo-IP perl-LWP-UserAgent-Determined perl-Mail-DKIM perl-Net-CIDR perl-Digest-SHA perl-Net-Patricia spamassassin perl-Mail-SPF redis perl-Archive-Zip perl-Net-LibIDN perl-IO-Socket-INET6 perl-Geo-IP'

    declare -g -r PACKAGE_BIND='bind'
    declare -g -r SERVICE_BIND='named'

    declare -g -r PACKAGE_POSTFWD='perl-Unix-Syslog perl-Net-Server perl-Net-DNS perl-IO-Multiplex'

    declare -g -r PACKAGE_SNMP='net-snmp'
    declare -g -r FILE_SNMP='/usr/share/snmp/snmpd.conf'

    declare -g -r CONFIG_IPTABLES='/etc/iptables/rules.v4'

    declare -g -r CONFIG_REDIS='/etc/redis/redis.conf'
fi

###################################################################################################
# Default settings
declare -g -r DEFAULT_EDITOR='vim'

###################################################################################################
# Dependencies
declare -g -a DEPENDENCY

DEPENDENCY=()
DEPENDENCY+=('dialog' 'dialog')
DEPENDENCY+=('gawk' 'gawk')
DEPENDENCY+=('gcc' 'gcc')
DEPENDENCY+=('pip3' 'python3-pip python3-setuptools python3-wheel')
DEPENDENCY+=('wget' 'wget')
DEPENDENCY+=('vim' 'vim')
DEPENDENCY+=('cpan' 'cpan')
DEPENDENCY+=('dig' 'bind-utils')

###################################################################################################
# Install features
declare -g -a INSTALL_FEATURE

INSTALL_FEATURE=()
INSTALL_FEATURE+=('postfix')
INSTALL_FEATURE+=('resolver')
INSTALL_FEATURE+=('postfwd')
INSTALL_FEATURE+=('spamassassin')
INSTALL_FEATURE+=('rspamd')
INSTALL_FEATURE+=('pyzor')
INSTALL_FEATURE+=('razor')
INSTALL_FEATURE+=('oletools')
[ "$DISTRO" = 'debian' ] && INSTALL_FEATURE+=('fuzzyocr')
INSTALL_FEATURE+=('clamav')
INSTALL_FEATURE+=('sophosav')
INSTALL_FEATURE+=('fail2ban')
INSTALL_FEATURE+=('dkim')
[ "$DISTRO" = 'suse' ] || INSTALL_FEATURE+=('spf')
INSTALL_FEATURE+=('acme')
INSTALL_FEATURE+=('logwatch')
INSTALL_FEATURE+=('logmanager')
INSTALL_FEATURE+=('reboot')
INSTALL_FEATURE+=('snmp')
INSTALL_FEATURE+=('cluster')

# Postfix
declare -g -r LABEL_INSTALL_POSTFIX='Postfix'
declare -g -r INSTALL_POSTFIX_PACKAGE='postfix'

# Local DNS resolver
declare -g -r LABEL_INSTALL_RESOLVER='Local DNS resolver'
declare -g -r INSTALL_RESOLVER_PACKAGE="$PACKAGE_BIND"

# Postfwd
declare -g -r LABEL_INSTALL_POSTFWD='Postfwd3'
declare -g -r INSTALL_POSTFWD_CUSTOM=1
declare -g -r INSTALL_POSTFWD_LINK='https://raw.githubusercontent.com/postfwd/postfwd/master/sbin/postfwd3'

# Spamassassin
declare -g -r LABEL_INSTALL_SPAMASSASSIN='Spamassassin'
declare -g -r INSTALL_SPAMASSASSIN_PACKAGE='spamassassin'

# Rspamd
declare -g -r LABEL_INSTALL_RSPAMD='Rspamd'
declare -g -r INSTALL_RSPAMD_PACKAGE='rspamd'

# Pyzor
declare -g -r LABEL_INSTALL_PYZOR='Pyzor'

# Razor
declare -g -r LABEL_INSTALL_RAZOR='Razor'
[ "$DISTRO" = 'debian' ] && declare -g -r INSTALL_RAZOR_PACKAGE='razor'

# Oletools
declare -g -r LABEL_INSTALL_OLETOOLS='Oletools'
declare -g -r INSTALL_OLETOOLS_CUSTOM=1

# FuzzyOCR
declare -g -r LABEL_INSTALL_FUZZYOCR='FuzzyOCR'
declare -g -r INSTALL_FUZZYOCR_PACKAGE='fuzzyocr'

# ClamAV
declare -g -r LABEL_INSTALL_CLAMAV='ClamAV'
declare -g -r INSTALL_CLAMAV_CUSTOM=1

# Sophos AV
declare -g -r LABEL_INSTALL_SOPHOSAV='Sophos AV'

# Fail2ban
declare -g -r LABEL_INSTALL_FAIL2BAN='Fail2ban'
declare -g -r INSTALL_FAIL2BAN_PACKAGE='fail2ban'

# OpenDKIM
declare -g -r LABEL_INSTALL_DKIM='OpenDKIM'
declare -g -r INSTALL_DKIM_PACKAGE='opendkim'

# SPF-Check
declare -g -r LABEL_INSTALL_SPF='SPF-check'
declare -g -r INSTALL_SPF_PACKAGE="$PACKAGE_SPF"

# Let's Encrypt Certificate
declare -g -r LABEL_INSTALL_ACME="Let's Encrypt Certificate"

# Logwatch
declare -g -r LABEL_INSTALL_LOGWATCH='Logwatch'
declare -g -r INSTALL_LOGWATCH_PACKAGE='logwatch'

# Log-manager
declare -g -r LABEL_INSTALL_LOGMANAGER='NetCon Log-manager'

# Reboot alert
declare -g -r LABEL_INSTALL_REBOOT='Reboot alert'

# SNMP support
declare -g -r LABEL_INSTALL_SNMP='SNMP support'
declare -g -r INSTALL_SNMP_PACKAGE="$PACKAGE_SNMP"

# Setup cluster peer
declare -g -r LABEL_INSTALL_CLUSTER='Setup cluster peer'

###################################################################################################
# Postfix server configs
declare -g -a POSTFIX_CONFIG_SERVER

POSTFIX_CONFIG_SERVER=()
POSTFIX_CONFIG_SERVER+=('postscreen')
POSTFIX_CONFIG_SERVER+=('pswlupdate')
POSTFIX_CONFIG_SERVER+=('client')
POSTFIX_CONFIG_SERVER+=('sender')
POSTFIX_CONFIG_SERVER+=('recipient')
POSTFIX_CONFIG_SERVER+=('helo')
POSTFIX_CONFIG_SERVER+=('esmtp')
POSTFIX_CONFIG_SERVER+=('rewrite')
POSTFIX_CONFIG_SERVER+=('milter')
POSTFIX_CONFIG_SERVER+=('header')
POSTFIX_CONFIG_SERVER+=('mime')
POSTFIX_CONFIG_SERVER+=('alias')

# Postscreen access IPs
declare -g -r LABEL_CONFIG_POSTFIX_POSTSCREEN='Postscreen access IPs'
declare -g -r CONFIG_POSTFIX_POSTSCREEN="$DIR_MAPS/check_postscreen_access_ips"

# Postscreen whitelist domains
declare -g -r LABEL_CONFIG_POSTFIX_PSWLUPDATE='Postscreen whitelist domains'
declare -g -r CONFIG_POSTFIX_PSWLUPDATE="$DIR_MAPS/domains"

# Client access IPs
declare -g -r LABEL_CONFIG_POSTFIX_CLIENT='Client access IPs'
declare -g -r CONFIG_POSTFIX_CLIENT="$DIR_MAPS/check_client_access_ips"

# Sender access
declare -g -r LABEL_CONFIG_POSTFIX_SENDER='Sender access'
declare -g -r CONFIG_POSTFIX_SENDER="$DIR_MAPS/check_sender_access"

# Recipient access
declare -g -r LABEL_CONFIG_POSTFIX_RECIPIENT='Recipient access'
declare -g -r CONFIG_POSTFIX_RECIPIENT="$DIR_MAPS/check_recipient_access"

# HELO access
declare -g -r LABEL_CONFIG_POSTFIX_HELO='HELO access'
declare -g -r CONFIG_POSTFIX_HELO="$DIR_MAPS/check_helo_access"

# ESMTP restrictions
declare -g -r LABEL_CONFIG_POSTFIX_ESMTP='ESMTP restrictions'
declare -g -r CONFIG_POSTFIX_ESMTP="$DIR_MAPS/esmtp_access"

# Sender rewriting
declare -g -r LABEL_CONFIG_POSTFIX_REWRITE='Sender rewriting'
declare -g -r CONFIG_POSTFIX_REWRITE="$DIR_MAPS/sender_canonical_maps"

# Milter bypass
declare -g -r LABEL_CONFIG_POSTFIX_MILTER='Milter bypass'
declare -g -r CONFIG_POSTFIX_MILTER="$DIR_MAPS/smtpd_milter_map"

# Header checks
declare -g -r LABEL_CONFIG_POSTFIX_HEADER='Header checks'
declare -g -r CONFIG_POSTFIX_HEADER="$DIR_MAPS/check_header"

# MIME header checks
declare -g -r LABEL_CONFIG_POSTFIX_MIME='MIME header checks'
declare -g -r CONFIG_POSTFIX_MIME="$DIR_MAPS/mime_header_checks"

# Virtual aliases
declare -g -r LABEL_CONFIG_POSTFIX_ALIAS='Virtual aliases'
declare -g -r CONFIG_POSTFIX_ALIAS="$DIR_MAPS/virtual_aliases"

###################################################################################################
# Postfix client configs
declare -g -a POSTFIX_CONFIG_CLIENT

POSTFIX_CONFIG_CLIENT=()
POSTFIX_CONFIG_CLIENT+=('transport')
POSTFIX_CONFIG_CLIENT+=('routing')

# Transport map
declare -g -r LABEL_CONFIG_POSTFIX_TRANSPORT='Transport map'
declare -g -r CONFIG_POSTFIX_TRANSPORT="$DIR_MAPS/transport"

# Sender-dependent routing
declare -g -r LABEL_CONFIG_POSTFIX_ROUTING='Sender-dependent routing'
declare -g -r CONFIG_POSTFIX_ROUTING="$DIR_MAPS/relayhost_map"

###################################################################################################
# Postfix features
declare -g -a POSTFIX_FEATURE

POSTFIX_FEATURE=()
POSTFIX_FEATURE+=('tls')
POSTFIX_FEATURE+=('dane')
POSTFIX_FEATURE+=('verbosetls')
POSTFIX_FEATURE+=('esmtp')
POSTFIX_FEATURE+=('header')
POSTFIX_FEATURE+=('mime')
POSTFIX_FEATURE+=('alias')
POSTFIX_FEATURE+=('rewrite')
POSTFIX_FEATURE+=('routing')
POSTFIX_FEATURE+=('milter')
POSTFIX_FEATURE+=('bounce')
POSTFIX_FEATURE+=('limit')
POSTFIX_FEATURE+=('postscreen')
POSTFIX_FEATURE+=('submission')
POSTFIX_FEATURE+=('recipient')
POSTFIX_FEATURE+=('postfwd')
POSTFIX_FEATURE+=('spamassassin')
POSTFIX_FEATURE+=('rspamd')
POSTFIX_FEATURE+=('spf')
POSTFIX_FEATURE+=('dkim')

for FEATURE in "${POSTFIX_FEATURE[@]}"; do
    declare -g -a POSTFIX_${FEATURE^^}
    eval "POSTFIX_${FEATURE^^}=()"
done

# TLS
declare -g -r POSTFIX_TLS_LABEL='TLS encryption'
declare -g -r POSTFIX_TLS_CUSTOM=1

POSTFIX_TLS+=('smtp_tls_security_level=may')
POSTFIX_TLS+=('smtp_use_tls=yes')
POSTFIX_TLS+=('smtpd_tls_CApath=/etc/ssl/certs')
POSTFIX_TLS+=('smtpd_tls_ask_ccert=yes')
POSTFIX_TLS+=('smtpd_tls_ciphers=high')
POSTFIX_TLS+=("smtpd_tls_dh1024_param_file=$FILE_DHPARAM")
POSTFIX_TLS+=('smtpd_tls_exclude_ciphers=aNULL eNULL EXPORT DES RC4 MD5 PSK aECDH EDH-DSS-DES-CBC3-SHA EDH-RSA-DES-CDC3-SHA KRB5-DE5 CBC3-SHA LOW SEED')
POSTFIX_TLS+=('smtpd_tls_mandatory_ciphers=high')
POSTFIX_TLS+=('smtpd_tls_received_header=yes')
POSTFIX_TLS+=('smtpd_tls_security_level=may')
POSTFIX_TLS+=('smtpd_use_tls=yes')

# DANE
declare -g -r POSTFIX_DANE_LABEL='DANE'

POSTFIX_DANE+=('smtp_tls_security_level=dane')
POSTFIX_DANE+=('smtp_dns_support_level=dnssec')

# Verbose TLS
declare -g -r POSTFIX_VERBOSETLS_LABEL='Verbose TLS'

POSTFIX_VERBOSETLS+=('smtpd_tls_loglevel=1')
POSTFIX_VERBOSETLS+=('smtp_tls_note_starttls_offer=yes')
POSTFIX_VERBOSETLS+=('smtp_tls_loglevel=1')

# ESMTP filter
declare -g -r POSTFIX_ESMTP_LABEL='ESMTP filter'

POSTFIX_ESMTP+=("smtpd_discard_ehlo_keyword_address_maps=cidr:$CONFIG_POSTFIX_ESMTP")
POSTFIX_ESMTP+=('smtpd_discard_ehlo_keywords=')

# Header checks
declare -g -r POSTFIX_HEADER_LABEL='Header checks'

POSTFIX_HEADER+=("header_checks=regexp:$CONFIG_POSTFIX_HEADER")

# MIME header checks
declare -g -r POSTFIX_MIME_LABEL='MIME header checks'

POSTFIX_MIME+=("mime_header_checks=regexp:$CONFIG_POSTFIX_MIME")

# Virtual aliases
declare -g -r POSTFIX_ALIAS_LABEL='Virtual aliases'

POSTFIX_ALIAS_ADMIN="$DIR_MAPS/virtual_alias_admin"

POSTFIX_ALIAS+=("virtual_alias_maps=hash:$POSTFIX_ALIAS_ADMIN hash:$CONFIG_POSTFIX_ALIAS")

# Sender rewrite
declare -g -r POSTFIX_REWRITE_LABEL='Sender rewrite'

POSTFIX_REWRITE+=("sender_canonical_maps=regexp:$CONFIG_POSTFIX_REWRITE")

# Sender-dependent routing
declare -g -r POSTFIX_ROUTING_LABEL='Sender-dependent routing'

POSTFIX_ROUTING+=("sender_dependent_default_transport_maps=hash:$CONFIG_POSTFIX_ROUTING")

# Milter bypass
declare -g -r POSTFIX_MILTER_LABEL='Milter bypass'

POSTFIX_MILTER+=("smtpd_milter_maps=cidr:$CONFIG_POSTFIX_MILTER")

# Bounce notifications
declare -g -r POSTFIX_BOUNCE_LABEL='Bounce notifications'
declare -g -r POSTFIX_BOUNCE_CUSTOM=1

POSTFIX_BOUNCE+=('notify_classes=bounce, delay, policy, protocol, resource, software, 2bounce')

# Connection limit
declare -g -r POSTFIX_LIMIT_LABEL='Connection limit'

POSTFIX_LIMIT+=('anvil_rate_time_unit=60s')
POSTFIX_LIMIT+=('smtpd_client_connection_rate_limit=20')
POSTFIX_LIMIT+=('smtpd_client_recipient_rate_limit=20')
POSTFIX_LIMIT+=('smtpd_client_connection_count_limit=20')

# Postscreen
declare -g -r POSTSCREEN_BLACKLISTS='zen.spamhaus.org*3 b.barracudacentral.org*2 ix.dnsbl.manitu.net*2 bl.spameatingmonkey.net bl.spamcop.net list.dnswl.org=127.0.[0..255].0*-2 list.dnswl.org=127.0.[0..255].1*-3 list.dnswl.org=127.0.[0..255].[2..3]*-4'

declare -g -r POSTFIX_POSTSCREEN_LABEL='Postscreen'
declare -g -r POSTFIX_POSTSCREEN_CUSTOM=1
declare -g -r POSTFIX_POSTSCREEN_FORCE=1

POSTFIX_POSTSCREEN+=('postscreen_blacklist_action=enforce')
POSTFIX_POSTSCREEN+=('postscreen_command_time_limit=${stress?10}${stress:300}s')
POSTFIX_POSTSCREEN+=('postscreen_dnsbl_action=enforce')
POSTFIX_POSTSCREEN+=("postscreen_dnsbl_sites=$POSTSCREEN_BLACKLISTS")
POSTFIX_POSTSCREEN+=('postscreen_dnsbl_threshold=3')
POSTFIX_POSTSCREEN+=('postscreen_dnsbl_ttl=1h')
POSTFIX_POSTSCREEN+=('postscreen_greet_action=enforce')
POSTFIX_POSTSCREEN+=('postscreen_greet_wait=${stress?4}${stress:15}s')

declare -g -a POSTSCREEN_FEATURE

POSTSCREEN_FEATURE=()
POSTSCREEN_FEATURE+=('psdeep')
POSTSCREEN_FEATURE+=('pswlupdate')

declare -g -r POSTSCREEN_PSDEEP_LABEL='Postscreen Deep'

declare -g -a POSTSCREEN_PSDEEP

POSTSCREEN_PSDEEP=()
POSTSCREEN_PSDEEP+=('postscreen_bare_newline_enable=yes')
POSTSCREEN_PSDEEP+=('postscreen_bare_newline_action=enforce')
POSTSCREEN_PSDEEP+=('postscreen_non_smtp_command_action=enforce')
POSTSCREEN_PSDEEP+=('postscreen_non_smtp_command_enable=yes')
POSTSCREEN_PSDEEP+=('postscreen_pipelining_enable=yes')
POSTSCREEN_PSDEEP+=('postscreen_dnsbl_whitelist_threshold=-1')

declare -g -r POSTSCREEN_PSWLUPDATE_LABEL='Automatic whitelist update'

declare -g -r POSTSCREEN_WHITELIST_SPF="$DIR_MAPS/postscreen_spf_whitelist.cidr"

# Submission port
declare -g -r POSTFIX_SUBMISSION_LABEL='Submission port'
declare -g -r POSTFIX_SUBMISSION_CUSTOM=1

# Recipient restrictions
declare -g -r RECIPIENT_ACCESS="check_client_access cidr:$CONFIG_POSTFIX_CLIENT, check_sender_access regexp:$CONFIG_POSTFIX_SENDER, check_recipient_access regexp:$CONFIG_POSTFIX_RECIPIENT, check_helo_access regexp:$CONFIG_POSTFIX_HELO"

declare -g -r POSTFIX_RECIPIENT_LABEL='Recipient restrictions'
declare -g -r POSTFIX_RECIPIENT_CUSTOM=1
declare -g -r POSTFIX_RECIPIENT_FORCE=1

POSTFIX_RECIPIENT+=('smtpd_delay_reject=yes')
POSTFIX_RECIPIENT+=('smtpd_helo_required=yes')

# Postfwd
declare -g -r POSTFWD_ACCESS='check_policy_service inet:127.0.0.1:10040'

declare -g -r POSTFIX_POSTFWD_LABEL='Postfwd3'
declare -g -r POSTFIX_POSTFWD_CHECK=1
declare -g -r POSTFIX_POSTFWD_CUSTOM=1

# Spamassassin
declare -g -r POSTFIX_SPAMASSASSIN_LABEL='Spamassassin'
declare -g -r POSTFIX_SPAMASSASSIN_CHECK=1
declare -g -r POSTFIX_SPAMASSASSIN_CUSTOM=1

# Rspamd
declare -g -r POSTFIX_RSPAMD_LABEL='Rspamd'
declare -g -r POSTFIX_RSPAMD_CHECK=1
declare -g -r POSTFIX_RSPAMD_CUSTOM=1

POSTFIX_RSPAMD+=('milter_protocol=6')

# SPF-check
declare -g -r POSTFIX_SPF_LABEL='SPF-check'
declare -g -r POSTFIX_SPF_CHECK=1
declare -g -r POSTFIX_SPF_CUSTOM=1

# OpenDKIM
declare -g -r POSTFIX_DKIM_LABEL='OpenDKIM'
declare -g -r POSTFIX_DKIM_CHECK=1
declare -g -r POSTFIX_DKIM_CUSTOM=1

POSTFIX_DKIM+=('non_smtpd_milters=inet:127.0.0.1:10001')

###################################################################################################
# Addon configs
declare -g -a ADDON_CONFIG

ADDON_CONFIG=()
ADDON_CONFIG+=('resolver')
ADDON_CONFIG+=('postfwd')
ADDON_CONFIG+=('spamassassin')
ADDON_CONFIG+=('dkim')
ADDON_CONFIG+=('spf')
ADDON_CONFIG+=('fail2ban')

# Local DNS resolver
declare -g -r LABEL_ADDON_RESOLVER='Local DNS resolver'
declare -g -r CONFIG_RESOLVER='/etc/bind/named.conf.options'
declare -g -r CONFIG_RESOLVER_FORWARD='/etc/bind/named.conf.forward-zones'
declare -g -r CONFIG_RESOLVER_LOCAL='/etc/bind/named.conf.local-zones'
declare -g -r DIR_ZONE='/var/cache/bind'

# Postfwd
declare -g -r LABEL_ADDON_POSTFWD='Postfwd3'
declare -g -r CONFIG_POSTFWD='/etc/postfix/postfwd.cf'

# Spamassassin
declare -g -r LABEL_ADDON_SPAMASSASSIN='Spamassassin'

# OpenDKIM
declare -g -r LABEL_ADDON_DKIM='OpenDKIM'
declare -g -r CONFIG_DKIM='/etc/opendkim.conf'

# SPF-check
declare -g -r LABEL_ADDON_SPF='SPF-check'
declare -g -r CONFIG_SPF='/etc/postfix-policyd-spf-python/policyd-spf.conf'

# Fail2ban
declare -g -r LABEL_ADDON_FAIL2BAN='Fail2ban'

###################################################################################################
# Spamassassin configs
declare -g -a SPAMASSASSIN_CONFIG

SPAMASSASSIN_CONFIG=()
SPAMASSASSIN_CONFIG+=('local')
SPAMASSASSIN_CONFIG+=('whitelist')

# Main
declare -g -r LABEL_CONFIG_SPAMASSASSIN_LOCAL='Main'
declare -g -r CONFIG_SPAMASSASSIN_LOCAL="$DIR_CONFIG_SPAMASSASSIN/local.cf"

# Whitelist
declare -g -r LABEL_CONFIG_SPAMASSASSIN_WHITELIST='Whitelist'
declare -g -r CONFIG_SPAMASSASSIN_WHITELIST="$DIR_CONFIG_SPAMASSASSIN/whitelist_from.cf"

###################################################################################################
# Spamassassin features
declare -g -a SPAMASSASSIN_FEATURE

SPAMASSASSIN_FEATURE=()
SPAMASSASSIN_FEATURE+=('wlupdate')

for FEATURE in "${SPAMASSASSIN_FEATURE[@]}"; do
    declare -g -a SPAMASSASSIN_${FEATURE^^}
    eval "SPAMASSASSIN_${FEATURE^^}=()"
done

# Automatic whitelist update
declare -g -r SPAMASSASSIN_WLUPDATE_LABEL='Automatic whitelist update'
declare -g -r SPAMASSASSIN_WLUPDATE_CUSTOM=1

###################################################################################################
# Rspamd configs
declare -g -r CONFIG_RSPAMD_LOCAL="$DIR_CONFIG_RSPAMD/rspamd.conf.local"
declare -g -r CONFIG_RSPAMD_REDIS="$DIR_CONFIG_RSPAMD/local.d/redis.conf"
declare -g -r CONFIG_RSPAMD_GREYLIST="$DIR_CONFIG_RSPAMD/local.d/greylist.conf"
declare -g -r CONFIG_RSPAMD_OPTIONS="$DIR_CONFIG_RSPAMD/local.d/options.inc"
declare -g -r CONFIG_RSPAMD_HISTORY="$DIR_CONFIG_RSPAMD/local.d/history_redis.conf"
declare -g -r CONFIG_RSPAMD_SARULES="$DIR_CONFIG_RSPAMD/local.d/spamassassin.conf"
declare -g -r CONFIG_RSPAMD_REPUTATION="$DIR_CONFIG_RSPAMD/local.d/url_reputation.conf"
declare -g -r CONFIG_RSPAMD_PHISHING="$DIR_CONFIG_RSPAMD/local.d/phishing.conf"
declare -g -r CONFIG_RSPAMD_ACTIONS="$DIR_CONFIG_RSPAMD/override.d/actions.conf"
declare -g -r CONFIG_RSPAMD_HEADERS="$DIR_CONFIG_RSPAMD/override.d/milter_headers.conf"
declare -g -r CONFIG_RSPAMD_BAYES="$DIR_CONFIG_RSPAMD/override.d/classifier-bayes.conf"
declare -g -r CONFIG_RSPAMD_MULTIMAP="$DIR_CONFIG_RSPAMD/local.d/multimap.conf"
declare -g -r CONFIG_RSPAMD_GROUPS="$DIR_CONFIG_RSPAMD/local.d/groups.conf"
declare -g -r CONFIG_RSPAMD_SIGNATURES="$DIR_CONFIG_RSPAMD/local.d/signatures_group.conf"
declare -g -r CONFIG_RSPAMD_EXTERNAL="$DIR_CONFIG_RSPAMD/local.d/external_services.conf"
declare -g -r CONFIG_RSPAMD_NORMAL="$DIR_CONFIG_RSPAMD/override.d/worker-normal.inc"
declare -g -r CONFIG_RSPAMD_CONTROLLER="$DIR_CONFIG_RSPAMD/override.d/worker-controller.inc"
declare -g -r CONFIG_RSPAMD_PROXY="$DIR_CONFIG_RSPAMD/override.d/worker-proxy.inc"
declare -g -r CONFIG_RSPAMD_FUZZY="$DIR_CONFIG_RSPAMD/override.d/worker-fuzzy.inc"
declare -g -r CONFIG_RSPAMD_ANTIVIRUS="$DIR_CONFIG_RSPAMD/local.d/antivirus.conf"
declare -g -r CONFIG_RSPAMD_LOGGING="$DIR_CONFIG_RSPAMD/local.d/logging.inc"

declare -g -a RSPAMD_CONFIG

RSPAMD_CONFIG=()
RSPAMD_CONFIG+=('whitelist_ip')
RSPAMD_CONFIG+=('whitelist_domain')
RSPAMD_CONFIG+=('whitelist_from')
RSPAMD_CONFIG+=('whitelist_to')
RSPAMD_CONFIG+=('whitelist_antivirus_from')
RSPAMD_CONFIG+=('blacklist_country')

# Whitelist sender IP
declare -g -r LABEL_CONFIG_RSPAMD_WHITELIST_IP='Whitelist sender IP'
declare -g -r CONFIG_RSPAMD_WHITELIST_IP="$DIR_LIB_RSPAMD/whitelist_sender_ip"

# Whitelist sender domain
declare -g -r LABEL_CONFIG_RSPAMD_WHITELIST_DOMAIN='Whitelist sender domain'
declare -g -r CONFIG_RSPAMD_WHITELIST_DOMAIN="$DIR_LIB_RSPAMD/whitelist_sender_domain"

# Whitelist sender from
declare -g -r LABEL_CONFIG_RSPAMD_WHITELIST_FROM='Whitelist sender from'
declare -g -r CONFIG_RSPAMD_WHITELIST_FROM="$DIR_LIB_RSPAMD/whitelist_sender_from"

# Whitelist recipient to
declare -g -r LABEL_CONFIG_RSPAMD_WHITELIST_TO='Whitelist recipient to'
declare -g -r CONFIG_RSPAMD_WHITELIST_TO="$DIR_LIB_RSPAMD/whitelist_recipient_to"

# Whitelist antivirus sender from
declare -g -r LABEL_CONFIG_RSPAMD_WHITELIST_ANTIVIRUS_FROM='Whitelist antivirus sender from'
declare -g -r CONFIG_RSPAMD_WHITELIST_ANTIVIRUS_FROM="$DIR_LIB_RSPAMD/whitelist_antivirus_sender_from"

# Blacklist sender country
declare -g -r LABEL_CONFIG_RSPAMD_BLACKLIST_COUNTRY='Blacklist sender country'
declare -g -r CONFIG_RSPAMD_BLACKLIST_COUNTRY="$DIR_LIB_RSPAMD/blacklist_sender_country"

###################################################################################################
# Rspamd features
declare -g -a RSPAMD_FEATURE

RSPAMD_FEATURE=()
RSPAMD_FEATURE+=('greylist')
RSPAMD_FEATURE+=('reject')
RSPAMD_FEATURE+=('bwlist')
RSPAMD_FEATURE+=('bayes')
RSPAMD_FEATURE+=('headers')
RSPAMD_FEATURE+=('history')
RSPAMD_FEATURE+=('spamd')
RSPAMD_FEATURE+=('sarules')
RSPAMD_FEATURE+=('rulesupdate')
RSPAMD_FEATURE+=('reputation')
RSPAMD_FEATURE+=('phishing')
RSPAMD_FEATURE+=('pyzor')
RSPAMD_FEATURE+=('razor')
RSPAMD_FEATURE+=('oletools')
RSPAMD_FEATURE+=('clamav')
RSPAMD_FEATURE+=('sophosav')
RSPAMD_FEATURE+=('cluster')

for FEATURE in "${RSPAMD_FEATURE[@]}"; do
    declare -g -a RSPAMD_${FEATURE^^}
    eval "RSPAMD_${FEATURE^^}=()"
done

# Disable greylisting
declare -g -r RSPAMD_GREYLIST_LABEL='Greylisting disabled'

RSPAMD_GREYLIST+=('greylist = null;' "$CONFIG_RSPAMD_ACTIONS")
RSPAMD_GREYLIST+=('enabled = false;' "$CONFIG_RSPAMD_GREYLIST")

# Disable rejecting
declare -g -r RSPAMD_REJECT_LABEL='Rejecting disabled'

RSPAMD_REJECT+=('reject = null;' "$CONFIG_RSPAMD_ACTIONS")

# Black-/whitelists
declare -g -r RSPAMD_BWLIST_LABEL='Black-/whitelists'
declare -g -r RSPAMD_BWLIST_CUSTOM=1

# Bayes-learning
declare -g -r RSPAMD_BAYES_LABEL='Bayes-learning'

RSPAMD_BAYES+=('autolearn = true;' "$CONFIG_RSPAMD_BAYES")

# Detailed headers
declare -g -r RSPAMD_HEADERS_LABEL='Detailed headers'

RSPAMD_HEADERS+=('extended_spam_headers = true;' "$CONFIG_RSPAMD_HEADERS")

# Detailed history
declare -g -r RSPAMD_HISTORY_LABEL='Detailed history'

RSPAMD_HISTORY+=('servers = 127.0.0.1:6379;' "$CONFIG_RSPAMD_HISTORY")

# Spamassassin rules
declare -g -r RSPAMD_SPAMD_LABEL='Spamassassin integration'
declare -g -r RSPAMD_SPAMD_CHECK=1
declare -g -r RSPAMD_SPAMD_CUSTOM=1

declare -g -r CONFIG_SPAMD='spamassassin {'$'\n\t''symbol = "SPAMD"'$'\n\t''type = "spamassassin"'$'\n\t''max_size = 1000000;'$'\n\t''servers = "127.0.0.1:783";'$'\n\t''one_shot = true;'$'\n\t''score = 1.0;'$'\n''}'

# Spamassassin rules
declare -g -r RSPAMD_SARULES_LABEL='Heinlein SA rules'
declare -g -r RSPAMD_SARULES_CUSTOM=1

RSPAMD_SARULES+=("ruleset = \"$FILE_RULES\";" "$CONFIG_RSPAMD_SARULES")
RSPAMD_SARULES+=('alpha = 0.1;' "$CONFIG_RSPAMD_SARULES")

# Automatic SA rules update
declare -g -r RSPAMD_RULESUPDATE_LABEL='Automatic SA rules update'
declare -g -r RSPAMD_RULESUPDATE_CUSTOM=1

# URL reputation
declare -g -r RSPAMD_REPUTATION_LABEL='URL reputation'

RSPAMD_REPUTATION+=('enabled = true;' "$CONFIG_RSPAMD_REPUTATION")

# Phishing detection
declare -g -r RSPAMD_PHISHING_LABEL='Phishing detection'

RSPAMD_PHISHING+=('phishtank_enabled = true;' "$CONFIG_RSPAMD_PHISHING")
RSPAMD_PHISHING+=('phishtank_map = "https://rspamd.com/phishtank/online-valid.json.zst";' "$CONFIG_RSPAMD_PHISHING")

# Pyzor
declare -g -r RSPAMD_PYZOR_LABEL='Pyzor'
declare -g -r RSPAMD_PYZOR_CHECK=1
declare -g -r RSPAMD_PYZOR_CUSTOM=1

# Razor
declare -g -r RSPAMD_RAZOR_LABEL='Razor'
declare -g -r RSPAMD_RAZOR_CHECK=1
declare -g -r RSPAMD_RAZOR_CUSTOM=1

# Oletools
declare -g -r RSPAMD_OLETOOLS_LABEL='Oletools'
declare -g -r RSPAMD_OLETOOLS_CHECK=1
declare -g -r RSPAMD_OLETOOLS_CUSTOM=1

declare -g -r CONFIG_OLETOOLS='oletools {'$'\n\t''log_clean = true;'$'\n\t''servers = "127.0.0.1:10050";'$'\n\t''cache_expire = 86400;'$'\n\t''scan_mime_parts = true;'$'\n''}'

# ClamAV
declare -g -r RSPAMD_CLAMAV_LABEL='ClamAV'
declare -g -r RSPAMD_CLAMAV_CHECK=1
declare -g -r RSPAMD_CLAMAV_CUSTOM=1

declare -g -r CONFIG_CLAMAV='clamav {'$'\n\t''max_size = 50000000;'$'\n\t''log_clean = true;'$'\n\t'"whitelist = \"$CONFIG_RSPAMD_WHITELIST_ANTIVIRUS_FROM\";"$'\n\t''scan_mime_parts = true;'$'\n\t''scan_text_mime = true;'$'\n\t''symbol = "CLAM_VIRUS";'$'\n\t''type = "clamav";'$'\n\t''action = "reject";'$'\n\t''servers = "127.0.0.1:3310";'$'\n''}'

# Sophos AV
declare -g -r RSPAMD_SOPHOSAV_LABEL='Sophos AV'
declare -g -r RSPAMD_SOPHOSAV_CHECK=1
declare -g -r RSPAMD_SOPHOSAV_CUSTOM=1

declare -g -r CONFIG_SOPHOSAV='sophos {'$'\n\t''max_size = 50000000;'$'\n\t''log_clean = true;'$'\n\t'"whitelist = \"$CONFIG_RSPAMD_WHITELIST_ANTIVIRUS_FROM\";"$'\n\t''scan_mime_parts = true;'$'\n\t''scan_text_mime = true;'$'\n\t''symbol = "SOPHOS_VIRUS";'$'\n\t''type = "sophos";'$'\n\t''action = "reject";'$'\n\t''servers = "127.0.0.1:4010";'$'\n\t''patterns {'$'\n\t\t'"JUST_EICAR = '^Eicar-Test-Signature$';"$'\n\t''}'$'\n''}'

# Cluster setup
declare -g -r RSPAMD_CLUSTER_LABEL='Cluster setup'
declare -g -r RSPAMD_CLUSTER_CHECK=1
declare -g -r RSPAMD_CLUSTER_CUSTOM=1

###################################################################################################
# Fail2ban configs
declare -g -a FAIL2BAN_CONFIG

FAIL2BAN_CONFIG=()
FAIL2BAN_CONFIG+=('local')
FAIL2BAN_CONFIG+=('filter')
FAIL2BAN_CONFIG+=('action')

# Main
declare -g -r LABEL_CONFIG_FAIL2BAN_LOCAL='Main'
declare -g -r CONFIG_FAIL2BAN_LOCAL="$DIR_CONFIG_FAIL2BAN/jail.local"

# Filter
declare -g -r LABEL_CONFIG_FAIL2BAN_FILTER='Filter'
declare -g -r CONFIG_FAIL2BAN_FILTER="$DIR_CONFIG_FAIL2BAN/filter.d/"

# Action
declare -g -r LABEL_CONFIG_FAIL2BAN_ACTION='Action'
declare -g -r CONFIG_FAIL2BAN_ACTION="$DIR_CONFIG_FAIL2BAN/action.d/"

###################################################################################################
# Text Editors
declare -g -a TEXT_EDITORS

TEXT_EDITORS=()
TEXT_EDITORS+=("$DEFAULT_EDITOR")
TEXT_EDITORS+=('nano')
TEXT_EDITORS+=('pico')

###################################################################################################
# Email addresses
declare -g -a EMAIL_ADDRESSES

EMAIL_ADDRESSES=()
EMAIL_ADDRESSES+=('update')
EMAIL_ADDRESSES+=('logwatch')
EMAIL_ADDRESSES+=('reboot')
EMAIL_ADDRESSES+=('wlupdate')

# Automatic update
declare -g -r LABEL_EMAIL_UPDATE='Automatic update'

# Logwatch
declare -g -r LABEL_EMAIL_LOGWATCH='Logwatch'
declare -g -r EMAIL_LOGWATCH_CHECK=1

# Reboot alert
declare -g -r LABEL_EMAIL_REBOOT='Reboot alert'
declare -g -r EMAIL_REBOOT_CHECK=1

# Automatic SA whitelist update
declare -g -r LABEL_EMAIL_WLUPDATE='Automatic SA whitelist update'
declare -g -r EMAIL_WLUPDATE_CHECK=1

###################################################################################################
# Logs
declare -g -a PROGRAM_LOGS

PROGRAM_LOGS=()
PROGRAM_LOGS+=('postfix')
PROGRAM_LOGS+=('spamassassin')
PROGRAM_LOGS+=('rspamd')
PROGRAM_LOGS+=('fail2ban')

# Postfix
declare -g -r LOG_POSTFIX_DIR="$DIR_LOG/postfix"
declare -g -r LOG_POSTFIX_LABEL='Postfix'

# Spamassassin
declare -g -r LOG_SPAMASSASSIN_DIR="$DIR_LOG/spamd"
declare -g -r LOG_SPAMASSASSIN_LABEL='Spamassassin'
declare -g -r LOG_SPAMASSASSIN_CHECK=1

# Rspamd
declare -g -r LOG_RSPAMD_DIR="$DIR_LOG/rspamd"
declare -g -r LOG_RSPAMD_LABEL='Rspamd'
declare -g -r LOG_RSPAMD_CHECK=1

# Fail2ban
declare -g -r LOG_FAIL2BAN_DIR="$DIR_LOG/fail2ban"
declare -g -r LOG_FAIL2BAN_LABEL='Fail2ban'
declare -g -r LOG_FAIL2BAN_CHECK=1

###################################################################################################
# Help
declare -g -r HELP_MAIN='NetCon Postfix Made Easy

This tool will help with various setup tasks for mailservers supporting the configuration of Postfix,
Postfwd, OpenDKIM, SPF-check, Spamassassin, Rspamd and Fail2ban.

* Install feature (only Ubuntu) - Install packages
* Postfix feature - Toggle Postfix features
* Postfix config - Edit Postfix configuration files
* Postfix plugin config (if any installed) - Edit Postfix plugin configuration files
* Postfix info - Show Postfix stats and infos
* Spamassassin config (if installed) - Edit Spamassassin configuration files
* Spamassassin info (if installed) - Show Spamassassin stats and infos
* Rspamd feature (if installed) - Toggle Rspamd features
* Rspamd config (if installed) - Edit Rspamd configuration files
* Fail2ban config (if installed) - Edit Fail2ban configuration files
* Other info - Show other stats and infos
* Sync all (if setup peer) - Sync all configuration files with peer'

declare -g -r HELP_INSTALL_FEATURE='Select feature to install.

* Postfwd3 - Install Postfwd3
* Spamassassin - Install Spamassassin
* Rspamd - Install Rspamd
* Pyzor - Install Pyzor
* Razor - Install Razor
* Fail2ban - Install Fail2ban
* OpenDKIM - Install OpenDKIM
* SPF-check - Install SPF-check (policyd-spf)
* Log-manager - Install Log-manager cron job
* Setup peer - Setup peering with other mailserver'

declare -g -r HELP_POSTFIX_FEATURE='Select Postfix features to enable.

* TLS encryption - Select TLS private key and public (fullchain) certificate and enable TLS encryption
* DANE - Enable DANE check for TLS certificates
* Verbose TLS - Enable verbose logging of TLS handshake
* ESMTP filter - Enable discarding of ESMTP verbs depending of client IP
* Sender rewrite - Enable rewriting of sender addresses
* Sender-dependent routing - Enable mail routing dependent on sender address
* Milter bypass - Enable bypass of milter settings dependent on client IP
* Bounce notifications - Enable bounce notifications for delays, bounces and errors
* Postscreen - Enable blocking based on reputation black-/whitelist
* Postscreen Deep - Enable additional checks
* Recipient restrictions - Enable various recipient restrictions
* Postfwd3 (if installed) - Enable Postfwd3
* Spamassassin (if installed) - Enable Spamassassin
* Rspamd (if installed) - Enable Rspamd
* SPF-check (if installed) - Enable SPF-check'

declare -g -r HELP_POSTFIX_CONFIG='Select Postfix config to edit. Sync option only available if peer setup.'

declare -g -r HELP_POSTFIX_PLUGIN='Select Postfix plugin config to edit. Sync option only available if peer setup.'

declare -g -r HELP_POSTFIX_INFO='Show Postfix infos and stats.

* Queues - Show Postfix queues
* Processes - Show all Postfix processes
* Current logs - Search current (today) log for keyword
* All logs - Search all logs for keyword'

declare -g -r HELP_SPAMASSASSIN_CONFIG='Select Spamassassin config to edit. Sync option only available if peer setup.'

declare -g -r HELP_SPAMASSASSIN_INFO='Show Spamassassin infos and stats.

* Ham stats - Most frequent evaluation criteria for ham mails
* Spam stats - Most frequent evaluation criteria for spam mails
* Spamassassin stats - Stats for rejected, ham and spam mails'

declare -g -r HELP_RSPAMD_FEATURE='Select Rspamd feature to enable.

* Greylisting disabled - Disable greylisting
* Rejecting disabled - Disable rejecting
* Black-/Whitelists - Enable various black- and whitelists
* Bayes-learning - Enable automatic learning of spam/ham messages
* Detailed headers - Enable insertion of detailed Rspamd info to email header
* Detailed history - Enable detailed history in Rspamd Web UI
* Heinlein SA rules - Enable Heinlein Spamassassin rules
* Automatic SA rules update - Enable cron job for daily updates of Spamassassin rules
* URL reputation - Enable checking of URLs against reputation service
* Phishing detection - Enable detection of phishing attempts
* Pyzor - Enable Pyzor collaborative filtering network
* Razor - Enable Razor collaborative filtering network'

declare -g -r HELP_RSPAMD_CONFIG='Select Rspamd config to edit. Sync option only available if peer setup.'

declare -g -r HELP_FAIL2BAN_CONFIG='Select Fail2ban config to edit. Sync option only available if peer setup.'

declare -g -r HELP_OTHER_INFO='Show other info and stats.

* Network connections - Show network connections
* Firewall rules - Show currently active firewall rules'

###################################################################################################
# Menu settings
declare -g TXT_EDITOR="$DEFAULT_EDITOR"
declare -g WGET='wget'

###################################################################################################
# pause and ask for keypress
# parameters:
# none
# return values:
# none
get_keypress() {
    echo
    read -p 'Press any key to continue.'
}

# show wait screen
# parameters:
# none
# return values:
# none
show_wait() {
    "$DIALOG" --backtitle "$TITLE_MAIN" --title '' --infobox 'Please wait...' 3 20
}

# show message in dialog msgbox
# parameters:
# $1 - dialog title
# $2 - message
# return values:
# none
show_info() {
    "$DIALOG" --clear --backtitle "$TITLE_MAIN" --title "$1" --msgbox "$2" 0 0
}

# show help text in dialog msgbox
# parameters:
# $1 - help text
# return values:
# none
show_help() {
    show_info 'Help' "$1"
}

# show program output in dialog programbox
# parameters:
# $1 - dialog title
# return values:
# none
show_output() {
    "$DIALOG" --clear --backtitle "$TITLE_MAIN" --title "$1" --programbox 40 120
}

# get user input in dialog inputbox (IMPORTANT: function call needs to be preceeded by 'exec 3>&1' and followed by 'exec 3>&-')
# parameters:
# $1 - dialog title
# $2 - message
# $3 - default input
# return values:
# stdout - user input
# error code - 0 for Ok, 1 for Cancel
get_input() {
    declare DIALOG_RET RET_CODE

    DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --title "$1" --inputbox "$2" 0 0 "$3" 2>&1 1>&3)"
    RET_CODE="$?"

    [ "$RET_CODE" = 0 ] && echo "$DIALOG_RET"

    return "$RET_CODE"
}

# select file in dialog menu (IMPORTANT: function call needs to be preceeded by 'exec 3>&1' and followed by 'exec 3>&-')
# parameters:
# $1 - dialog title
# $2 - directory
# $3 - allow changing directory
# return values:
# stdout - selected file path
# error code - 0 for Ok, 1 for Cancel
get_file() {
    declare DIRECTORY LIST_DIR LIST_FILE DIALOG_RET RET_CODE
    declare -a MENU_FILE

    DIRECTORY="$2"
    echo "$DIRECTORY" | grep -q '/$' || DIRECTORY+='/'

    if [ "$3" = 1 ]; then
        while true; do
            LIST_FILE="$(ls "$DIRECTORY")"

            MENU_FILE=()
            [ "$DIRECTORY" != '/' ] && MENU_FILE+=('..' '/..')

            LIST_DIR=''

            for NAME_FILE in $LIST_FILE; do
                if [ -d "$DIRECTORY$NAME_FILE" ]; then
                    LIST_DIR+=" $NAME_FILE"
                    MENU_FILE+=("$NAME_FILE" "/$NAME_FILE")
                fi
            done

            for NAME_FILE in $LIST_FILE; do
                [ -f "$DIRECTORY$NAME_FILE" ] && MENU_FILE+=("$NAME_FILE" "$NAME_FILE")
            done

            DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --title "$1" --ok-label 'Select' --no-tags --menu "$DIRECTORY" 0 0 0 "${MENU_FILE[@]}" 2>&1 1>&3)"
            RET_CODE="$?"

            if [ "$RET_CODE" = 0 ]; then
                if [ "$DIALOG_RET" = '..' ]; then
                    DIRECTORY="$(echo "$DIRECTORY" | sed -E 's/[^/]+\/$//')"
                elif echo "$LIST_DIR" | grep -E -q "(^| )$DIALOG_RET($| )"; then
                    DIRECTORY+="$DIALOG_RET/"
                else
                    if ! [ -z "$DIALOG_RET" ]; then
                        echo "$DIRECTORY$DIALOG_RET"

                        return 0
                    else
                        return 1
                    fi
                fi
            else
                return 1
            fi
        done
    else
        LIST_FILE="$(ls "$DIRECTORY")"

        MENU_FILE=()

        if [ -z "$LIST_FILE" ]; then
            MENU_FILE+=('' 'No files')
        else
            for NAME_FILE in $LIST_FILE; do
                [ -f "$DIRECTORY$NAME_FILE" ] && MENU_FILE+=("$NAME_FILE" "$NAME_FILE")
            done
        fi

        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --title "$1" --ok-label 'Select' --no-tags --menu "$DIRECTORY" 0 0 0 "${MENU_FILE[@]}" 2>&1 1>&3)"
        RET_CODE="$?"

        if [ "$RET_CODE" = 0 ] && ! [ -z "$DIALOG_RET" ]; then
            echo "$DIRECTORY$DIALOG_RET"

            return 0
        fi

        return 1
    fi
}

# get yes/no decision
# parameters:
# $1 - question
# return values:
# error code - 0 for Yes, 1 for No
get_yesno() {
    "$DIALOG" --clear --backtitle "$TITLE_MAIN" --title '' --yesno "$1" 0 0
}

# toggle setting
# parameters:
# $1 - setting keyword
# $2 - setting label
# return values:
# error code - 0 if setting changed, 1 if not changed
toggle_setting() {
    declare SETTING_STATUS MESSAGE
    
    MESSAGE="$2 is currently "

    "$1_status"
    SETTING_STATUS="$?"

    [ "$SETTING_STATUS" = 0 ] && MESSAGE+='enabled. Disable?' || MESSAGE+='disabled. Enable?'

    get_yesno "$MESSAGE"

    if [ "$?" = 0 ]; then
        if [ "$SETTING_STATUS" = 0 ]; then
            "$1_disable" && return 0
        else
            "$1_enable" && return 0
        fi
    fi

    return 1
}

# manage list of items in dialog menu
# parameters:
# $1 - title
# $2 - label item
# $3 - list function
# $4 - add function
# $5 - delete function
manage_list() {
    declare -r TAG_NONE='none'
    declare -r LABEL_NONE='-- None --'
    declare ITEM DIALOG_RET RET_CODE RETURN_CODE
    declare -a LIST_ITEM
    declare -a MENU_ITEM

    while true; do
        LIST_ITEM="$("$3")"

        MENU_ITEM=()

        if [ -z "$LIST_ITEM" ]; then
            MENU_ITEM+=("$TAG_NONE" "$LABEL_NONE")
        else
            while read ITEM; do
                MENU_ITEM+=("$ITEM" "$ITEM")
            done < <(echo "$LIST_ITEM")
        fi

        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --title "$1" --ok-label 'Add' --extra-button --extra-label 'Remove' --cancel-label 'Back' --no-tags --menu '' 0 0 0 "${MENU_ITEM[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            exec 3>&1
            DIALOG_RET="$(get_input "Add $2" "Enter $2")"
            RETURN_CODE="$?"
            exec 3>&-

            [ "$RETURN_CODE" = 0 ] && "$4" "$DIALOG_RET"
        elif [ "$RET_CODE" = 3 ]; then
            [ "$DIALOG_RET" = "$TAG_NONE" ] || "$5" "$DIALOG_RET"
        else
            break
        fi
    done
}

# check crontab for entry
# parameters:
# $1 - crontab entry
# return values:
# error code - 0 for entry present, 1 for missing
check_crontab() {
    crontab -l 2>/dev/null | grep -q "^$(echo "$1" | sed 's/\*/\\\*/g')$"
}

# add crontab entry
# parameters:
# $1 - crontab entry
# return values:
# none
add_crontab() {
    declare CRONTAB

    if ! check_crontab "$1"; then
        CRONTAB="$(crontab -l 2>/dev/null)"

        [ -z "$CRONTAB" ] && CRONTAB="$1" || CRONTAB+=$'\n'"$1"

        echo "$CRONTAB" | crontab -
    fi
}

# delete crontab entry
# parameters:
# $1 - crontab entry
# return values:
# none
del_crontab() {
    crontab -l 2>/dev/null | grep -v "^$(echo "$1" | sed 's/\*/\\\*/g')$" | crontab -
}

# enable SysV service
# parameters:
# $1 - service name
# return values:
# none
enable_service() {
    if [ "$DISTRO" = 'redhat' ] || [ "$DISTRO" = 'suse' ]; then
        chkconfig "$1" on
    elif [ "$DISTRO" = 'debian' ]; then
        update-rc.d "$2" defaults
    fi
}

# disable SysV service
# parameters:
# $1 - service name
# return values:
# none
disable_service() {
    if [ "$DISTRO" = 'redhat' ] || [ "$DISTRO" = 'suse' ]; then
        chkconfig "$1" off
    elif [ "$DISTRO" = 'debian' ]; then
        update-rc.d "$1" remove
    fi
}

# check whether Postfix is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_postfix() {
    which postfix &>/dev/null && return 0 || return 1
}

# check whether local DNS resolver is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_resolver() {
    which named &>/dev/null && return 0 || return 1
}

# check whether Postfwd3 is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_postfwd() {
    which /usr/local/postfwd/sbin/postfwd &>/dev/null && return 0 || return 1
}

# check whether Spamassassin is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_spamassassin() {
    which spamassassin &>/dev/null && return 0 || return 1
}

# check whether Spamassassin is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_spamd() {
    check_installed_spamassassin
}

# check whether Rspamd is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_rspamd() {
    which rspamd &>/dev/null && return 0 || return 1
}

# check whether Pyzor is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_pyzor() {
    which pyzor &>/dev/null && return 0 || return 1
}

# check whether Razor is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_razor() {
    which razor-check &>/dev/null && return 0 || return 1
}

# check whether Oletools is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_oletools() {
    which olevba3 &>/dev/null && return 0 || return 1
}

# check whether FuzzyOCR is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_fuzzyocr() {
    cpan -l 2>/dev/null | grep -q '^FuzzyOcr\s' && return 0 || return 1
}

# check whether ClamAV is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_clamav() {
    which clamd &>/dev/null && return 0 || return 1
}

# check whether Sophos AV is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_sophosav() {
    which savdid &>/dev/null && return 0 || return 1
}

# check whether Fail2ban is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_fail2ban() {
    which fail2ban-client &>/dev/null && return 0 || return 1
}

# check whether OpenDKIM is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_dkim() {
    which opendkim &>/dev/null && return 0 || return 1
}

# check whether SPF-check is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_spf() {
    which policyd-spf &>/dev/null && return 0 || return 1
}

# check whether Acme.sh is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_acme() {
    [ -f '/root/.acme.sh/acme.sh' ] && return 0 || return 1
}

# check whether Logwatch is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_logwatch() {
    which logwatch &>/dev/null && return 0 || return 1
}

# check whether log-manager is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_logmanager() {
    [ -f "$CRON_LOGMANAGER" ] && return 0 || return 1
}

# check whether reboot alert is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_reboot() {
    if [ -f "$SCRIPT_REBOOT" ] && check_crontab "$CRONTAB_REBOOT"; then
        return 0
    else
        return 1
    fi
}

# check whether SNMP support is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_snmp() {
    which net-snmp-create-v3-user &>/dev/null && return 0 || return 1
}

# check whether cluster peer is available
# parameters:
# none
# return values:
# error code - 0 for cluster peer available, 1 for not available
check_installed_cluster() {
    if [ -f "$CONFIG_SSH" ] && grep -q '^Host mx$' "$CONFIG_SSH"; then
        return 0
    else
        return 1
    fi
}

# check whether daemonize is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_daemonize() {
    which daemonize &>/dev/null && return 0 || return 1
}

# check whether any Postfix plugin is available
# parameters:
# none
# return values:
# error code - 0 for peer available, 1 for not available
check_installed_plugin() {
    check_installed_postfwd || check_installed_dkim || check_installed_spf
}

###################################################################################################
# Postfix feature custom functions

# check TLS certificate/key Postfix parameter status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 disabled
tls_status() {
    if ! [ -f "$FILE_DHPARAM" ]                                                                                 \
        || [ -z "$(postconf 'smtp_tls_cert_file' 2>/dev/null | sed -E "s/^smtp_tls_cert_file = ?//")" ]         \
        || [ -z "$(postconf 'smtp_tls_key_file' 2>/dev/null | sed -E "s/^smtp_tls_cert_file = ?//")" ]          \
        || [ -z "$(postconf 'smtpd_tls_cert_file' 2>/dev/null | sed -E "s/^smtpd_tls_cert_file = ?//")" ]       \
        || [ -z "$(postconf 'smtpd_tls_key_file' 2>/dev/null | sed -E "s/^smtpd_tls_cert_file = ?//")" ]; then
        return 1
    fi

    return 0
}

# select TLS certificate/key and set TLS Postfix parameters
# parameters:
# none
# return values:
# error code - 0 for changes made, 1 for no changes made
tls_enable() {
    declare FILE_CERT RET_CODE FILE_KEY

    exec 3>&1
    FILE_CERT="$(get_file 'Enter TLS public certificate' '/etc/ssl/')"
    RET_CODE="$?"
    exec 3>&-

    if [ "$RET_CODE" = 0 ]; then
        exec 3>&1
        FILE_KEY="$(get_file 'Enter TLS private key' '/etc/ssl/')"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            if ! [ -f "$FILE_DHPARAM" ]; then
                "$DIALOG" --backtitle "$TITLE_MAIN" --title '' --infobox 'Generating 2048-bit Diffie-Hellman param file.'$'\n\n''This may take a bit longer...' 5 50

                openssl dhparam -out "$FILE_DHPARAM" 2048 &>/dev/null
            fi

            postconf "smtp_tls_cert_file=$FILE_CERT" 2>/dev/null
            postconf "smtp_tls_key_file=$FILE_KEY" 2>/dev/null
            postconf "smtpd_tls_cert_file=$FILE_CERT" 2>/dev/null
            postconf "smtpd_tls_key_file=$FILE_KEY" 2>/dev/null

            return 0
        fi
    fi

    return 1
}

# reset TLS certificate/key Postfix parameter to default
# parameters:
# none
# return values:
# none
tls_disable() {
    declare POSTFIX_SETTING

    for POSTFIX_SETTING in smtp_tls_cert_file smtp_tls_key_file smtpd_tls_cert_file smtpd_tls_key_file; do
        postconf "$POSTFIX_SETTING=$(postconf -d "$POSTFIX_SETTING" 2>/dev/null | sed -E "s/^$POSTFIX_SETTING = ?//")" 2>/dev/null
    done
}

# check bounce notifications status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 disabled
bounce_status() {
    declare SETTING_KEY

    for SETTING_KEY in 2bounce_notice_recipient bounce_notice_recipient delay_notice_recipient error_notice_recipient; do
        [ "$(postconf "$SETTING_KEY" 2>/dev/null)" != "$(postconf -d "$SETTING_KEY" 2>/dev/null)" ] && return 0
    done

    return 1
}

# enable bounce notifications
# parameters:
# none
# return values:
# error code - 0 for changes made, 1 for no changes made
bounce_enable() {
    declare EMAIL_BOUNCE RET_CODE SETTING_KEY

    exec 3>&1
    EMAIL_BOUNCE="$(get_input 'Bounce notification email' 'Enter email address for bounce notifications')"
    RET_CODE="$?"
    exec 3>&-

    if [ "$RET_CODE" = 0 ] && ! [ -z "$EMAIL_BOUNCE" ]; then
        for SETTING_KEY in 2bounce_notice_recipient bounce_notice_recipient delay_notice_recipient error_notice_recipient; do
            postconf "$SETTING_KEY=$EMAIL_BOUNCE" 2>/dev/null
        done

        return 0
    fi

    return 1
}

# disable bounce notifications
# parameters:
# none
# return values:
# none
bounce_disable() {
    declare SETTING_KEY

    for SETTING_KEY in 2bounce_notice_recipient bounce_notice_recipient delay_notice_recipient error_notice_recipient; do
        postconf "$SETTING_KEY=$(postconf -d "$SETTING_KEY" 2>/dev/null | sed -E "s/^$SETTING_KEY = ?//")" 2>/dev/null
    done
}

# check Postscreen status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 for disabled
postscreen_status() {
    if postconf 'postscreen_access_list' 2>/dev/null | sed -E 's/^postscreen_access_list = ?//' | grep -q -E "^permit_mynetworks cidr:$CONFIG_POSTFIX_POSTSCREEN( cidr:$POSTSCREEN_WHITELIST_SPF)?$" \
        && postconf -M 'smtp/inet' 2>/dev/null | grep -q -E '^smtp\s+inet\s+n\s+-\s+y\s+-\s+1\s+postscreen$'                                                                                         \
        && postconf -M 'smtpd/pass' 2>/dev/null | grep -q -E '^smtpd\s+pass\s+-\s+-\s+y\s+-\s+-\s+smtpd(\s+-o\s+content_filter=spamassassin)?$'                                                      \
        && postconf -M 'dnsblog/unix' 2>/dev/null | grep -q -E '^dnsblog\s+unix\s+-\s+-\s+y\s+-\s+0\s+dnsblog$'                                                                                      \
        && postconf -M 'tlsproxy/unix' 2>/dev/null | grep -q -E '^tlsproxy\s+unix\s+-\s+-\s+y\s+-\s+0\s+tlsproxy$'; then
        return 0
    else
        return 1
    fi
}

# checks status of Postscreen Deep
# parameters:
# none
# return values:
# stdout - Postscreen Deep status
psdeep_status() {
    declare POSTFIX_SETTING SETTING_KEY

    for POSTFIX_SETTING in "${POSTSCREEN_PSDEEP[@]}"; do
        SETTING_KEY="$(echo "$POSTFIX_SETTING" | awk -F= '{print $1}')"
        if [ "$(postconf "$SETTING_KEY" 2>/dev/null | sed -E "s/^$SETTING_KEY = ?//")" != "$(echo "$POSTFIX_SETTING" | sed "s/^$SETTING_KEY=//")" ]; then
            echo 'off'
            return
        fi
    done

    echo 'on'
}

# enable Postscreen Deep
# parameters:
# none
# return values:
# none
psdeep_enable() {
    declare POSTFIX_SETTING

    for POSTFIX_SETTING in "${POSTSCREEN_PSDEEP[@]}"; do
        postconf "$POSTFIX_SETTING" 2>/dev/null
    done
}

# disable Postscreen Deep
# parameters:
# none
# return values:
# none
psdeep_disable() {
    declare POSTFIX_SETTING SETTING_KEY

    for POSTFIX_SETTING in "${POSTSCREEN_PSDEEP[@]}"; do
        SETTING_KEY="$(echo "$POSTFIX_SETTING" | awk -F= '{print $1}')"
        postconf "$SETTING_KEY=$(postconf -d "$SETTING_KEY" 2>/dev/null | sed -E "s/^$SETTING_KEY = ?//")" 2>/dev/null
    done
}

# checks status of Postscreen whitelist update
# parameters:
# none
# return values:
# stdout - Postscreen whitelist update status
pswlupdate_status() {
    if ! postconf 'postscreen_access_list' 2>/dev/null | sed -E 's/^postscreen_access_list = ?//' | grep -q -E "^permit_mynetworks cidr:$CONFIG_POSTFIX_POSTSCREEN cidr:$POSTSCREEN_WHITELIST_SPF$" \
        || ! [ -f "$SCRIPT_PSWLUPDATE" ] || ! check_crontab "$CRONTAB_PSWLUPDATE"; then
        echo 'off'
        return
    fi

    echo 'on'
}

# enable Postscreen whitelist update
# parameters:
# none
# return values:
# none
pswlupdate_enable() {
    declare -r PACKED_SCRIPT='
    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
    '

    mkdir -p "$(dirname "$SCRIPT_PSWLUPDATE")"
    printf '%s' $PACKED_SCRIPT | base64 -d | gunzip > "$SCRIPT_PSWLUPDATE"
    chmod 700 "$SCRIPT_PSWLUPDATE"
    "$SCRIPT_PSWLUPDATE"

    add_crontab "$CRONTAB_PSWLUPDATE"

    postconf "postscreen_access_list=permit_mynetworks cidr:$CONFIG_POSTFIX_POSTSCREEN cidr:$POSTSCREEN_WHITELIST_SPF" 2>/dev/null
}

# disable Postscreen whitelist update
# parameters:
# none
# return values:
# none
pswlupdate_disable() {
    del_crontab "$CRONTAB_PSWLUPDATE"

    rm -f "$SCRIPT_PSWLUPDATE"
}

# enable Postscreen
# parameters:
# none
# return values:
# none
postscreen_enable() {
    declare -a MENU_POSTSCREEN_FEATURE
    declare DIALOG_RET RET_CODE FEATURE

    MENU_POSTSCREEN_FEATURE=()

    for FEATURE in "${POSTSCREEN_FEATURE[@]}"; do
        declare -r STATUS_POSTSCREEN_${FEATURE^^}="$("${FEATURE}_status")"

        MENU_POSTSCREEN_FEATURE+=("$FEATURE" "$(eval echo \"\$POSTSCREEN_${FEATURE^^}_LABEL\")" "$(eval echo \"\$STATUS_POSTSCREEN_${FEATURE^^}\")")
    done

    while true; do
        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --ok-label 'Select' --no-tags --extra-button --extra-label 'Help' --checklist 'Choose Postscreen features to enable' 0 0 0 "${MENU_POSTSCREEN_FEATURE[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            for FEATURE in "${POSTSCREEN_FEATURE[@]}"; do
                if echo "$DIALOG_RET" | grep -E -q "(^| )$FEATURE($| )"; then
                    "${FEATURE}_enable"
                else
                    "${FEATURE}_disable"
                fi
            done

            break
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$HELP_POSTSCREEN_FEATURE"
        else
            return 1
        fi
    done

    [ "$(pswlupdate_status)" = 'off' ] && postconf "postscreen_access_list=permit_mynetworks cidr:$CONFIG_POSTFIX_POSTSCREEN" 2>/dev/null

    postconf -Me 'smtp/inet=smtp inet n - y - 1 postscreen' 2>/dev/null
    [ "$(postfix_feature_status 'spamassassin')" = 'off' ] && postconf -Me 'smtpd/pass=smtpd pass - - y - - smtpd' 2>/dev/null
    postconf -Me 'dnsblog/unix=dnsblog unix - - y - 0 dnsblog' 2>/dev/null
    postconf -Me 'tlsproxy/unix=tlsproxy unix - - y - 0 tlsproxy' 2>/dev/null
}

# disable Postscreen
# parameters:
# none
# return values:
# none
postscreen_disable() {
    [ "$(pswlupdate_status)" = 'on' ] && pswlupdate_disable
    [ "$(psdeep_status)" = 'on' ] && psdeep_disable

    postconf "postscreen_access_list=$(postconf -d 'postscreen_access_list' 2>/dev/null | sed -E 's/^$postscreen_access_list = ?//')" 2>/dev/null

    postconf -MX 'smtp/inet' 2>/dev/null
    [ "$(postfix_feature_status 'spamassassin')" = 'off' ] && postconf -MX 'smtpd/pass' 2>/dev/null
    postconf -MX 'dnsblog/unix' 2>/dev/null
    postconf -MX 'tlsproxy/unix' 2>/dev/null
}

# check Submission status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 for disabled
submission_status() {
    if postconf -M 'submission/inet' 2>/dev/null | grep -q -E '^submission\s+inet\s+n\s+-\s+n\s+-\s+-\s+smtpd\s+-o\s+message_size_limit=\s+-o\s+smtpd_milters=\s+-o\s+smtpd_recipient_restrictions=$'; then
        return 0
    else
        return 1
    fi
}

# enable Submission
# parameters:
# none
# return values:
# none
submission_enable() {
    postconf -Me 'submission/inet=submission inet n - n - - smtpd -o message_size_limit= -o smtpd_milters= -o smtpd_recipient_restrictions=' 2>/dev/null
}

# disable Submission
# parameters:
# none
# return values:
# none
submission_disable() {
    postconf -MX 'submission/inet' 2>/dev/null
}

# check recipient restrictions status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 for disabled
recipient_status() {
    declare RESTRICTION_CURRENT
    
    RESTRICTION_CURRENT="$(postconf 'smtpd_recipient_restrictions' 2>/dev/null)"

    postfwd_status && RESTRICTION_CURRENT=$(echo "$RESTRICTION_CURRENT" | sed -E "s/(, | )?$POSTFWD_ACCESS//g")

    if [ "$RESTRICTION_CURRENT" != "$(postconf -d 'smtpd_recipient_restrictions' 2>/dev/null)" ]; then
        return 0
    fi
    
    return 1
}

# check unverified recipient restriction status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 for disabled
unverified_status() {
    if [ "$(postconf 'address_verify_transport_maps' 2>/dev/null | sed -E 's/^address_verify_transport_maps = ?//')" = "hash:$CONFIG_POSTFIX_TRANSPORT" ]               \
        && [ -z "$(postconf 'address_verify_map' 2>/dev/null | sed -E 's/^address_verify_map = ?//')" ]                                                                 \
        && [ "$(postconf 'unverified_recipient_reject_reason' 2>/dev/null | sed -E 's/^unverified_recipient_reject_reason = ?//')" = "User doesn't exist" ]; then
        return 0
    else
        return 1
    fi
}

# enable unverified recipient restriction
# parameters:
# none
# return values:
# none
unverified_enable() {
    postconf "address_verify_transport_maps=hash:$CONFIG_POSTFIX_TRANSPORT" 2>/dev/null
    postconf 'address_verify_map=' 2>/dev/null
    postconf "unverified_recipient_reject_reason=User doesn't exist" 2>/dev/null
}

# disable unverified recipient restriction
# parameters:
# none
# return values:
# none
unverified_disable() {
    postconf "address_verify_transport_maps=$(postconf -d 'address_verify_transport_maps')" 2>/dev/null
    postconf "address_verify_map=$(postconf -d 'address_verify_map')" 2>/dev/null
    postconf "unverified_recipient_reject_reason=$(postconf -d 'unverified_recipient_reject_reason')" 2>/dev/null
}

# enable recipient restrictions
# parameters:
# none
# return values:
# error code - 0 for changes made, 1 for no changes made
recipient_enable() {
    declare -a MENU_RESTRICTION
    declare RESTRICTION_CURRENT POSTFWD_ACTIVE LIST_RESTRICTION RESTRICTION DIALOG_RET RET_CODE RESTRICTION_NEW

    RESTRICTION_CURRENT="$(postconf 'smtpd_recipient_restrictions' 2>/dev/null | sed -E 's/^smtpd_recipient_restrictions = ?//')"

    echo "$RESTRICTION_CURRENT" | grep -E -q "(^| )$POSTFWD_ACCESS($|,)" && POSTFWD_ACTIVE=1

    LIST_RESTRICTION="$(echo "$RESTRICTION_CURRENT" | sed -E "s/^$(echo "$RECIPIENT_ACCESS" | sed 's/\//\\\//g')//" | sed -E "s/(, )?$POSTFWD_ACCESS//g")"
    MENU_RESTRICTION=()

    for RESTRICTION in unknown_client invalid_hostname non_fqdn_hostname unknown_reverse_client_hostname non_fqdn_helo_hostname invalid_helo_hostname   \
        unknown_helo_hostname non_fqdn_sender unknown_sender_domain unknown_recipient_domain non_fqdn_recipient unauth_pipelining; do
        echo "$LIST_RESTRICTION" | grep -E -q "(^| )reject_$RESTRICTION($|,)" && MENU_RESTRICTION+=("$RESTRICTION" "$RESTRICTION" 'on') || MENU_RESTRICTION+=("$RESTRICTION" "$RESTRICTION" 'off')
    done

    if echo "$LIST_RESTRICTION" | grep -E -q '(^| )reject_unverified_recipient($|,)' && unverified_status; then
        declare -r STATUS_UNVERIFIED='on'
    else
        declare -r STATUS_UNVERIFIED='off'
    fi

    MENU_RESTRICTION+=('unverified_recipient' 'unverified_recipient' "$STATUS_UNVERIFIED")

    exec 3>&1
    DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Cancel' --ok-label 'Select' --no-tags --checklist 'Choose recipient restriction to enable' 0 0 0 "${MENU_RESTRICTION[@]}" 2>&1 1>&3)"
    RET_CODE="$?"
    exec 3>&-

    if [ "$RET_CODE" = 0 ]; then
        RESTRICTION_NEW="$RECIPIENT_ACCESS$(echo "$DIALOG_RET" | sed -E 's/ ?(\S+)/, reject_\1/g')"
        [ "$POSTFWD_ACTIVE" = 1 ] && RESTRICTION_NEW+=", $POSTFWD_ACCESS"

        if [ "$RESTRICTION_NEW" != "$RESTRICTION_CURRENT" ]; then
            postconf "smtpd_recipient_restrictions=$RESTRICTION_NEW" 2>/dev/null

            if echo "$DIALOG_RET" | grep -E -q '(^| )unverified_recipient($| )'; then
                [ "$STATUS_UNVERIFIED" = 'off' ] && unverified_enable
            else
                [ "$STATUS_UNVERIFIED" = 'on' ] && unverified_disable
            fi

            return 0
        fi
    fi

    return 1
}

# disable recipient restrictions
# parameters:
# none
# return values:
# none
recipient_disable() {
    declare -r RESTRICTION_DEFAULT="$(postconf -d 'smtpd_recipient_restrictions' 2>/dev/null | sed -E 's/^smtpd_recipient_restrictions = ?//')"

    if postfwd_status; then
        if [ -z "$RESTRICTION_DEFAULT" ]; then
            postconf "smtpd_recipient_restrictions=$POSTFWD_ACCESS" 2>/dev/null
        else
            postconf "smtpd_recipient_restrictions=$RESTRICTION_DEFAULT, $POSTFWD_ACCESS" 2>/dev/null
        fi
    else
        postconf "smtpd_recipient_restrictions=$RESTRICTION_DEFAULT" 2>/dev/null
    fi
}

# check Postfwd status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 for disabled
postfwd_status() {
    if postconf 'smtpd_recipient_restrictions' 2>/dev/null | sed -E 's/^smtpd_recipient_restrictions = ?//' | grep -E -q "(^| )$POSTFWD_ACCESS($|,)"; then
        return 0
    else
        return 1
    fi
}

# enable Postfwd
# parameters:
# none
# return values:
# none
postfwd_enable() {
    declare -r RESTRICTION_CURRENT="$(postconf 'smtpd_recipient_restrictions' 2>/dev/null | sed -E 's/^smtpd_recipient_restrictions = ?//')"

    if [ -z "$RESTRICTION_CURRENT" ]; then
        postconf "smtpd_recipient_restrictions=$POSTFWD_ACCESS"
    else
        postconf "smtpd_recipient_restrictions=$RESTRICTION_CURRENT, $POSTFWD_ACCESS" 2>/dev/null
    fi
}

# disable Postfwd
# parameters:
# none
# return values:
# none
postfwd_disable() {
    postconf "smtpd_recipient_restrictions=$(postconf 'smtpd_recipient_restrictions' 2>/dev/null | sed -E 's/^smtpd_recipient_restrictions = ?//' | sed -E "s/(, )?$POSTFWD_ACCESS//g")" 2>/dev/null
}

# check Spamassassin status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 for disabled
spamassassin_status() {
    if postconf -M 'smtpd/pass' 2>/dev/null | grep -q -E '^smtpd\s+pass\s+-\s+-\s+y\s+-\s+-\s+smtpd\s+-o\s+content_filter=spamassassin$'                                                                                                              \
        && postconf -M 'spamassassin/unix' 2>/dev/null | grep -q -E '^spamassassin\s+unix\s+-\s+n\s+n\s+-\s+-\s+pipe\s+user=spamd\s+argv=/usr/bin/spamc\s+-s\s+1024000\s+-f\s+-e\s+/usr/sbin/sendmail\s+-oi\s+-f\s+\${sender}\s+\${recipient}$'; then
        return 0
    else
        return 1
    fi
}

# enable Spamassassin
# parameters:
# none
# return values:
# none
spamassassin_enable() {
    postconf -Me 'smtpd/pass=smtpd pass - - y - - smtpd -o content_filter=spamassassin' 2>/dev/null
    postconf -Me 'spamassassin/unix=spamassassin unix - n n - - pipe user=spamd argv=/usr/bin/spamc -s 1024000 -f -e /usr/sbin/sendmail -oi -f ${sender} ${recipient}' 2>/dev/null
}

# disable Spamassassin
# parameters:
# none
# return values:
# none
spamassassin_disable() {
    postscreen_status || postconf -MX 'smtpd/pass' 2>/dev/null
    postconf -MX 'spamassassin/unix' 2>/dev/null
}

# check Rspamd status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 for disabled
rspamd_status() {
    if postconf smtpd_milters 2>/dev/null | sed -E 's/^smtpd_milters = ?//' | grep -q 'inet:127.0.0.1:11332'; then
        return 0
    else
        return 1
    fi
}

# enable Rspamd
# parameters:
# none
# return values:
# none
rspamd_enable() {
    declare LIST_MILTER

    LIST_MILTER="$(postconf smtpd_milters 2>/dev/null | sed -E 's/^smtpd_milters = ?//')"

    [ -z "$LIST_MILTER" ] && LIST_MILTER='inet:127.0.0.1:11332' || LIST_MILTER+=', inet:127.0.0.1:11332'
    
    postconf "smtpd_milters=$LIST_MILTER" 2>/dev/null
}

# disable Rspamd
# parameters:
# none
# return values:
# none
rspamd_disable() {
    declare LIST_MILTER

    LIST_MILTER="$(postconf smtpd_milters 2>/dev/null | sed -E 's/^smtpd_milters = ?//')"

    if [ "$LIST_MILTER" = 'inet:127.0.0.1:11332' ]; then
        LIST_MILTER=''
    elif echo "$LIST_MILTER" | grep -E -q ', ?inet:127.0.0.1:11332'; then
        LIST_MILTER="$(echo "$LIST_MILTER" | sed -E 's/, ?inet:127.0.0.1:11332//')"
    else
        LIST_MILTER="$(echo "$LIST_MILTER" | sed -E 's/inet:127.0.0.1:11332, //')"
    fi

    postconf "smtpd_milters=$LIST_MILTER" 2>/dev/null
}

# check SPF-check status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 for disabled
spf_status() {
    if postconf -M 'policyd-spf/unix' 2>/dev/null | grep -q -E '^policyd-spf\s+unix\s+-\s+n\s+n\s+-\s+0\s+spawn\s+user=policyd-spf\s+argv=/usr/bin/policyd-spf$'; then
        return 0
    else
        return 1
    fi
}

# enable SPF-check
# parameters:
# none
# return values:
# none
spf_enable() {
    postconf -Me 'policyd-spf/unix=policyd-spf unix - n n - 0 spawn user=policyd-spf argv=/usr/bin/policyd-spf' 2>/dev/null
}

# disable SPF-check
# parameters:
# none
# return values:
# none
spf_disable() {
    postconf -MX 'policyd-spf/unix' 2>/dev/null
}

# check DKIM status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 for disabled
dkim_status() {
    if postconf smtpd_milters 2>/dev/null | sed -E 's/^smtpd_milters = ?//' | grep -q 'inet:127.0.0.1:10001'; then
        return 0
    else
        return 1
    fi
}

# enable DKIM
# parameters:
# none
# return values:
# none
dkim_enable() {
    declare LIST_MILTER

    LIST_MILTER="$(postconf smtpd_milters 2>/dev/null | sed -E 's/^smtpd_milters = ?//')"

    [ -z "$LIST_MILTER" ] && LIST_MILTER='inet:127.0.0.1:10001' || LIST_MILTER+=', inet:127.0.0.1:10001'
    
    postconf "smtpd_milters=$LIST_MILTER" 2>/dev/null
}

# disable DKIM
# parameters:
# none
# return values:
# none
dkim_disable() {
    declare LIST_MILTER

    LIST_MILTER="$(postconf smtpd_milters 2>/dev/null | sed -E 's/^smtpd_milters = ?//')"

    if [ "$LIST_MILTER" = 'inet:127.0.0.1:10001' ]; then
        LIST_MILTER=''
    elif echo "$LIST_MILTER" | grep -E -q ', ?inet:127.0.0.1:10001'; then
        LIST_MILTER="$(echo "$LIST_MILTER" | sed -E 's/, ?inet:127.0.0.1:10001//')"
    else
        LIST_MILTER="$(echo "$LIST_MILTER" | sed -E 's/inet:127.0.0.1:10001, //')"
    fi

    postconf "smtpd_milters=$LIST_MILTER" 2>/dev/null
}

# checks status of given Postfix feature
# parameters:
# $1 - feature label
# return values:
# stdout - feature status
postfix_feature_status() {
    declare POSTFIX_SETTING SETTING_KEY

    if [ "$(eval echo \"\$POSTFIX_${1^^}_CUSTOM\")" = 1 ] && ! "${1}_status"; then
        echo 'off'
        return
    fi

    while read POSTFIX_SETTING; do
        SETTING_KEY="$(echo "$POSTFIX_SETTING" | awk -F= '{print $1}')"
        if [ "$(postconf "$SETTING_KEY" 2>/dev/null | sed -E "s/^$SETTING_KEY = ?//")" != "$(echo "$POSTFIX_SETTING" | sed "s/^$SETTING_KEY=//")" ]; then
            echo 'off'
            return
        fi
    done < <(eval "for ELEMENT in \"\${POSTFIX_${1^^}[@]}\"; do echo \"\$ELEMENT\"; done")

    echo 'on'
}

# enable given Postfix feature
# parameters:
# $1 - feature label
# return values:
# error code - 0 for changes made, 1 for no changes made
postfix_feature_enable() {
    declare POSTFIX_SETTING

    if [ "$(eval echo \"\$POSTFIX_${1^^}_CUSTOM\")" = 1 ]; then
        "${1}_enable" || return 1
    fi

    while read POSTFIX_SETTING; do
        postconf "$POSTFIX_SETTING" 2>/dev/null
    done < <(eval "for ELEMENT in \"\${POSTFIX_${1^^}[@]}\"; do echo \"\$ELEMENT\"; done")

    return 0
}

# disable given Postfix feature
# parameters:
# $1 - feature label
# return values:
# error code - 0 for changes made, 1 for no changes made
postfix_feature_disable() {
    declare POSTFIX_SETTING SETTING_KEY

    if [ "$(eval echo \"\$POSTFIX_${1^^}_CUSTOM\")" = 1 ]; then
        "${1}_disable" || return 1
    fi

    while read POSTFIX_SETTING; do
        SETTING_KEY="$(echo "$POSTFIX_SETTING" | awk -F= '{print $1}')"
        postconf "$SETTING_KEY=$(postconf -d "$SETTING_KEY" 2>/dev/null | sed -E "s/^$SETTING_KEY = ?//")" 2>/dev/null
    done < <(eval "for ELEMENT in \"\${POSTFIX_${1^^}[@]}\"; do echo \"\$ELEMENT\"; done")

    return 0
}

# restart Postfix
# parameters:
# none
# return values:
# none
postfix_restart() {
    postfix stop &>/dev/null
    postfix start &>/dev/null
}

# enable/disable Postfix features in dialog checklist
# parameters:
# none
# return values:
# none
postfix_feature() {
    declare -a MENU_POSTFIX_FEATURE
    declare DIALOG_RET RET_CODE POSTFIX_RESTART FEATURE

    MENU_POSTFIX_FEATURE=()

    for FEATURE in "${POSTFIX_FEATURE[@]}"; do
        if [ "$(eval echo \"\$POSTFIX_${FEATURE^^}_CHECK\")" != 1 ] || "check_installed_$FEATURE"; then
            declare -r STATUS_POSTFIX_${FEATURE^^}="$(postfix_feature_status "$FEATURE")"

            MENU_POSTFIX_FEATURE+=("$FEATURE" "$(eval echo \"\$POSTFIX_${FEATURE^^}_LABEL\")" "$(eval echo \"\$STATUS_POSTFIX_${FEATURE^^}\")")
        fi
    done

    while true; do
        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --ok-label 'Select' --no-tags --extra-button --extra-label 'Help' --checklist 'Choose Postfix features to enable' 0 0 0 "${MENU_POSTFIX_FEATURE[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            show_wait
            POSTFIX_RESTART=0

            for FEATURE in "${POSTFIX_FEATURE[@]}"; do
                if echo "$DIALOG_RET" | grep -E -q "(^| )$FEATURE($| )"; then
                    if [ "$(eval echo \"\$POSTFIX_${FEATURE^^}_FORCE\")" = 1 ] || [ "$(eval echo \"\$STATUS_POSTFIX_${FEATURE^^}\")" = 'off' ]; then
                        postfix_feature_enable "$FEATURE" && POSTFIX_RESTART=1
                    fi
                else
                    if [ "$(eval echo \"\$STATUS_POSTFIX_${FEATURE^^}\")" = 'on' ]; then
                        postfix_feature_disable "$FEATURE" && POSTFIX_RESTART=1
                    fi
                fi
            done

            [ "$POSTFIX_RESTART" = 1 ] && postfix_restart

            break
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$HELP_POSTFIX_FEATURE"
        else
            break
        fi
    done
}

# edit config file
# parameters:
# $1 - config file
# return values:
# stderr - 1 if config file changed, 0 if not changed
edit_config() {
    declare -r TMP_CONFIG='/tmp/TMPconfig'

    if [ -f "$1" ]; then
        cp -f "$1" "$TMP_CONFIG"
    else
        touch "$TMP_CONFIG"
    fi

    "$TXT_EDITOR" "$TMP_CONFIG"

    diff -N -s "$TMP_CONFIG" "$1" &>/dev/null

    if [ "$?" != 0 ]; then
        mv -f "$TMP_CONFIG" "$1"

        return 0
    fi

    rm -f "$TMP_CONFIG"

    return 1
}

# select Postfix configuration file for editing in dialog menu
# parameters:
# $1 - config tag (either 'server' or 'client')
# return values:
# none
postfix_config() {
    declare -a MENU_POSTFIX_CONFIG
    declare CONFIG DIALOG_RET RET_CODE FILE_CONFIG

    MENU_POSTFIX_CONFIG=()

    while read CONFIG; do
        MENU_POSTFIX_CONFIG+=("$CONFIG" "$(eval echo \"\$LABEL_CONFIG_POSTFIX_${CONFIG^^}\")")
    done < <(eval "for ELEMENT in \"\${POSTFIX_CONFIG_${1^^}[@]}\"; do echo \"\$ELEMENT\"; done")

    while true; do
        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --ok-label 'Select' --no-tags --extra-button --extra-label 'Help' --menu 'Choose Postfix config to edit' 0 0 0 "${MENU_POSTFIX_CONFIG[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            FILE_CONFIG="$(eval echo \"\$CONFIG_POSTFIX_${DIALOG_RET^^}\")"

            edit_config "$FILE_CONFIG"

            if [ "$?" = 0 ]; then
                if [ "$DIALOG_RET" = 'transport' ] || postconf 2>/dev/null | grep -q "hash:$FILE_CONFIG"; then
                    postmap "$FILE_CONFIG" &>/dev/null
                fi

                postfix reload &>/dev/null
            fi
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$(eval echo \"\$HELP_POSTFIX_${1^^}\")"
        else
            break
        fi
    done
}

# select Postfix server configuration file for editing
# parameters:
# none
# return values:
# none
postfix_server() {
    postfix_config 'server'
}

# select Postfix client configuration file for editing
# parameters:
# none
# return values:
# none
postfix_client() {
    postfix_config 'client'
}

# show Postfix queues
# parameters:
# none
# return values:
# none
show_queues() {
    declare -r INFO="$(postmulti -x sh -c 'echo "-- $MAIL_CONFIG"; qshape deferred | head -12')"

    show_info 'Postfix queues' "$INFO"
}
# show Postfix processes
# parameters:
# none
# return values:
# none
show_processes() {
    declare -r INFO="$(ps aux | grep postfix)"

    show_info 'Postfix processes' "$INFO"
}

# select Postfix info to show in dialog menu
# parameters:
# none
# return values:
# none
postfix_info() {
    declare -a MENU_POSTFIX_INFO
    declare DIALOG_RET RET_CODE

    MENU_POSTFIX_INFO=()
    MENU_POSTFIX_INFO+=('queues' 'Queues')
    MENU_POSTFIX_INFO+=('processes' 'Processes')

    while true; do
        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --ok-label 'Select' --no-tags --extra-button --extra-label 'Help' --menu 'Choose Postfix info to show' 0 0 0 "${MENU_POSTFIX_INFO[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            "show_$DIALOG_RET"
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$HELP_POSTFIX_INFO"
        else
            break
        fi
    done
}

# sync Postfix config with other peer
# parameters:
# none
# return values:
# none
postfix_sync() {
    show_wait
    rsync -avzh -e ssh "$DIR_MAPS/" mx:"$DIR_MAPS/" &>/dev/null
    ssh mx postfix reload &>/dev/null
}

# edit Postfwd config
# parameters:
# none
# return values:
# none
postfwd_config() {
    edit_config "$CONFIG_POSTFWD" && systemctl reload postfwd &>/dev/null
}

# sync Postfwd config
# parameters:
# none
# return values:
# none
postfwd_sync() {
    show_wait
    rsync -avzh -e ssh "$CONFIG_POSTFWD" mx:"$CONFIG_POSTFWD" &>/dev/null
    ssh mx systemctl reload postfwd &>/dev/null
}

# reload Bind resolver
# parameters:
# none
# return values:
# none
bind_reload() {
    systemctl reload "$SERVICE_BIND" &>/dev/null
}

# edit local DNS resolver config
# parameters:
# none
# return values:
# none
resolver_config() {
    edit_config "$CONFIG_RESOLVER" && bind_reload
}

# add forwarder IP address to forward zone
# parameters:
# $1 - zone name
# return values:
# none
add_forwarder() {
    declare FORWARDER_NEW RET_CODE LIST_FORWARD

    exec 3>&1
    FORWARDER_NEW="$(get_input 'Add forwarder IP' 'Enter IP address of forwarder')"
    RET_CODE="$?"
    exec 3>&-

    if [ "$RET_CODE" = 0 ] && ! [ -z "$FORWARDER_NEW" ]; then
        LIST_FORWARD="$(sed -n "/^zone \"$1\" {$/,/^};$/p" "$CONFIG_RESOLVER_FORWARD" | grep -E $'\t''forwarders {' | awk 'match($0, /^\tforwarders { (.*[^ ]+) };$/, a) {print a[1]}')"

        [ -z "$LIST_FORWARD" ] && LIST_FORWARD="$FORWARDER_NEW;" || LIST_FORWARD+=" $FORWARDER_NEW;"

        sed -i "/^zone \"$1\" {$/,/^};$/d" "$CONFIG_RESOLVER_FORWARD"
        echo "zone \"$1\" {"$'\n\t''type forward;'$'\n\t''forward only;'$'\n\t'"forwarders { $LIST_FORWARD };"$'\n''};' >> "$CONFIG_RESOLVER_FORWARD"

        bind_reload
    fi
}

# remove forwarder IP address from forward zone
# parameters:
# $1 - zone name
# $2 - forwarder name
# return values:
# none
remove_forwarder() {
    declare LIST_FORWARD

    LIST_FORWARD="$(sed -n "/^zone \"$1\" {$/,/^};$/p" "$CONFIG_RESOLVER_FORWARD" | grep -E $'\t''forwarders {' | awk 'match($0, /^\tforwarders { (.*[^ ]+) };$/, a) {print a[1]}' | sed -E "s/ ?$2;//")"

    sed -i "/^zone \"$1\" {$/,/^};$/d" "$CONFIG_RESOLVER_FORWARD"
    echo "zone \"$1\" {"$'\n\t''type forward;'$'\n\t''forward only;'$'\n\t'"forwarders { $LIST_FORWARD };"$'\n''};' >> "$CONFIG_RESOLVER_FORWARD"

    bind_reload
}

# edit forward zone
# parameters:
# $1 - zone name
# return values:
# none
forward_zone() {
    declare LIST_FORWARD IP_ADDRESS DIALOG_RET RET_CODE
    declare -a MENU_FORWARD

    while true; do
        LIST_FORWARD="$(sed -n "/^zone \"$1\" {$/,/^};$/p" "$CONFIG_RESOLVER_FORWARD" | grep -E $'\t''forwarders {' | awk 'match($0, /^\tforwarders { (.*[^ ]+) };$/, a) {print a[1]}' | sed 's/;//g')"

        MENU_FORWARD=()

        if [ -z "$LIST_FORWARD" ]; then
            MENU_FORWARD+=('' 'No forwarders')

            "$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --ok-label 'Add' --no-tags --menu 'Choose forwarder IP address to remove' 0 0 0 "${MENU_FORWARD[@]}"

            if [ "$?" = 0 ]; then
                add_forwarder "$1"
            else
                break
            fi
        else
            for IP_ADDRESS in $LIST_FORWARD; do
                MENU_FORWARD+=("$IP_ADDRESS" "$IP_ADDRESS")
            done

            exec 3>&1
            DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --ok-label 'Remove' --no-tags --extra-button --extra-label 'Add' --menu 'Choose forwarder IP address to remove' 0 0 0 "${MENU_FORWARD[@]}" 2>&1 1>&3)"
            RET_CODE="$?"
            exec 3>&-

            if [ "$RET_CODE" = 0 ] && ! [ -z "$DIALOG_RET" ]; then
                remove_forwarder "$1" "$DIALOG_RET"
            elif [ "$RET_CODE" = 3 ]; then
                add_forwarder "$1"
            else
                break
            fi
        fi
    done
}

# add forward zone
# parameters:
# none
# return values:
# none
add_forward() {
    declare FORWARD_NEW RET_CODE

    exec 3>&1
    FORWARD_NEW="$(get_input 'Add forward zone' 'Enter name of forward zone')"
    RET_CODE="$?"
    exec 3>&-

    if [ "$RET_CODE" = 0 ] && ! [ -z "$FORWARD_NEW" ]; then
        echo "zone \"$FORWARD_NEW\" {"$'\n\t''type forward;'$'\n\t''forward only;'$'\n\t'"forwarders {  };"$'\n''};' >> "$CONFIG_RESOLVER_FORWARD"

        forward_zone "$FORWARD_NEW"

        bind_reload
    fi
}

# manage forward zones in dialog menu
# parameters:
# none
# return values:
# none
resolver_forward() {
    declare LIST_FORWARD DIALOG_RET RET_CODE ZONE_FORWARD
    declare -a MENU_FORWARD

    while true; do
        [ -f "$CONFIG_RESOLVER_FORWARD" ] && LIST_FORWARD="$(grep -E '^zone "\S+" {' "$CONFIG_RESOLVER_FORWARD" | awk 'match($0, /^zone "([^"]+)" {$/, a) {print a[1]}')"

        MENU_FORWARD=()

        if [ -z "$LIST_FORWARD" ]; then
            MENU_FORWARD+=('' 'No forward zones')

            "$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --ok-label 'Add' --no-tags --menu 'Choose forward zone to edit' 0 0 0 "${MENU_FORWARD[@]}"

            if [ "$?" = 0 ]; then
                add_forward
            else
                break
            fi
        else
            for ZONE_FORWARD in $LIST_FORWARD; do
                MENU_FORWARD+=("$ZONE_FORWARD" "$ZONE_FORWARD")
            done

            exec 3>&1
            DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --ok-label 'Edit' --no-tags --extra-button --extra-label 'Add' --menu 'Choose forward zone to edit' 0 0 0 "${MENU_FORWARD[@]}" 2>&1 1>&3)"
            RET_CODE="$?"
            exec 3>&-

            if [ "$RET_CODE" = 0 ] && ! [ -z "$DIALOG_RET" ]; then
                forward_zone "$DIALOG_RET"
            elif [ "$RET_CODE" = 3 ]; then
                add_forward
            else
                break
            fi
        fi
    done
}

# add local zone
# parameters:
# none
# return values:
# none
add_local() {
    declare LOCAL_NEW RET_CODE FILE_ZONE

    exec 3>&1
    LOCAL_NEW="$(get_input 'Add local zone' 'Enter name of local zone')"
    RET_CODE="$?"
    exec 3>&-

    if [ "$RET_CODE" = 0 ] && ! [ -z "$LOCAL_NEW" ]; then
        FILE_ZONE="$LOCAL_NEW.db"

        echo "zone \"$LOCAL_NEW\" {"$'\n\t''type master;'$'\n\t'"file \"$FILE_ZONE\";"$'\n''};' >> "$CONFIG_RESOLVER_LOCAL"
        echo '$TTL 86400'$'\n'"@   IN SOA  ns.$LOCAL_NEW. hostmaster.$LOCAL_NEW. ("$'\n'"       $(date +%Y%m%d)00   ; serial"$'\n''       3600         ; refresh'$'\n''       1800         ; retry'$'\n''       1209600      ; expire'$'\n''       86400 )      ; minimum'$'\n'"@        IN      NS      ns.$LOCAL_NEW."$'\n''ns       IN      A       127.0.0.1' > "$DIR_ZONE/$FILE_ZONE"

        bind_reload
    fi
}

# edit zone file
# parameters:
# $1 - zone name
# return values:
# stderr - 0 if zone file changed, 1 if not changed
edit_zone() {
    declare -r FILE_ZONE="$DIR_ZONE/$1.db"
    declare -r TMP_ZONE='/tmp/TMPzone'
    declare -r TMP_CONFIG='/tmp/TMPconfig'
    declare RET_CODE SERIAL_LAST DATE_NEW DATE_LAST SERIAL_NEW

    SERIAL_LAST="$(grep '; serial$' "$FILE_ZONE" | awk '{print $1}')"

    sed "s/^       $SERIAL_LAST   ; serial$/       <do not edit>; serial/" "$FILE_ZONE" > "$TMP_ZONE"

    cp -f "$TMP_ZONE" "$TMP_CONFIG"

    "$TXT_EDITOR" "$TMP_CONFIG"

    diff -N -s "$TMP_CONFIG" "$TMP_ZONE" &>/dev/null
    RET_CODE="$?"

    if [ "$RET_CODE" != 0 ]; then
        DATE_NEW="$(date +%Y%m%d)"
        DATE_LAST="$(echo "$SERIAL_LAST" | cut -c -8)"

        if [ "$DATE_NEW" -le "$DATE_LAST" ]; then
            SERIAL_NEW="$(expr "$SERIAL_LAST" + 1)"
        else
            SERIAL_NEW="${DATE_NEW}00"
        fi

        sed "s/^       <do not edit>; serial$/       $SERIAL_NEW   ; serial/" "$TMP_CONFIG" > "$TMP_ZONE"

        if named-checkzone "$1" "$TMP_ZONE" | tail -1 | grep -q '^OK$'; then
            mv -f "$TMP_ZONE" "$FILE_ZONE"
            rm -f "$TMP_CONFIG"

            rndc reload "$1" &>/dev/null

            return 0
        else
            show_info 'Error' 'Invalid syntax in zone configuration.'
        fi
    fi

    rm -f "$TMP_ZONE" "$TMP_CONFIG"

    return 1
}

# manage local zones in dialog menu
# parameters:
# none
# return values:
# none
resolver_local() {
    declare LIST_LOCAL DIALOG_RET RET_CODE
    declare -a MENU_LOCAL

    while true; do
        [ -f "$CONFIG_RESOLVER_LOCAL" ] && LIST_LOCAL="$(grep -E '^zone "\S+" {' "$CONFIG_RESOLVER_LOCAL" | awk 'match($0, /^zone "([^"]+)" {$/, a) {print a[1]}')"

        MENU_LOCAL=()

        if [ -z "$LIST_LOCAL" ]; then
            MENU_LOCAL+=('' 'No local zones')

            "$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --ok-label 'Add' --no-tags --menu 'Choose local zone to edit' 0 0 0 "${MENU_LOCAL[@]}"

            if [ "$?" = 0 ]; then
                add_local
            else
                break
            fi
        else
            for ZONE_LOCAL in $LIST_LOCAL; do
                MENU_LOCAL+=("$ZONE_LOCAL" "$ZONE_LOCAL")
            done

            exec 3>&1
            DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --ok-label 'Edit' --no-tags --extra-button --extra-label 'Add' --menu 'Choose local zone to edit' 0 0 0 "${MENU_LOCAL[@]}" 2>&1 1>&3)"
            RET_CODE="$?"
            exec 3>&-

            if [ "$RET_CODE" = 0 ] && ! [ -z "$DIALOG_RET" ]; then
                edit_zone "$DIALOG_RET" && bind_reload
            elif [ "$RET_CODE" = 3 ]; then
                add_local
            else
                break
            fi
        fi
    done
}

# sync local DNS resolver config
# parameters:
# none
# return values:
# none
resolver_sync() {
    show_wait
    rsync -avzh -e ssh "$CONFIG_RESOLVER" mx:"$CONFIG_RESOLVER" &>/dev/null
    ssh mx systemctl reload "$SERVICE_BIND" &>/dev/null
}

# edit OpenDKIM config
# parameters:
# none
# return values:
# none
dkim_config() {
    edit_config "$CONFIG_DKIM" && systemctl reload opendkim &>/dev/null
}

# sync OpenDKIM config
# parameters:
# none
# return values:
# none
dkim_sync() {
    show_wait
    rsync -avzh -e ssh "$CONFIG_DKIM" mx:"$CONFIG_DKIM" &>/dev/null
    ssh mx systemctl reload opendkim &>/dev/null
}

# edit SPF-check config
# parameters:
# none
# return values:
# none
spf_config() {
    edit_config "$CONFIG_SPF"
}

# sync SPF-check config
# parameters:
# none
# return values:
# none
spf_sync() {
    show_wait
    rsync -avzh -e ssh "$CONFIG_SPF" mx:"$CONFIG_SPF" &>/dev/null
}

# check Rspamd black-/whitelists status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 for disabled
bwlist_status() {
    if [ -f "$CONFIG_RSPAMD_MULTIMAP" ]                                                                                                                                                                                                                                                                                     \
        && [ "$(sed -n '/^WHITELIST_SENDER_IP {$/,/^}$/p' "$CONFIG_RSPAMD_MULTIMAP")" = 'WHITELIST_SENDER_IP {'$'\n\t''type = "ip";'$'\n\t''prefilter = "true";'$'\n\t'"map = \"$CONFIG_RSPAMD_WHITELIST_IP\";"$'\n\t''description = "Whitelisted sender IP";'$'\n\t''action = "accept";'$'\n''}' ]                         \
        && [ "$(sed -n '/^WHITELIST_SENDER_DOMAIN {$/,/^}$/p' "$CONFIG_RSPAMD_MULTIMAP")" = 'WHITELIST_SENDER_DOMAIN {'$'\n\t''type = "from";'$'\n\t''filter = "email:domain";'$'\n\t'"map = \"$CONFIG_RSPAMD_WHITELIST_DOMAIN\";"$'\n\t''description = "Whitelisted sender domain";'$'\n\t''score = -10.0;'$'\n''}' ]     \
        && [ "$(sed -n '/^WHITELIST_SENDER_FROM {$/,/^}$/p' "$CONFIG_RSPAMD_MULTIMAP")" = 'WHITELIST_SENDER_FROM {'$'\n\t''type = "from";'$'\n\t''filter = "email:addr";'$'\n\t'"map = \"$CONFIG_RSPAMD_WHITELIST_FROM\";"$'\n\t''description = "Whitelisted sender from";'$'\n\t''score = -10.0;'$'\n''}' ]               \
        && [ "$(sed -n '/^WHITELIST_RECIPIENT_TO {$/,/^}$/p' "$CONFIG_RSPAMD_MULTIMAP")" = 'WHITELIST_RECIPIENT_TO {'$'\n\t''type = "rcpt";'$'\n\t''filter = "email:addr";'$'\n\t'"map = \"$CONFIG_RSPAMD_WHITELIST_TO\";"$'\n\t''description = "Whitelisted recipient to";'$'\n\t''score = -10.0;'$'\n''}' ]              \
        && [ "$(sed -n '/^BLACKLIST_COUNTRY {$/,/^}$/p' "$CONFIG_RSPAMD_MULTIMAP")" = 'BLACKLIST_COUNTRY {'$'\n\t''type = "country";'$'\n\t'"map = \"$CONFIG_RSPAMD_BLACKLIST_COUNTRY\";"$'\n\t''description = "Blacklisted sender country";'$'\n\t''score = 10.0;'$'\n''}' ]; then
        return 0
    else
        return 1
    fi
}

# enable Rspamd black-/whitelists
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 for disabled
bwlist_enable() {
    if ! [ -f "$CONFIG_RSPAMD_MULTIMAP" ] || [ "$(sed -n '/^WHITELIST_SENDER_IP {$/,/^}$/p' "$CONFIG_RSPAMD_MULTIMAP")" != 'WHITELIST_SENDER_IP {'$'\n\t''type = "ip";'$'\n\t''prefilter = "true";'$'\n\t'"map = \"$CONFIG_RSPAMD_WHITELIST_IP\";"$'\n\t''description = "Whitelisted sender IP";'$'\n\t''action = "accept";'$'\n''}' ]; then
        echo $'\n''WHITELIST_SENDER_IP {'$'\n\t''type = "ip";'$'\n\t''prefilter = "true";'$'\n\t'"map = \"$CONFIG_RSPAMD_WHITELIST_IP\";"$'\n\t''description = "Whitelisted sender IP";'$'\n\t''action = "accept";'$'\n''}' >> "$CONFIG_RSPAMD_MULTIMAP"
    fi
    if [ "$(sed -n '/^WHITELIST_SENDER_DOMAIN {$/,/^}$/p' "$CONFIG_RSPAMD_MULTIMAP")" != 'WHITELIST_SENDER_DOMAIN {'$'\n\t''type = "from";'$'\n\t''filter = "email:domain";'$'\n\t'"map = \"$CONFIG_RSPAMD_WHITELIST_DOMAIN\";"$'\n\t''description = "Whitelisted sender domain";'$'\n\t''score = -10.0;'$'\n''}' ]; then
        echo $'\n''WHITELIST_SENDER_DOMAIN {'$'\n\t''type = "from";'$'\n\t''filter = "email:domain";'$'\n\t'"map = \"$CONFIG_RSPAMD_WHITELIST_DOMAIN\";"$'\n\t''description = "Whitelisted sender domain";'$'\n\t''score = -10.0;'$'\n''}' >> "$CONFIG_RSPAMD_MULTIMAP"
    fi
    if [ "$(sed -n '/^WHITELIST_SENDER_FROM {$/,/^}$/p' "$CONFIG_RSPAMD_MULTIMAP")" != 'WHITELIST_SENDER_FROM {'$'\n\t''type = "from";'$'\n\t''filter = "email:addr";'$'\n\t'"map = \"$CONFIG_RSPAMD_WHITELIST_FROM\";"$'\n\t''description = "Whitelisted sender from";'$'\n\t''score = -10.0;'$'\n''}' ]; then
        echo $'\n''WHITELIST_SENDER_FROM {'$'\n\t''type = "from";'$'\n\t''filter = "email:addr";'$'\n\t'"map = \"$CONFIG_RSPAMD_WHITELIST_FROM\";"$'\n\t''description = "Whitelisted sender from";'$'\n\t''score = -10.0;'$'\n''}' >> "$CONFIG_RSPAMD_MULTIMAP"
    fi
    if [ "$(sed -n '/^WHITELIST_RECIPIENT_TO {$/,/^}$/p' "$CONFIG_RSPAMD_MULTIMAP")" != 'WHITELIST_RECIPIENT_TO {'$'\n\t''type = "rcpt";'$'\n\t''filter = "email:addr";'$'\n\t'"map = \"$CONFIG_RSPAMD_WHITELIST_TO\";"$'\n\t''description = "Whitelisted recipient to";'$'\n\t''score = -10.0;'$'\n''}' ]; then
        echo $'\n''WHITELIST_RECIPIENT_TO {'$'\n\t''type = "rcpt";'$'\n\t''filter = "email:addr";'$'\n\t'"map = \"$CONFIG_RSPAMD_WHITELIST_TO\";"$'\n\t''description = "Whitelisted recipient to";'$'\n\t''score = -10.0;'$'\n''}' >> "$CONFIG_RSPAMD_MULTIMAP"
    fi
    if [ "$(sed -n '/^BLACKLIST_COUNTRY {$/,/^}$/p' "$CONFIG_RSPAMD_MULTIMAP")" != 'BLACKLIST_COUNTRY {'$'\n\t''type = "country";'$'\n\t'"map = \"$CONFIG_RSPAMD_BLACKLIST_COUNTRY\";"$'\n\t''description = "Blacklisted sender country";'$'\n\t''score = 10.0;'$'\n''}' ]; then
        echo $'\n''BLACKLIST_COUNTRY {'$'\n\t''type = "country";'$'\n\t'"map = \"$CONFIG_RSPAMD_BLACKLIST_COUNTRY\";"$'\n\t''description = "Blacklisted sender country";'$'\n\t''score = 10.0;'$'\n''}' >> "$CONFIG_RSPAMD_MULTIMAP"
    fi
}

# disable Rspamd black-/whitelists
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 for disabled
bwlist_disable() {
    sed -i '/^WHITELIST_SENDER_IP {$/,/^}$/d' "$CONFIG_RSPAMD_MULTIMAP"
    sed -i '/^WHITELIST_SENDER_DOMAIN {$/,/^}$/d' "$CONFIG_RSPAMD_MULTIMAP"
    sed -i '/^WHITELIST_SENDER_FROM {$/,/^}$/d' "$CONFIG_RSPAMD_MULTIMAP"
    sed -i '/^WHITELIST_RECIPIENT_TO {$/,/^}$/d' "$CONFIG_RSPAMD_MULTIMAP"
    sed -i '/^BLACKLIST_COUNTRY {$/,/^}$/d' "$CONFIG_RSPAMD_MULTIMAP"
}

# check Spamassassin integration status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 for disabled
spamd_status() {
    if [ -f "$CONFIG_RSPAMD_EXTERNAL" ] && ! [ -z "$(sed -n '/^spamassassin {$/,/^}$/p' "$CONFIG_RSPAMD_EXTERNAL")" ]; then
        return 0
    else
        return 1
    fi
}

# enable Spamassassin integration
# parameters:
# none
# return values:
# error code - 0 for changes made, 1 for no changes made
spamd_enable() {
    if ! [ -f "$CONFIG_RSPAMD_EXTERNAL" ] || [ -z "$(sed -n '/^spamassassin {$/,/^}$/p' "$CONFIG_RSPAMD_EXTERNAL")" ]; then
        echo "$CONFIG_SPAMD" >> "$CONFIG_RSPAMD_EXTERNAL"
    fi
}

# disable Spamassassin integration
# parameters:
# none
# return values:
# none
spamd_disable() {
    sed -i '/^spamassassin {$/,/^}$/d' "$CONFIG_RSPAMD_EXTERNAL"
}

# check Spamassassin rules status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 for disabled
sarules_status() {
    [ -f "$FILE_RULES" ] && return 0 || return 1
}

# enable Spamassassin rules
# parameters:
# none
# return values:
# error code - 0 for changes made, 1 for no changes made
sarules_enable() {
    declare -r DIR_RULES='/tmp/TMPrules'
    declare -r VERSION_RULES="$(dig txt 2.4.3.spamassassin.heinlein-support.de +short | tr -d '"')"
    declare FILE_DOWNLOAD 

    if [ -z "$VERSION_RULES" ]; then
        return 1
    else
        FILE_DOWNLOAD="$DIR_RULES/$VERSION_RULES.tgz"
        rm -rf "$DIR_RULES" &>/dev/null
        mkdir -p "$DIR_RULES"
        "$WGET" "http://www.spamassassin.heinlein-support.de/$VERSION_RULES.tar.gz" -O "$FILE_DOWNLOAD" &>/dev/null

        if ! [ -f "$FILE_DOWNLOAD" ]; then
            return 1
        else
            tar -C "$DIR_RULES" -xzf "$FILE_DOWNLOAD"
            cat "$DIR_RULES"/*.cf > "$FILE_RULES"
            rm -rf "$DIR_RULES" &>/dev/null
        fi
    fi

    return 0
}

# disable Spamassassin rules
# parameters:
# none
# return values:
# none
sarules_disable() {
    rm -f "$FILE_RULES"
}

# check Spamassassin rules update status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 for disabled
rulesupdate_status() {
    [ -f "$CRON_RULES" ] && return 0 || return 1
}

# enable Spamassassin rules update
# parameters:
# none
# return values:
# error code - 0 for changes made, 1 for no changes made
rulesupdate_enable() {
    declare -r PACKED_SCRIPT='
    H4sIAOxMtFwAA41UbXOiSBD+zq/oNdmYnCcgvu/VphYRFUVN8N2rqxTC8BJhGGEQtfbHH2IuFytb
    dUcxBTM9/fTTz/T0zRdu42Juo0cOw9xATEydopcw9lDERg7MS6zA8sxNapICcgxd26FwbzyAwJea
    MEJUCjDMMEUhRo6PcLRBoU5jbEPX3/R+B4yoEeBiOqLYoy62WSPwMzgxpk4QfoOhHhrQdlG4jRCG
    e5813/5//NL3gWHaivaizVR58j3PUZ9w0+FTxjfPdBRVfjel3lwYEd03OS8wdI81ufNMj6L0dTH7
    5sPMZW2ijEdvfrnbe9O1gR4oCGyFLbNXPg5ysZeOYhQTEoSUNREUojQPCj+BhlA0IZ/LP+QYxrXg
    TyieIHd7hZ+Dv/4A6iDMQPogwwkgL+kYBxRMlKrouxjBRISMHOxRGLkBzl82H1wKJcZymUue7fFi
    pI7Fdkr5XRHuOhpL7dOFy5czGytlc+V6zcbfmm6aAoEPgLnMEvpn5w9hfsuWjTj0oFiMXA9hCjmH
    UvKN45Ik+U/RPvHUQzalmoIFMSUx/USUyQL+z0Q+Sxsk2At0813Z/L/7zqoK2fSs7PmbkoGidKUC
    FA+nz0Gz3R/p/HPEcHcHBvls+Dh7SQstvWpQ+Np5uCAZOr3SmDUseLxGuBB8EqWB3H6ZSJryNP1+
    yaVXiRRR7AtRJxHF8mLCL3btYWvSrZeFwfOgy3caVbO+UJJFv/SqToluSvymI021oKILs+VgEmnL
    NV84jJr+QM0A1ecTbQ5b/YRYDQUZXHdVVlru9EhEiWirynYXv7YGgeQr8tZoNeLeQpP2nMw3mo1+
    pbqrvWpNVd4dStJ8RrwM8FR1ukrPtA6D3qhGK2ve1tXaeLbtW+3WDHXoSl7X1bl4mkoaHkpTnhvO
    T1rTFseFQTWQiRp13LWF13Kd9usZoFIrJdQ/uOiptOWJsGlJs+pQOgRkR6INT5YWOjbXs7h53OvP
    SUl+nRvW2HELRFB6wXBkDruLncYtk+XTqNHKAOflmfLsCcbY49YaHVKj7pREedlfnpZbiz/VhJOC
    muU9SvjCYrlvd6nuz5Nwu7YTLihMjiuv11+txqpfo2EtA2zpHrLr1UC0RTFbuJwVCV1M09r4GuXg
    9uow0y6SdmJUq5w7yU+wY3xyCTz+sgoiFO5dA8Glx0GIorRwKdw9cibaczj2vHOv+BukmnrV4AUA
    AA==
    '

    printf '%s' $PACKED_SCRIPT | base64 -d | gunzip > "$CRON_RULES"
    chmod 700 "$CRON_RULES"
    "$CRON_RULES"
}

# disable Spamassassin rules update
# parameters:
# none
# return values:
# none
rulesupdate_disable() {
    rm -f "$CRON_RULES"
}

# check Pyzor status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 for disabled
pyzor_status() {
    if [ -f "$CONFIG_RSPAMD_LOCAL" ]                                                                                                                                                                                                                                                                                        \
        && grep -q '^pyzor { }$' "$CONFIG_RSPAMD_LOCAL"                                                                                                                                                                                                                                                                     \
        && [ -f "$CONFIG_RSPAMD_GROUPS" ]                                                                                                                                                                                                                                                                                   \
        && [ "$(sed -n '/^group "signatures" {$/,/^}$/p' "$CONFIG_RSPAMD_GROUPS")" = 'group "signatures" {'$'\n\t''.include(try=true; priority=1; duplicate=merge) "$LOCAL_CONFDIR/local.d/signatures_group.conf"'$'\n\t''.include(try=true; priority=10) "$LOCAL_CONFDIR/override.d/signatures_group.conf"'$'\n''}' ]      \
        && [ -f "$CONFIG_RSPAMD_SIGNATURES" ]                                                                                                                                                                                                                                                                               \
        && [ "$(sed 'H;/^symbols = {$/h;/^}$/!d;x;/\n\t"PYZOR" {/!d' "$CONFIG_RSPAMD_SIGNATURES")" = 'symbols = {'$'\n\t''"PYZOR" {'$'\n\t\t''weight = 2.5;'$'\n\t\t''description = "check message signatures against the Pyzor collaborative filtering network";'$'\n\t''}'$'\n''}' ]                                      \
        && [ -f "$PYZOR_PLUGIN" ]                                                                                                                                                                                                                                                                                           \
        && [ -f "$PYZOR_SCRIPT" ]                                                                                                                                                                                                                                                                                           \
        && [ -f "$PYZOR_SERVICE" ]; then
        return 0
    else
        return 1
    fi
}

# enable Pyzor
# parameters:
# none
# return values:
# error code - 0 for changes made, 1 for no changes made
pyzor_enable() {
    declare PACKED_SCRIPT

    if ! [ -f "$CONFIG_RSPAMD_LOCAL" ] || ! grep -q '^pyzor { }$' "$CONFIG_RSPAMD_LOCAL"; then
        echo 'pyzor { }' >> "$CONFIG_RSPAMD_LOCAL"
    fi
    if ! [ -f "$CONFIG_RSPAMD_GROUPS" ] || [ "$(sed -n '/^group "signatures" {$/,/^}$/p' "$CONFIG_RSPAMD_GROUPS")" != 'group "signatures" {'$'\n\t''.include(try=true; priority=1; duplicate=merge) "$LOCAL_CONFDIR/local.d/signatures_group.conf"'$'\n\t''.include(try=true; priority=10) "$LOCAL_CONFDIR/override.d/signatures_group.conf"'$'\n''}' ]; then
        echo $'\n''group "signatures" {'$'\n\t''.include(try=true; priority=1; duplicate=merge) "$LOCAL_CONFDIR/local.d/signatures_group.conf"'$'\n\t''.include(try=true; priority=10) "$LOCAL_CONFDIR/override.d/signatures_group.conf"'$'\n''}' >> "$CONFIG_RSPAMD_GROUPS"
    fi
    if ! [ -f "$CONFIG_RSPAMD_SIGNATURES" ] || [ "$(sed 'H;/^symbols = {$/h;/^}$/!d;x;/\n\t"PYZOR" {/!d' "$CONFIG_RSPAMD_SIGNATURES")" != 'symbols = {'$'\n\t''"PYZOR" {'$'\n\t\t''weight = 2.5;'$'\n\t\t''description = "check message signatures against the Pyzor collaborative filtering network";'$'\n\t''}'$'\n''}' ]; then
        echo $'\n''symbols = {'$'\n\t''"PYZOR" {'$'\n\t\t''weight = 2.5;'$'\n\t\t''description = "check message signatures against the Pyzor collaborative filtering network";'$'\n\t''}'$'\n''}' >> "$CONFIG_RSPAMD_SIGNATURES"
    fi

    PACKED_SCRIPT='
    H4sIAANBq1wAA5VVbW/TMBD+TH6FFWlqKnVRWiiISt2XDQkJ2CaEQLypcpJrGpbaxXZUyrT/zp2d
    95UKug+L7+55fL7XQia8YGVSsCVT8LPMFTAfj75XWE0hswxUV6n0jm/TlVPUZibZHbFBqe9VFteo
    93eH37LB6MM2lsXKykh5+/nLzftaKXdGE6MjSqRY59kiA7PiRbFCZXA99rzzc3YFa14WhmkwJheZ
    ruDJOlttpDbEO529CCP8m/od5U4qUs5fzp8Sz71/+9FfMH+GVhPmX8oU7DGK6Pjp7fmlLIUhUeT0
    1Wn+lI4fNgp46s7Pps9JdJXzjAQ3b/yHOgTrUiQml4IlG0ju3MMDw/Xd2GP4GxrFASg1YSk33BnQ
    L18zlDKzAdHIHJjSEaLul6VEFygbgCFAmVQLdqbRL/we93AKTKlaKhCpN6BMIS6zbXA9YY53RA4R
    3QglGGKFYQ+sk5iRFktv2XGlbfFgQYXuEIwHNvLOeoVGzmBh/60q3uEFnTAIaRD8T5GwEbD8SIVP
    1jspNPxHSAY+E0PrMFWljH9AYh49br/JDRS5NpCivZGi3MYYA8J/bavq+xCmgMrzGKYBDLOUi7Vs
    3puQ1fJMs32xtG+sCSddjzok2Ejv+B20Ws0sB+OsyI0pgMW5Cfvmhxgo+ApGGs1i7D9M9Z4f0GWs
    lD5ZLlDIE8s56dLEJd5hWAEcC9VscjTVTMst4LfI2hs7EWk+z7uPGaZoD3m2oQ6PvG7RNOCLJZtG
    0ePqaXDTcN6WQKFhAJ7NT2JnJ8GnsdEp6JRxkfbrCt94gi8KZ8dLGYkro4tjBFRKixzbRJkV1h7O
    2KA7sCcVeMJcg4ZrqbbcBHXtpbb20r/W3vjRyGmcq3vATa8lu29M/cvXry7ffBN+W0PWTepAXBEG
    BLag0z3UXEdnmI/c6kDDwG2kqhVwX4XVvcF97wrqREI2wmq51HumVVSLpd4xrUJvSpPKvSAqVUKr
    oNFWLU/oMmEUipgndHcSu0eNPRslTJ3dj03SKkFoveqlsrMIG4sm3F2o9fsRtHpNY9HPVH87K8go
    t2rl6qQTQcG3gCy9+jn6zHYvTrwn5rAj1Kg2GKEsU7Kk0TvSeSY4zmnQoyY02C3dpLuR6OMY3Mq0
    xBlGG8P5ijgqzWsXzz/X6mWbBAkAAA==
    '
    printf '%s' $PACKED_SCRIPT | base64 -d | gunzip > "$PYZOR_PLUGIN"

    groupadd "$PYZOR_USER"
    useradd -g "$PYZOR_USER" "$PYZOR_USER"
    mkdir -p "$PYZOR_DIR/bin/"

    PACKED_SCRIPT='
    H4sIAGtBq1wAA3VUTY/TMBC951eYcHFEcYW4VeoBuistQitVtDdAloknrVvHDnba3YL474w/mmZL
    8SX2eN6b8byZvH41PXg3/aHMtDv1W2veF6rtrOuJcJtOOA/nM7RCaRZN7spmtapPZ5v1593OW1M0
    zrbE23oPPQKP4Ei+XS+Wq2iYkPXWgZDKbB7V8yczIasez+0X+HkA3z8IIzWGPLN2p1/WsVorMP1L
    m1Qb9C+KotbCe/IST2+RVrOiILgkNGQbTdSDbtBM8qpbSeYkGJlrlAYWMtXKAK2YhNpK3HydvX33
    fUCoJoHmpFw83C8+lxeysCJVisXrLdR7Wg33oD3c8H5yqgceqkl/l+CcdeWMlAezN/bJkNq2LdKV
    f6rrt2T+qxclBfFRY0HZx1MPfhn3NOk5H4vLVo/r5SXR1m+QIEPjh15KlPOIuURFgutIIHYnenEX
    txgMqSp2FPoAl5qHtAdQUpot4gernh6VqEah/qnUfkaOpLGO7Ce4USbRMnRoPa3G1RqhAsuEyFG5
    dphIuGLy0Haeyoq8IeU3U14Fjr0RieiOgUmNUQ29mDqdXjf6MAM5YIe+iAlJYfENzeYwipjGeSLZ
    B7c5tFiNrJcEXzvV9cqaeXn/3FkPqXbEGiLy8JXVQMWElFxkDlriyZUTsgXdzeMBMOHeEq1QIIMc
    /4eG4RugcRJv43zOPvVKIEAJkgAhIN7SYAvs+DtQSB2PgbHKft4d0S3XMfldzXJ0693poh1iWPzp
    cOwDCMDk1CgjtL7l6HitsXwhuQIHmXMjWuA8TjPnQRPO80AngYq/7vjOR0EFAAA=
    '
    printf '%s' $PACKED_SCRIPT | base64 -d | gunzip > "$PYZOR_SCRIPT"
    chown "$PYZOR_USER:$PYZOR_USER" "$PYZOR_SCRIPT"
    chmod 0700 "$PYZOR_SCRIPT"

    PACKED_SCRIPT='
    H4sIAJqvOl4AA5VTYW/TMBD97l9xJNFGkbI0m7JBpwoBy6aK0k5phwQIIdd1G6upHWwH6Nb9dxy3
    DUk7PsyWIt27d+/unRX3RTBhPJhglSIXuZCv7oVUgiyotjFJF0TwGZt3wIfXEYSRAadUEclyzQTv
    NCsgl4JQpThe0mYKua4L7+Ob3gB6g97YfK6Hhn9FZ7jItD/SWOoOlOcMokZC5Bsc2hDCKZxbpXhw
    VdNBSTz+/K7fbaPbZHjTPa41Pkb94YeP171+3HWCX1gGmYEDVUzUSgVeSXfQ7Zevw2RkaPH4x90o
    TvYEkCqHe9mCBwTbQ0kqwOfg2LkZn4OV6oBTUaaYLgVn9xT8wmT3WkAgch3U2thnqMUn+QrC04uT
    trkhRG+is0p5a9Z7WyHfwNuA4NOfZk/f4egItChICt7OfmP2KpBUF5LvytFjaVbk//GaFtp6nYrf
    /NDwgmUZzjLwx3Hy6UnTz3Ugl+DPnu+AYEXB8UIHGLc0+36tqsKGVXR5ueWIvE4R+SED60K19mFJ
    D+RrtU/2etVqLte5U3hu/he7UniwNetSZr3pud72ePy3bPqHaQjrwlRhgiy8W8VfBJ0WIdwDAAA=
    '
    printf '%s' $PACKED_SCRIPT | base64 -d | gunzip > "$PYZOR_SERVICE"
    chmod +x "$PYZOR_SERVICE"

    check_installed_daemonize || "$INSTALLER" install -y daemonize &>/dev/null

    systemctl daemon-reload
    systemctl start pyzorsocket
    enable_service pyzorsocket
}

# disable Pyzor
# parameters:
# none
# return values:
# none
pyzor_disable() {
    sed -i '/^pyzor { }$/d' "$CONFIG_RSPAMD_LOCAL"
    sed -i 'H;/^symbols = {$/h;/^}$/!d;x;/\n\t"PYZOR" {/d' "$CONFIG_RSPAMD_SIGNATURES"
    [ "$(rspamd_feature_status 'razor')" = 'off' ] && sed -i '/^group "signatures" {$/,/^}$/d' "$CONFIG_RSPAMD_GROUPS"

    disable_service pyzorsocket
    systemctl stop pyzorsocket

    rm -rf "$PYZOR_PLUGIN" "$PYZOR_DIR" "$PYZOR_SERVICE"
    userdel -r "$PYZOR_USER" &>/dev/null
    groupdel "$PYZOR_USER" &>/dev/null

    systemctl daemon-reload
}

# check Razor status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 for disabled
razor_status() {
    if [ -f "$CONFIG_RSPAMD_LOCAL" ]                                                                                                                                                                                                                                                                                        \
        && grep -q '^razor { }$' "$CONFIG_RSPAMD_LOCAL"                                                                                                                                                                                                                                                                     \
        &&  [ -f "$CONFIG_RSPAMD_GROUPS" ]                                                                                                                                                                                                                                                                                  \
        && [ "$(sed -n '/^group "signatures" {$/,/^}$/p' "$CONFIG_RSPAMD_GROUPS")" = 'group "signatures" {'$'\n\t''.include(try=true; priority=1; duplicate=merge) "$LOCAL_CONFDIR/local.d/signatures_group.conf"'$'\n\t''.include(try=true; priority=10) "$LOCAL_CONFDIR/override.d/signatures_group.conf"'$'\n''}' ]      \
        && [ -f "$CONFIG_RSPAMD_SIGNATURES" ]                                                                                                                                                                                                                                                                               \
        && [ "$(sed 'H;/^symbols = {$/h;/^}$/!d;x;/\n\t"RAZOR" {/!d' "$CONFIG_RSPAMD_SIGNATURES")" = 'symbols = {'$'\n\t''"RAZOR" {'$'\n\t\t''weight = 2.5;'$'\n\t\t''description = "check message signatures against the Razor collaborative filtering network";'$'\n\t''}'$'\n''}' ]                                      \
        && [ -f "$RAZOR_PLUGIN" ]                                                                                                                                                                                                                                                                                           \
        && [ -f "$RAZOR_SCRIPT" ]                                                                                                                                                                                                                                                                                           \
        && [ -f "$RAZOR_SERVICE" ]; then
        return 0
    else
        return 1
    fi
}

# enable Razor
# parameters:
# none
# return values:
# error code - 0 for changes made, 1 for no changes made
razor_enable() {
    declare PACKED_SCRIPT

    if ! [ -f "$CONFIG_RSPAMD_LOCAL" ] || ! grep -q '^razor { }$' "$CONFIG_RSPAMD_LOCAL"; then
        echo 'razor { }' >> "$CONFIG_RSPAMD_LOCAL"
    fi
    if ! [ -f "$CONFIG_RSPAMD_GROUPS" ] || [ "$(sed -n '/^group "signatures" {$/,/^}$/p' "$CONFIG_RSPAMD_GROUPS")" != 'group "signatures" {'$'\n\t''.include(try=true; priority=1; duplicate=merge) "$LOCAL_CONFDIR/local.d/signatures_group.conf"'$'\n\t''.include(try=true; priority=10) "$LOCAL_CONFDIR/override.d/signatures_group.conf"'$'\n''}' ]; then
        echo $'\n''group "signatures" {'$'\n\t''.include(try=true; priority=1; duplicate=merge) "$LOCAL_CONFDIR/local.d/signatures_group.conf"'$'\n\t''.include(try=true; priority=10) "$LOCAL_CONFDIR/override.d/signatures_group.conf"'$'\n''}' >> "$CONFIG_RSPAMD_GROUPS"
    fi
    if ! [ -f "$CONFIG_RSPAMD_SIGNATURES" ] || [ "$(sed 'H;/^symbols = {$/h;/^}$/!d;x;/\n\t"RAZOR" {/!d' "$CONFIG_RSPAMD_SIGNATURES")" != 'symbols = {'$'\n\t''"RAZOR" {'$'\n\t\t''weight = 2.5;'$'\n\t\t''description = "check message signatures against the Razor collaborative filtering network";'$'\n\t''}'$'\n''}' ]; then
        echo $'\n''symbols = {'$'\n\t''"RAZOR" {'$'\n\t\t''weight = 2.5;'$'\n\t\t''description = "check message signatures against the Razor collaborative filtering network";'$'\n\t''}'$'\n''}' >> "$CONFIG_RSPAMD_SIGNATURES"
    fi

    PACKED_SCRIPT='
    H4sIAAdCq1wAA4VUTWvbQBA9R79iEQRLoJg4lxJDDiUtFAou5FgKYiWNPvBq191d0bih/70zu6uv
    2KXywWLmzZuZNzMSquSCCdU0oNkT0/Bz6DSwWJsT76vcO+JIOJgtT1cwaI2jgDigP9b8t5pizLkv
    lMidjZwvH79/exmd6mQNMXqiUsm6a/YN2JwLkaMzOaRRdHfHPkHNB2GZAWs72ZgQXtZN3ipjiXf3
    8GF7j79dvHCelCbn4+7xYaywHmRpOyVZ2UJ59HUllptjGjF83oOKBLTOWMUt9wB6upqhldkW5GTz
    waTWFn2vjjJDLVAswArRpvSe3Zo4o/d0FafBDnqmAllFMyXVo8GQ8hZ71dh/clGOB6AMpGR8WRlV
    s++kAW1zxKKWyXIwGdtt79NrvVRQDE2fHDIWGnIJZigIA8v87dX0/yJrL7j+p+cgj1L9ki6hwn5Y
    rVXPXBNGlUewQWPypxeK0v9izONwntjbBI2fv3x+/vpDxtlkcuLRVuKCWpA2Sb3vz8h1vTnk1mec
    lq8O+3RovJZtyJu8rVLQgClyMobVHrd8doS1Hjd8dph2sBXJg1R6gCy6oU0JNwtLCmxfFLykpGUR
    2kkjpw+O093lNMVg2Lp6VrNdHOCEmIRehrqKL0JDHxNiPaP1V0FD0xkLOvd7u9BO8h6QZbXP0Y09
    n8i6GRvdoK3RaqA72piukRxvDszmuiTzt2HWZtzOMO9O1uo1iW8N61U1CGBSWeaLReIKd/DgBf0L
    bFL70WMFAAA=
    '
    printf '%s' $PACKED_SCRIPT | base64 -d | gunzip > "$RAZOR_PLUGIN"

    groupadd "$RAZOR_USER"
    useradd -g "$RAZOR_USER" "$RAZOR_USER"
    mkdir -p "$RAZOR_DIR/bin/"

    PACKED_SCRIPT='
    H4sIAAtN/F4AA31UTW/cIBC9+1dQesHqxtuqlyqSD22UKlWVKmr2lkYWMeM1iQEXcJJtlf/eAWzv
    hzblYs8w83jMG+btm+Xg7PJO6iXoR9JvfGv0xyyTqjfWE27XPbcOJhsUl10RXfbAZzpZbyafcdPf
    vTN6+nfDXW9NDc5ljTWKOFM/gEeoR7BkjFmdXV1Hx4KsWgtcSL2+lM/f9IJce7TVT/g9gPMXXIsO
    SUQgD6pvZAcTyA+uQKwgGNxuvuJOltUdd47sZ7NjkPlpRnAJaEgbPcxB14zesGolSEmCs7Dh1CLQ
    7KQGlhcCaiPw5+b05MNtNqfIJmWVhJ5dnJ99p1u0sCJWOqyqW6gfWD7vQ+fgSPSTlR6qUF32l4K1
    xtJTQgf9oM2TJrVRCuHoS54dXGbEP7hSUhRvtStw8WXjwV3Ff5b0LXfFLq4vV1dbosqtEWBMjR+2
    rVG+rcWT9O0RhZiQtqRLr3qaE+5Is3/p8cYMTym4q+4CNZbvwIZlwQ2dD+LMnVbUvOvYDZ3b3PI/
    xp7EKtAFwmpkcpvvSTXBlOT9HolU+Ch5IpNYUNdzhVh08M3JJ5r/R7vXENoDgFm0HZlD7oKIHdXu
    8aZhqxCD6h0TOXlH6C9Ns1ePuy9ApwbNpxeRXhs7fGzzOxzP6zE2ywIl7ADNRm+YD0hiGhPFZ7se
    FGg/No0AV1vZe2l0Sc+fe+OAxPoTowkf3z/NZ6iCC1HxEYNRtCyWpYWuL6OBehJvSCedB40Yr6eG
    MTCnxplwPM+N7FPDBgDsqlT+cCDusuAL6DiRJEJHMyBOMjn7iGFjGVPcwUBJcd5uttJhUhEHX9UY
    CyEzUWqkxn49FmirusP6BXbYolUV+raq4kipqqBJVY1TJQmU/QNDrD+S2wUAAA==
    '
    printf '%s' $PACKED_SCRIPT | base64 -d | gunzip > "$RAZOR_SCRIPT"
    chown "$RAZOR_USER:$RAZOR_USER" "$RAZOR_SCRIPT"
    chmod 0700 "$RAZOR_SCRIPT"

    PACKED_SCRIPT='
    H4sIANWvOl4AA5VT72/aMBD97r/ilkTtmJSGMNEVEJq6Na1QGVQB+qHTNBljiEWwU9vZWqD/+xIX
    svCjH2pLke7u3Xv3zor9wRsz7o2xipCNbJB4KaQSZE61iSdUEckSzQRv7hYhkYJQpThe0P0SieZE
    8CmbNcGFizr4dYRs24ZvwU2nB51eZ5h9rvsZ8opOcRprd6Cx1E3Iz2eo7xRE8pqHKvhQg3PDFPSu
    SjwoDIb3l912Fd2F/Zv2aWmaU9Ttf7+97nSDtuX9wdKLs7Sn0rF6Vp6Twy0UXj70w0EGC4a/R4Mg
    3CNAKh/uYwVWCDaHkkiAy8EyczM+A0PVBKuATDBdCM6WFNwUnH0J8ESivZKMeYZSfJY8g1/7clbN
    rg8Nv1ErmDdmna9F5mcmYJLg0sdsT7/g5AS0SEkEztb+zuxFIKlOJd+2o5fcrEje8Bql2nidiL/8
    0PCcxTGOY3CHQfjjuOn3WpALcKfvt0CwomA5vgWMG5h5wErRYcIiarU2GJGUISI5RGCdqsp+WtID
    +lLvUa1Pld3tWiOFZ9lfZHYKK9OzzmnWr5rrjcbL/23TJ6bBLxNThQky6e0q/gGLGIAQ3QMAAA==
    '
    printf '%s' $PACKED_SCRIPT | base64 -d | gunzip > "$RAZOR_SERVICE"
    chmod +x "$RAZOR_SERVICE"

    check_installed_daemonize || "$INSTALLER" install -y daemonize &>/dev/null

    systemctl daemon-reload
    systemctl start razorsocket
    enable_service razorsocket
}

# disable Razor
# parameters:
# none
# return values:
# none
razor_disable() {
    sed -i '/^razor { }$/d' "$CONFIG_RSPAMD_LOCAL"
    sed -i 'H;/^symbols = {$/h;/^}$/!d;x;/\n\t"RAZOR" {/d' "$CONFIG_RSPAMD_SIGNATURES"
    [ "$(rspamd_feature_status 'pyzor')" = 'off' ] && sed -i '/^group "signatures" {$/,/^}$/d' "$CONFIG_RSPAMD_GROUPS"

    disable_service razorsocket
    systemctl stop razorsocket

    rm -rf "$RAZOR_PLUGIN" "$RAZOR_DIR" "$RAZOR_SERVICE"
    userdel -r "$RAZOR_USER" &>/dev/null
    groupdel "$RAZOR_USER" &>/dev/null

    systemctl daemon-reload
}

# check Oletools status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 for disabled
oletools_status() {
    if [ -f "$CONFIG_RSPAMD_EXTERNAL" ]                                             \
        && ! [ -z "$(sed -n '/^oletools {$/,/^}$/p' "$CONFIG_RSPAMD_EXTERNAL")" ]   \
        && [ -f "$OLETOOLS_SCRIPT" ]                                                \
        && [ -f "$OLETOOLS_CONFIG" ]                                                \
        && [ -f "$OLETOOLS_SERVICE" ]; then
        return 0
    else
        return 1
    fi
}

# enable Oletools
# parameters:
# none
# return values:
# error code - 0 for changes made, 1 for no changes made
oletools_enable() {
    if ! [ -f "$CONFIG_RSPAMD_EXTERNAL" ] || [ -z "$(sed -n '/^oletools {$/,/^}$/p' "$CONFIG_RSPAMD_EXTERNAL")" ]; then
        echo "$CONFIG_OLETOOLS" >> "$CONFIG_RSPAMD_EXTERNAL"
    fi

    groupadd "$OLETOOLS_USER"
    useradd -g "$OLETOOLS_USER" "$OLETOOLS_USER"

    "$WGET" https://raw.githubusercontent.com/HeinleinSupport/olefy/master/olefy.py -O "$OLETOOLS_SCRIPT" 2>/dev/null
    "$WGET" https://raw.githubusercontent.com/HeinleinSupport/olefy/master/olefy.conf -O - 2>/dev/null | sed -E 's/(OLEFY_BINDADDRESS=127.0.0.1), ::1/\1/g' > "$OLETOOLS_CONFIG"
    "$WGET" https://raw.githubusercontent.com/HeinleinSupport/olefy/master/olefy.service -O "$OLETOOLS_SERVICE" 2>/dev/null

    systemctl daemon-reload
    systemctl enable olefy.service &>/dev/null
    systemctl start olefy.service
}

# disable Oletools
# parameters:
# none
# return values:
# none
oletools_disable() {
    sed -i '/^oletools {$/,/^}$/d' "$CONFIG_RSPAMD_EXTERNAL"

    systemctl stop olefy.service
    systemctl disable olefy.service &>/dev/null

    rm -rf "$OLETOOLS_SCRIPT" "$OLETOOLS_CONFIG" "$OLETOOLS_SERVICE"
    userdel -r "$OLETOOLS_USER" &>/dev/null
    groupdel "$OLETOOLS_USER" &>/dev/null

    systemctl daemon-reload
}

# check ClamAV status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 for disabled
clamav_status() {
    if [ -f "$CONFIG_RSPAMD_ANTIVIRUS" ] && ! [ -z "$(sed -n '/^clamav {$/,/^}$/p' "$CONFIG_RSPAMD_ANTIVIRUS")" ]; then
        return 0
    else
        return 1
    fi
}

# enable ClamAV
# parameters:
# none
# return values:
# error code - 0 for changes made, 1 for no changes made
clamav_enable() {
    if ! [ -f "$CONFIG_RSPAMD_ANTIVIRUS" ] || [ -z "$(sed -n '/^clamav {$/,/^}$/p' "$CONFIG_RSPAMD_ANTIVIRUS")" ]; then
        echo "$CONFIG_CLAMAV" >> "$CONFIG_RSPAMD_ANTIVIRUS"
        touch "$CONFIG_RSPAMD_WHITELIST_ANTIVIRUS_FROM"
    fi
}

# disable ClamAV
# parameters:
# none
# return values:
# none
clamav_disable() {
    sed -i '/^clamav {$/,/^}$/d' "$CONFIG_RSPAMD_ANTIVIRUS"
}

# check Sophos AV status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 for disabled
sophosav_status() {
    if [ -f "$CONFIG_RSPAMD_ANTIVIRUS" ] && ! [ -z "$(sed -n '/^sophos {$/,/^}$/p' "$CONFIG_RSPAMD_ANTIVIRUS")" ]; then
        return 0
    else
        return 1
    fi
}

# enable Sophos AV
# parameters:
# none
# return values:
# error code - 0 for changes made, 1 for no changes made
sophosav_enable() {
    if ! [ -f "$CONFIG_RSPAMD_ANTIVIRUS" ] || [ -z "$(sed -n '/^sophos {$/,/^}$/p' "$CONFIG_RSPAMD_ANTIVIRUS")" ]; then
        echo "$CONFIG_SOPHOSAV" >> "$CONFIG_RSPAMD_ANTIVIRUS"
        touch "$CONFIG_RSPAMD_WHITELIST_ANTIVIRUS_FROM"
    fi
}

# disable Sophos AV
# parameters:
# none
# return values:
# none
sophosav_disable() {
    sed -i '/^sophos {$/,/^}$/d' "$CONFIG_RSPAMD_ANTIVIRUS"
}

# check cluster setup status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 for disabled
cluster_status() {
    if [ -f "$CONFIG_RSPAMD_OPTIONS" ]                                                              \
        && ! [ -z "$(sed -n '/^neighbours {$/,/^}$/p' "$CONFIG_RSPAMD_OPTIONS")" ]                  \
        && grep -q '^dynamic_conf = "/var/lib/rspamd/rspamd_dynamic";$' "$CONFIG_RSPAMD_OPTIONS"    \
        && grep -q '^#bind 127.0.0.1' "$CONFIG_REDIS"                                               \
        && grep -q '^protected-mode no$' "$CONFIG_REDIS"; then
        return 0
    else
        return 1
    fi
}

# enable cluster setup
# parameters:
# none
# return values:
# error code - 0 for changes made, 1 for no changes made
cluster_enable() {
    declare -r IP_ADDRESS="$(hostname -I | tr -d ' ')"
    declare -r IP_PEER="$(sed -n '/^Host mx$/,/^$/p' ~/.ssh/config | awk 'match($0, /^\tHostName (\S+)$/, a) {print a[1]}')"
    declare -r LIST_IP="$(echo "$IP_ADDRESS"$'\n'"$IP_PEER" | sort | xargs)"
    declare -r IP_MASTER="$(echo "$LIST_IP" | awk '{print $1}')"
    declare -r IP_SLAVE="$(echo "$LIST_IP" | awk '{print $2}')"
    declare CONFIG_CLUSTER CONFIG_DYNAMIC CONFIG_WRITE CONFIG_SLAVE CONFIG_FW

    if [ -z "$IP_MASTER" ] || [ -z "$IP_SLAVE" ]; then
        return 1
    fi

    CONFIG_CLUSTER='neighbours {'$'\n\t'"master { host = \"$IP_MASTER:11334\"; }"$'\n\t'"slave { host = \"$IP_SLAVE:11334\"; }"$'\n''}'
    CONFIG_DYNAMIC='dynamic_conf = "/var/lib/rspamd/rspamd_dynamic";'
    CONFIG_WRITE="write_servers = \"$IP_MASTER\";"
    CONFIG_SLAVE="slaveof $IP_MASTER 6379"

    if ! [ -f "$CONFIG_RSPAMD_OPTIONS" ] || [ "$(sed -n '/^neighbours {$/,/^}$/p' "$CONFIG_RSPAMD_OPTIONS")" != "$CONFIG_CLUSTER" ]; then
        echo "$CONFIG_CLUSTER" >> "$CONFIG_RSPAMD_OPTIONS"
    fi

    if ! [ -f "$CONFIG_RSPAMD_OPTIONS" ] || ! grep -q "^$CONFIG_DYNAMIC$" "$CONFIG_RSPAMD_OPTIONS"; then
        echo "$CONFIG_DYNAMIC" >> "$CONFIG_RSPAMD_OPTIONS"
    fi

    grep -q '^read_servers = "127.0.0.1";$' "$CONFIG_RSPAMD_REDIS" && sed -i "s/^read_servers = \"127.0.0.1\";$/read_servers = \"master-slave:127.0.0.1,$IP_PEER\";/" "$CONFIG_RSPAMD_REDIS"

    grep -q '^bind 127.0.0.1' "$CONFIG_REDIS" && sed -i 's/^bind 127.0.0.1/#bind 127.0.0.1/' "$CONFIG_REDIS"
    grep -q '^protected-mode yes$' "$CONFIG_REDIS" && sed -i 's/^protected-mode yes$/protected-mode no/' "$CONFIG_REDIS"

    if [ "$IP_ADDRESS" = "$IP_SLAVE" ]; then
        if ! [ -f "$CONFIG_RSPAMD_REDIS" ] || grep -q '^write_servers = "127.0.0.1";$' "$CONFIG_RSPAMD_REDIS"; then
            sed -i "s/^write_servers = \"127.0.0.1\";$/$CONFIG_WRITE/" "$CONFIG_RSPAMD_REDIS"
        fi

        grep -q "^$CONFIG_SLAVE$" "$CONFIG_REDIS" || echo "$CONFIG_SLAVE" >> "$CONFIG_REDIS"
    fi

    CONFIG_FW="-p tcp -m tcp -s $IP_PEER --match multiport --dports 11334,6379 -j ACCEPT"

    if ! grep -q "^$CONFIG_FW$" "$CONFIG_IPTABLES"; then
        NUM_LINE="$(grep -n '^-A INPUT ' "$CONFIG_IPTABLES" | head -1 | awk -F: '{print $1}')"
        sed -i "${NUM_LINE}i -A INPUT $CONFIG_FW" "$CONFIG_IPTABLES"
        iptables -I INPUT 1 $CONFIG_FW &>/dev/null
    fi

    CONFIG_FW="-p tcp -m tcp -s $IP_ADDRESS --match multiport --dports 11334,6379 -j ACCEPT"

    ssh mx "if ! [ -f '$CONFIG_RSPAMD_OPTIONS' ] || [ \"\$(sed -n '/^neighbours {$/,/^}$/p' '$CONFIG_RSPAMD_OPTIONS')\" != '$CONFIG_CLUSTER' ]; then echo '$CONFIG_CLUSTER' >> '$CONFIG_RSPAMD_OPTIONS'; fi; if ! [ -f '$CONFIG_RSPAMD_OPTIONS' ] || ! grep -q '^$CONFIG_DYNAMIC$' '$CONFIG_RSPAMD_OPTIONS'; then echo '$CONFIG_DYNAMIC' >> '$CONFIG_RSPAMD_OPTIONS'; fi; grep -q '^read_servers = \"127.0.0.1\";$' '$CONFIG_RSPAMD_REDIS' && sed -i 's/^read_servers = \"127.0.0.1\";$/read_servers = \"master-slave:127.0.0.1,$IP_ADDRESS\";/' '$CONFIG_RSPAMD_REDIS'; grep -q '^bind 127.0.0.1' '$CONFIG_REDIS' && sed -i 's/^bind 127.0.0.1/#bind 127.0.0.1/' '$CONFIG_REDIS'; grep -q '^protected-mode yes$' '$CONFIG_REDIS' && sed -i 's/^protected-mode yes$/protected-mode no/' '$CONFIG_REDIS'; if [ '$IP_PEER' = '$IP_SLAVE' ]; then if ! [ -f '$CONFIG_RSPAMD_REDIS' ] || grep -q '^write_servers = \"127.0.0.1\";$' '$CONFIG_RSPAMD_REDIS'; then sed -i 's/^write_servers = \"127.0.0.1\";$/$CONFIG_WRITE/' '$CONFIG_RSPAMD_REDIS'; fi; grep -q '^$CONFIG_SLAVE$' '$CONFIG_REDIS' || echo '$CONFIG_SLAVE' >> '$CONFIG_REDIS'; fi; if ! grep -q '^$CONFIG_FW$' '$CONFIG_IPTABLES'; then NUM_LINE="$(grep -n '^-A INPUT ' "$CONFIG_IPTABLES" | head -1 | awk -F: '{print $1}')"; sed -i \"\${NUM_LINE}i -A INPUT $CONFIG_FW\" '$CONFIG_IPTABLES'; iptables -I INPUT 1 $CONFIG_FW; fi; systemctl restart redis; systemctl restart rspamd" &>/dev/null

    systemctl restart redis &>/dev/null
}

# disable cluster setup
# parameters:
# none
# return values:
# none
cluster_disable() {
    declare -r IP_ADDRESS="$(hostname -I | tr -d ' ')"
    declare -r IP_PEER="$(sed -n '/^Host mx$/,/^$/p' ~/.ssh/config | awk 'match($0, /^\tHostName (\S+)$/, a) {print a[1]}')"
    declare -r LIST_IP="$(echo "$IP_ADDRESS"$'\n'"$IP_PEER" | sort | xargs)"
    declare -r IP_MASTER="$(echo "$LIST_IP" | awk '{print $1}')"
    declare -r IP_SLAVE="$(echo "$LIST_IP" | awk '{print $2}')"
    declare -r CONFIG_DYNAMIC='dynamic_conf = "\/var\/lib\/rspamd\/rspamd_dynamic";'
    declare -r CONFIG_WRITE="write_servers = \"$IP_MASTER\";"
    declare -r CONFIG_SLAVE="slaveof $IP_MASTER 6379"

    sed -i '/^neighbours {$/,/^}$/d' "$CONFIG_RSPAMD_OPTIONS"
    sed -i "/^$CONFIG_DYNAMIC$/d" "$CONFIG_RSPAMD_OPTIONS"
    sed -i "s/^read_servers = \"master-slave:127.0.0.1,$IP_PEER\";$/read_servers = \"127.0.0.1\";/" "$CONFIG_RSPAMD_REDIS"
    sed -i "s/^$CONFIG_WRITE$/write_servers = \"127.0.0.1\";/" "$CONFIG_RSPAMD_REDIS"

    sed -i 's/^#bind 127.0.0.1/bind 127.0.0.1/' "$CONFIG_REDIS"
    sed -i 's/^protected-mode no$/protected-mode yes/' "$CONFIG_REDIS"
    sed -i "/^$CONFIG_SLAVE$/d" "$CONFIG_REDIS"

    systemctl restart rspamd &>/dev/null
    systemctl restart redis &>/dev/null

    CONFIG_FW="INPUT -p tcp -m tcp -s $IP_PEER --match multiport --dports 11334,6379 -j ACCEPT"

    sed -i "/^-A $CONFIG_FW$/d" "$CONFIG_IPTABLES"
    iptables -D $CONFIG_FW &>/dev/null

    CONFIG_FW="INPUT -p tcp -m tcp -s $IP_ADDRESS --match multiport --dports 11334,6379 -j ACCEPT"

    ssh mx "sed -i '/^neighbours {$/,/^}$/d' '$CONFIG_RSPAMD_OPTIONS'; sed -i '/^$CONFIG_DYNAMIC$/d' '$CONFIG_RSPAMD_OPTIONS'; sed -i 's/^read_servers = \"master-slave:127.0.0.1,$IP_ADDRESS\";$/read_servers = \"127.0.0.1\";/' '$CONFIG_RSPAMD_REDIS'; sed -i 's/^$CONFIG_WRITE$/write_servers = \"127.0.0.1\";/' '$CONFIG_RSPAMD_REDIS'; sed -i 's/^#bind 127.0.0.1/bind 127.0.0.1/' '$CONFIG_REDIS'; sed -i 's/^protected-mode no$/protected-mode yes/' '$CONFIG_REDIS'; sed -i '/^$CONFIG_SLAVE$/d' '$CONFIG_REDIS'; systemctl restart rspamd; systemctl restart redis; sed -i '/^-A $CONFIG_FW$/d' '$CONFIG_IPTABLES'; iptables -D $CONFIG_FW" &>/dev/null
}

# checks status of given Rspamd feature
# parameters:
# $1 - feature label
# return values:
# stdout - feature status
rspamd_feature_status() {
    declare COUNTER RSPAMD_SETTING SETTING_KEY SETTING_VALUE FILE_CONFIG

    if [ "$(eval echo \"\$RSPAMD_${1^^}_CUSTOM\")" = 1 ] && ! "${1}_status"; then
        echo 'off'
        return
    fi

    for COUNTER in $(seq 0 "$(expr "$(eval echo \"\${\#RSPAMD_${1^^}[@]}\")" / 2 - 1)"); do
        RSPAMD_SETTING="$(eval echo \"\${RSPAMD_${1^^}[\$\(expr $COUNTER \\\* 2\)]}\")"
        SETTING_KEY="$(echo "$RSPAMD_SETTING" | awk -F ' = ' '{print $1}')"
        SETTING_VALUE="$(echo "$RSPAMD_SETTING" | sed -E "s/^$SETTING_KEY = //")"
        FILE_CONFIG="$(eval echo \"\${RSPAMD_${1^^}[\$\(expr $COUNTER \\\* 2 + 1\)]}\")"

        if ! [ -f "$FILE_CONFIG" ] || [ "$(grep "^$SETTING_KEY = " "$FILE_CONFIG" | sed -E "s/^$SETTING_KEY = ?//")" != "$SETTING_VALUE" ]; then
            echo 'off'
            return
        fi
    done

    echo 'on'
}

# enable given Rspamd feature
# parameters:
# $1 - feature label
# return values:
# error code - 0 for changes made, 1 for no changes made
rspamd_feature_enable() {
    declare COUNTER RSPAMD_SETTING FILE_CONFIG

    if [ "$(eval echo \"\$RSPAMD_${1^^}_CUSTOM\")" = 1 ] && ! "${1}_enable"; then
        return 1
    fi

    for COUNTER in $(seq 0 "$(expr "$(eval echo \"\${\#RSPAMD_${1^^}[@]}\")" / 2 - 1)"); do
        RSPAMD_SETTING="$(eval echo \"\${RSPAMD_${1^^}[\$\(expr $COUNTER \\\* 2\)]}\")"
        FILE_CONFIG="$(eval echo \"\${RSPAMD_${1^^}[\$\(expr $COUNTER \\\* 2 + 1\)]}\")"

        [ -f "$FILE_CONFIG" ] && sed -i "/^$(echo "$RSPAMD_SETTING" | awk -F ' = ' '{print $1}')/d" "$FILE_CONFIG"
        echo "$RSPAMD_SETTING" >> "$FILE_CONFIG"
    done

    return 0
}

# disable given Rspamd feature
# parameters:
# $1 - feature label
# return values:
# error code - 0 for changes made, 1 for no changes made
rspamd_feature_disable() {
    declare COUNTER RSPAMD_SETTING FILE_CONFIG

    if [ "$(eval echo \"\$RSPAMD_${1^^}_CUSTOM\")" = 1 ] && ! "${1}_disable"; then
        return 1
    fi

    for COUNTER in $(seq 0 "$(expr "$(eval echo \"\${\#RSPAMD_${1^^}[@]}\")" / 2 - 1)"); do
        RSPAMD_SETTING="$(eval echo \"\${RSPAMD_${1^^}[\$\(expr $COUNTER \\\* 2\)]}\")"
        FILE_CONFIG="$(eval echo \"\${RSPAMD_${1^^}[\$\(expr $COUNTER \\\* 2 + 1\)]}\")"

        [ -f "$FILE_CONFIG" ] && sed -i "/^$(echo "$RSPAMD_SETTING" | awk -F ' = ' '{print $1}')/d" "$FILE_CONFIG"
    done

    return 0
}

# restart Rspamd
# parameters:
# none
# return values:
# none
rspamd_restart() {
    systemctl restart rspamd &>/dev/null
}

# enable/disable Rspamd features in dialog checklist
# parameters:
# none
# return values:
# none
rspamd_feature() {
    declare -a MENU_RSPAMD_FEATURE
    declare DIALOG_RET RET_CODE RSPAMD_RESTART FEATURE

    MENU_RSPAMD_FEATURE=()

    for FEATURE in "${RSPAMD_FEATURE[@]}"; do
        if [ "$(eval echo \"\$RSPAMD_${FEATURE^^}_CHECK\")" != 1 ] || "check_installed_$FEATURE"; then
            declare -r STATUS_RSPAMD_${FEATURE^^}="$(rspamd_feature_status "$FEATURE")"

            MENU_RSPAMD_FEATURE+=("$FEATURE" "$(eval echo \"\$RSPAMD_${FEATURE^^}_LABEL\")" "$(eval echo \"\$STATUS_RSPAMD_${FEATURE^^}\")")
        fi
    done

    while true; do
        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --ok-label 'Select' --no-tags --extra-button --extra-label 'Help' --checklist 'Choose Rspamd features to enable' 0 0 0 "${MENU_RSPAMD_FEATURE[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            show_wait
            RSPAMD_RESTART=0

            for FEATURE in "${RSPAMD_FEATURE[@]}"; do
                if echo "$DIALOG_RET" | grep -E -q "(^| )$FEATURE($| )"; then
                    if [ "$(eval echo \"\$STATUS_RSPAMD_${FEATURE^^}\")" = 'off' ]; then
                        rspamd_feature_enable "$FEATURE" && RSPAMD_RESTART=1 || break
                    fi
                else
                    if [ "$(eval echo \"\$STATUS_RSPAMD_${FEATURE^^}\")" = 'on' ]; then
                        rspamd_feature_disable "$FEATURE" && RSPAMD_RESTART=1 || break
                    fi
                fi
            done

            [ "$RSPAMD_RESTART" = 1 ] && rspamd_restart

            break
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$HELP_RSPAMD_FEATURE"
        else
            break
        fi
    done
}

# select Rspamd configuration file for editing in dialog menu
# parameters:
# none
# return values:
# none
rspamd_config() {
    declare -r TAG_LOCAL='local.d'
    declare -r TAG_OVERRIDE='override.d'
    declare -r LABEL_LOCAL='local.d'
    declare -r LABEL_OVERRIDE='override.d'
    declare -a MENU_RSPAMD_CONFIG MENU_FILE
    declare CONFIG DIALOG_RET RET_CODE DIR_CONFIG

    MENU_RSPAMD_CONFIG=()

    [ -z "$(ls "$DIR_CONFIG")" ] || MENU_RSPAMD_CONFIG+=("$TAG_LOCAL" "$LABEL_LOCAL")
    [ -z "$(ls "$DIR_CONFIG")" ] || MENU_RSPAMD_CONFIG+=("$TAG_OVERRIDE" "$LABEL_OVERRIDE")

    for CONFIG in "${RSPAMD_CONFIG[@]}"; do
        MENU_RSPAMD_CONFIG+=("$CONFIG" "$(eval echo \"\$LABEL_CONFIG_RSPAMD_${CONFIG^^}\")")
    done

    while true; do
        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --ok-label 'Select' --no-tags --extra-button --extra-label 'Help' --menu 'Choose Rspamd config to edit' 0 0 0 "${MENU_RSPAMD_CONFIG[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            if [ "$DIALOG_RET" = "$TAG_LOCAL" ] || [ "$DIALOG_RET" = "$TAG_OVERRIDE" ]; then
                DIR_CONFIG="$DIR_CONFIG_RSPAMD/$DIALOG_RET"

                LIST_FILE="$(ls "$DIR_CONFIG")"

                MENU_FILE=()

                for FILE in $LIST_FILE; do
                    MENU_FILE+=("$FILE" "$FILE")
                done

                exec 3>&1
                DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --ok-label 'Select' --no-tags --extra-button --extra-label 'Help' --menu 'Choose Rspamd config to edit' 0 0 0 "${MENU_FILE[@]}" 2>&1 1>&3)"
                RET_CODE="$?"
                exec 3>&-

                if [ "$RET_CODE" = 0 ]; then
                    edit_config "$DIR_CONFIG/$DIALOG_RET" && systemctl reload rspamd &>/dev/null
                fi
            else
                edit_config "$(eval echo \"\$CONFIG_RSPAMD_${DIALOG_RET^^}\")" && systemctl reload rspamd &>/dev/null
            fi
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$HELP_RSPAMD_CONFIG"
        else
            break
        fi
    done
}

# sync Rspamd config with other peer
# parameters:
# none
# return values:
# none
rspamd_sync() {
    show_wait
    rsync -avzh -e ssh "$DIR_CONFIG_RSPAMD" mx:"$DIR_CONFIG_RSPAMD" &>/dev/null
    rsync -avzh -e ssh "$DIR_LIB_RSPAMD/$CONFIG_RSPAMD_WHITELIST_IP" mx:"$DIR_LIB_RSPAMD/$CONFIG_RSPAMD_WHITELIST_IP" &>/dev/null
    rsync -avzh -e ssh "$DIR_LIB_RSPAMD/$CONFIG_RSPAMD_WHITELIST_DOMAIN" mx:"$DIR_LIB_RSPAMD/$CONFIG_RSPAMD_WHITELIST_DOMAIN" &>/dev/null
    rsync -avzh -e ssh "$DIR_LIB_RSPAMD/$CONFIG_RSPAMD_WHITELIST_FROM" mx:"$DIR_LIB_RSPAMD/$CONFIG_RSPAMD_WHITELIST_FROM" &>/dev/null
    rsync -avzh -e ssh "$DIR_LIB_RSPAMD/$CONFIG_RSPAMD_WHITELIST_TO" mx:"$DIR_LIB_RSPAMD/$CONFIG_RSPAMD_WHITELIST_TO" &>/dev/null
    rsync -avzh -e ssh "$DIR_LIB_RSPAMD/$CONFIG_RSPAMD_BLACKLIST_COUNTRY" mx:"$DIR_LIB_RSPAMD/$CONFIG_RSPAMD_BLACKLIST_COUNTRY" &>/dev/null
    ssh mx systemctl reload rspamd &>/dev/null
}

# show Rspamd info & stats
# parameters:
# none
# return values:
# none
rspamd_info() {
    declare -r INFO="$(rspamc stat)"

    show_info 'Rspamd info & stats' "$INFO"
}

# check SA whitelist update status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 for disabled
wlupdate_status() {
    [ -f "$SCRIPT_WLUPDATE" ] && grep -q '^Host whitelist$' "$CONFIG_SSH" && check_crontab "$CRONTAB_WLUPDATE"
}

# enable SA whitelist update
# parameters:
# none
# return values:
# error code - 0 for changes made, 1 for no changes made
wlupdate_enable() {
    declare -r DIR_SSH="$HOME/.ssh"
    declare -r PACKED_SCRIPT='
    H4sIAOgeh14AA3VUYW+iQBD9zq+YUlM0PcCa3JdebDRKTxNrG7HXXFpLVliFlF3I7nJt77z/fgNV
    QeqR1azuvjdvZt5wemIvI24viQw17RSyNCCKeq9hpGgcSWXJEH5cWG2rrZ3i8SBJ30W0DhU0/RZ0
    2p02TKkaJBzuuaKC05BRLpdUEJXxNXxny9EX4FT5CTfxI7NYRXxt+Qkr6PqZChNxCTdE+DCMqHiR
    lEOTWcF23zuKbWma64680a077xp7qYbm3PTHE2/mDMZ3Y2eKZ9kr7WUyYYwKK6CGpl2PJ473MBrP
    nck4B9tIb8uUMCIlLizEns5biYRZ/gpR81l/6t7dzubeTf9uC0oTqVbRm81IKm0lCJdpIlCDlhN7
    /eFw5rhuV280JVZQb+z06tC5sgP6y+ZZHMMGlAAzAONJGC1d06IVPIL5G+9XWXRYfAMVUq4BPsNb
    zHJayRJjUD9MEFTLX98AeX0B81rv6WD8SUXEFTQ6f/NQOVPxtYVM+j+7hlH+jTJWyHiQOeqAs7Mq
    AkOvBU1Bf27UZYH+Gf6hp6oEdhLBeHx6wrVYGMekbqtShj6qJYjWcC7RUQrOeRJwKakP7A2BdXW5
    FpnfM7nIu0CiGMyLIwKrpSq7c6Cj0pv8+ejFgHCeKAgoTgWLOAWWhxA0Ju96efUtUnBR/KSxpIcU
    hiNEImBNVW57KG2OKgsyU2LR7ot5hYfd6QL+CzNdkEyl3ar8y85XHUyBKTVDNDQnjLZ65R692dKP
    GKtQuoq0veq66beGPHQxlpyi16X9XJsysAv3b2t8sjPf4bDmHd9s8KxOe9LN5ftEfYa0/teeGsXV
    Z+gesN/Id6ko81XRxoQEUH1vwFk51rvq4PoHZwjOYF4FAAA=
    '
    declare IP_ADDRESS RET_CODE SSH_PORT SSH_KEY

    if [ -d "$DIR_SSH" ] && ! [ -z "$(ls "$DIR_SSH"/*)" ]; then
        exec 3>&1
        IP_ADDRESS="$(get_input 'Whitelist server IP address' 'Enter whitelist server IP address')"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            exec 3>&1
            SSH_PORT="$(get_input 'Whitelist server SSH port' 'Enter whitelist server SSH port' '22')"
            RET_CODE="$?"
            exec 3>&-

            if [ "$RET_CODE" = 0 ]; then
                exec 3>&1
                SSH_KEY="$(get_file 'Select SSH key' "$DIR_SSH")"
                RET_CODE="$?"
                exec 3>&-

                if [ "$RET_CODE" = 0 ]; then
                    show_wait

                    if ! [ -z "$(ssh -o 'StrictHostKeyChecking=accept-new' -p "$SSH_PORT" "whitelist@$IP_ADDRESS" -i "$SSH_KEY" 2>/dev/null)" ]; then
                        echo $'\n''Host whitelist'$'\n\t'"HostName $IP_ADDRESS"$'\n\t''User whitelist'$'\n\t'"Port $SSH_PORT"$'\n\t'"IdentityFile $SSH_KEY"$'\n' >> "$CONFIG_SSH"

                        mkdir -p "$(dirname "$SCRIPT_WLUPDATE")"
                        printf '%s' $PACKED_SCRIPT | base64 -d | gunzip > "$SCRIPT_WLUPDATE"
                        chmod 700 "$SCRIPT_WLUPDATE"
                        "$SCRIPT_WLUPDATE"

                        add_crontab "$CRONTAB_WLUPDATE"

                        return 0
                    else
                        show_info 'Error' 'Error getting whitelist from server.'
                    fi
                fi
            fi
        fi
    else
        show_info 'Error' 'No SSH keys for connection to whitelist server available.'
    fi

    return 1
}

# disable SA whitelist update
# parameters:
# none
# return values:
# none
wlupdate_disable() {
    del_crontab "$CRONTAB_WLUPDATE"

    rm -f "$SCRIPT_WLUPDATE"

    sed -i '/^Host whitelist/,/^$/d' "$CONFIG_SSH"
}

# checks status of given Spamassassin feature
# parameters:
# $1 - feature label
# return values:
# stdout - feature status
spamassassin_feature_status() {
    if [ "$(eval echo \"\$SPAMASSASSIN_${1^^}_CUSTOM\")" = 1 ] && ! "${1}_status"; then
        echo 'off'
        return
    fi

    echo 'on'
}

# enable given Spamassassin feature
# parameters:
# $1 - feature label
# return values:
# error code - 0 for changes made, 1 for no changes made
spamassassin_feature_enable() {
    if [ "$(eval echo \"\$SPAMASSASSIN_${1^^}_CUSTOM\")" = 1 ] && ! "${1}_enable"; then
        return 1
    fi

    return 0
}

# disable given Spamassassin feature
# parameters:
# $1 - feature label
# return values:
# error code - 0 for changes made, 1 for no changes made
spamassassin_feature_disable() {
    if [ "$(eval echo \"\$SPAMASSASSIN_${1^^}_CUSTOM\")" = 1 ] && ! "${1}_disable"; then
        return 1
    fi

    return 0
}

# restart Spamassassin
# parameters:
# none
# return values:
# none
spamassassin_restart() {
    systemctl restart spamassassin &>/dev/null
}

# enable/disable Spamassassin features in dialog checklist
# parameters:
# none
# return values:
# none
spamassassin_feature() {
    declare -a MENU_SPAMASSASSIN_FEATURE
    declare DIALOG_RET RET_CODE SPAMASSASSIN_RESTART FEATURE

    MENU_SPAMASSASSIN_FEATURE=()

    for FEATURE in "${SPAMASSASSIN_FEATURE[@]}"; do
        if [ "$(eval echo \"\$SPAMASSASSIN_${FEATURE^^}_CHECK\")" != 1 ] || "check_installed_$FEATURE"; then
            declare -r STATUS_SPAMASSASSIN_${FEATURE^^}="$(spamassassin_feature_status "$FEATURE")"

            MENU_SPAMASSASSIN_FEATURE+=("$FEATURE" "$(eval echo \"\$SPAMASSASSIN_${FEATURE^^}_LABEL\")" "$(eval echo \"\$STATUS_SPAMASSASSIN_${FEATURE^^}\")")
        fi
    done

    while true; do
        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --ok-label 'Select' --no-tags --extra-button --extra-label 'Help' --checklist 'Choose Spamassassin features to enable' 0 0 0 "${MENU_SPAMASSASSIN_FEATURE[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            show_wait
            SPAMASSASSIN_RESTART=0

            for FEATURE in "${SPAMASSASSIN_FEATURE[@]}"; do
                if echo "$DIALOG_RET" | grep -E -q "(^| )$FEATURE($| )"; then
                    if [ "$(eval echo \"\$SPAMASSASSIN_${FEATURE^^}_FORCE\")" = 1 ] || [ "$(eval echo \"\$STATUS_SPAMASSASSIN_${FEATURE^^}\")" = 'off' ]; then
                        spamassassin_feature_enable "$FEATURE" && SPAMASSASSIN_RESTART=1
                    fi
                else
                    if [ "$(eval echo \"\$STATUS_SPAMASSASSIN_${FEATURE^^}\")" = 'on' ]; then
                        spamassassin_feature_disable "$FEATURE" && SPAMASSASSIN_RESTART=1
                    fi
                fi
            done

            [ "$SPAMASSASSIN_RESTART" = 1 ] && spamassassin_restart

            break
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$HELP_SPAMASSASSIN_FEATURE"
        else
            break
        fi
    done
}

# select Spamassassin configuration file for editing in dialog menu
# parameters:
# none
# return values:
# none
spamassassin_config() {
    declare -a MENU_SPAMASSASSIN_CONFIG
    declare CONFIG DIALOG_RET RET_CODE FILE_CONFIG

    MENU_SPAMASSASSIN_CONFIG=()

    for CONFIG in "${SPAMASSASSIN_CONFIG[@]}"; do
        MENU_SPAMASSASSIN_CONFIG+=("$CONFIG" "$(eval echo \"\$LABEL_CONFIG_SPAMASSASSIN_${CONFIG^^}\")")
    done

    while true; do
        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --ok-label 'Select' --no-tags --extra-button --extra-label 'Help' --menu 'Choose Spamassassin config to edit' 0 0 0 "${MENU_SPAMASSASSIN_CONFIG[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            edit_config "$(eval echo \"\$CONFIG_SPAMASSASSIN_${DIALOG_RET^^}\")" && systemctl reload spamassassin &>/dev/null
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$HELP_SPAMASSASSIN_CONFIG"
        else
            break
        fi
    done
}

# show ham stats
# parameters:
# none
# return values:
# none
show_ham() {
    declare -r INFO="$(grep 'result: \.' "$DIR_LOG_SPAMASSASSIN/current.log" | awk -F 'result:' '{print $2}'| awk '{$1=$2=$3=""; print $0}' | awk -F 'scantime' '{print $1}' | sed 's/,/\n/g' | sed 's/ //g' | sort | uniq -c | sort -nr | head -50)"
 
    show_info 'Today ham stats' "$INFO"
}

# show spam stats
# parameters:
# none
# return values:
# none
show_spam() {
    declare -r INFO="$(grep 'result: Y' "$DIR_LOG_SPAMASSASSIN/current.log" | awk -F ' - ' '{print $2}' | awk -F 'scantime' '{print $1}' | sed 's/,/\n/g' | sed 's/ //g' | sort | uniq -c | sort -nr | head -50)"

    show_info 'Today spam stats' "$INFO"
}

# show spamassassin stats
# parameters:
# none
# return values:
# none
show_spamassassin() {
    declare -r NUM_REJECTED="$(find "$DIR_LOG_POSTFIX/rejected" -daystart -mtime 1 -name 'rejected*.log' | sort | xargs -l grep -v '450' | wc -l)"
    declare -r NUM_HAM="$(find "$DIR_LOG_SPAMASSASSIN" -daystart -mtime 1 -name 'spamd*.log' | sort | xargs -l grep 'result: \.' | wc -l)"
    declare -r NUM_SPAM="$(find "$DIR_LOG_SPAMASSASSIN" -daystart -mtime 1 -name 'spamd*.log' | sort | xargs -l grep 'result: Y' | wc -l )"
    declare -r NUM_TOTAL="$(expr $NUM_REJECTED + $NUM_HAM + $NUM_SPAM)"
    declare -r INFO="Rejected: $NUM_REJECTED"$'\n'"Ham: $NUM_HAM"$'\n'"Spam: $NUM_SPAM"$'\n'"Total: $NUM_TOTAL"

    show_info 'Yesterday spamassassin stats' "$INFO"
}

# select Spamassassin info to show in dialog menu
# parameters:
# none
# return values:
# none
spamassassin_info() {
    declare -a MENU_SPAMASSASSIN_INFO
    declare DIALOG_RET RET_CODE

    MENU_SPAMASSASSIN_INFO=()
    MENU_SPAMASSASSIN_INFO+=('ham' 'Ham stats')
    MENU_SPAMASSASSIN_INFO+=('spam' 'Spam stats')
    MENU_SPAMASSASSIN_INFO+=('spamassassin' 'Spamassassin stats')

    while true; do
        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --ok-label 'Select' --no-tags --extra-button --extra-label 'Help' --menu 'Choose info to show' 0 0 0 "${MENU_SPAMASSASSIN_INFO[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            "show_$DIALOG_RET"
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$HELP_SPAMASSASSIN_INFO"
        else
            break
        fi
    done
}

# sync Spamassassin config with other peer
# parameters:
# none
# return values:
# none
spamassassin_sync() {
    show_wait
    rsync -avzh -e ssh "$DIR_CONFIG_SPAMASSASSIN" mx:"$DIR_CONFIG_SPAMASSASSIN" &>/dev/null
    ssh mx systemctl reload spamassassin &>/dev/null
}

# select Fail2ban configuration file for editing in dialog menu
# parameters:
# none
# return values:
# none
fail2ban_config() {
    declare -r TAG_SYNC='sync'
    declare -a MENU_FAIL2BAN_CONFIG
    declare CONFIG DIALOG_RET RET_CODE FILE_CONFIG

    MENU_FAIL2BAN_CONFIG=()

    for CONFIG in "${FAIL2BAN_CONFIG[@]}"; do
        MENU_FAIL2BAN_CONFIG+=("$CONFIG" "$(eval echo \"\$LABEL_CONFIG_FAIL2BAN_${CONFIG^^}\")")
    done

    check_installed_cluster && MENU_FAIL2BAN_CONFIG+=("$TAG_SYNC" 'Sync cluster')

    while true; do
        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --ok-label 'Select' --no-tags --extra-button --extra-label 'Help' --menu 'Choose config to edit' 0 0 0 "${MENU_FAIL2BAN_CONFIG[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            if [ "$DIALOG_RET" = "$TAG_SYNC" ]; then
                sync_fail2ban
            else
                FILE_CONFIG="$(eval echo \"\$CONFIG_FAIL2BAN_${DIALOG_RET^^}\")"

                if [ -d "$FILE_CONFIG" ]; then
                    exec 3>&1
                    FILE_CONFIG="$(get_file 'Select config file' "$FILE_CONFIG")"
                    RET_CODE="$?"
                    exec 3>&-

                    if [ "$RET_CODE" = 0 ] && ! [ -z "$FILE_CONFIG" ]; then
                        edit_config "$FILE_CONFIG"
                    fi
                else
                    edit_config "$FILE_CONFIG"
                fi

                if [ "$?" != 0 ]; then
                    systemctl restart fail2ban
                fi
            fi
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$HELP_FAIL2BAN_CONFIG"
        else
            break
        fi
    done
}

# sync Fail2ban config with other peer
# parameters:
# none
# return values:
# none
fail2ban_sync() {
    show_wait
    rsync -avzh -e ssh "$CONFIG_FAIL2BAN" mx:"$CONFIG_FAIL2BAN"
    ssh mx systemctl restart fail2ban
}

# add IP addresses to jail
# parameters:
# $1 - jail name
# return values:
# none
fail2ban_ban() {
    declare IP_ADDRESS RET_CODE

    exec 3>&1
    IP_ADDRESS="$(get_input 'Fail2ban' 'Enter IP address to ban')" 
    RET_CODE="$?"
    exec 3>&-

    if [ "$RET_CODE" = 0 ]; then
        fail2ban-client set "$1" banip "$IP_ADDRESS" &>/dev/null
        sleep 1
    fi
}

# show banned IPs for given Fail2ban jail with option to unban in dialog menu
# parameters:
# $1 - jail name
# return values:
# none
fail2ban_banned() {
    declare -a MENU_FAIL2BAN_BANNED
    declare -r LABEL_BANNED_NONE='No banned IPs'
    declare LIST_BANNED RET_CODE DIALOG_RET

    while true; do
        LIST_BANNED="$(fail2ban-client status "$1" | grep '^   `\- Banned IP list:' | sed -E 's/^   `\- Banned IP list:\s+//' | xargs -n1 | sort)"

        if [ -z "$LIST_BANNED" ]; then
            "$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --ok-label 'Ban' --no-tags --menu 'Choose IP address to unban' 0 0 0 '' "$LABEL_BANNED_NONE"

            if [ "$?" = 0 ]; then
                fail2ban_ban "$1"
            else
                break
            fi
        else
            MENU_FAIL2BAN_BANNED=()

            for IP_ADDRESS in $LIST_BANNED; do
                MENU_FAIL2BAN_BANNED+=("$IP_ADDRESS" "$IP_ADDRESS")
            done

            exec 3>&1
            DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --ok-label 'Unban' --extra-button --extra-label 'Ban' --no-tags --menu 'Choose IP address to unban' 0 0 0 "${MENU_FAIL2BAN_BANNED[@]}" 2>&1 1>&3)"
            RET_CODE="$?"
            exec 3>&-

            if [ "$RET_CODE" = 0 ]; then
                if ! [ -z "$DIALOG_RET" ]; then
                    fail2ban-client set "$1" unbanip "$DIALOG_RET" &>/dev/null
                    sleep 1
                fi
            elif [ "$RET_CODE" = 3 ]; then
                fail2ban_ban "$1"
            else
                break
            fi
        fi
    done
}

# select Fail2ban jail in dialog menu
# parameters:
# none
# return values:
# none
fail2ban_jail() {
    declare -r LIST_JAIL="$(fail2ban-client status | grep '^`- Jail list:' | sed -E 's/^`- Jail list:\s+//' | sed 's/,//g')"
    declare -r LABEL_JAIL_NONE='No jails configured'
    declare -a MENU_FAIL2BAN_JAIL
    declare DIALOG_RET RET_CODE

    MENU_FAIL2BAN_JAIL=()
    if [ -z "$LIST_JAIL" ]; then
        "$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --no-ok --no-tags --menu 'Choose Fail2ban jail' 0 0 0 '' "$LABEL_JAIL_NONE"

        break
    else
        for NAME_JAIL in $LIST_JAIL; do
            MENU_FAIL2BAN_JAIL+=("$NAME_JAIL" "$NAME_JAIL")
        done

        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --ok-label 'Select' --no-tags --menu 'Choose Fail2ban jail' 0 0 0 "${MENU_FAIL2BAN_JAIL[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ] && ! [ -z "$DIALOG_RET" ]; then
            fail2ban_banned "$DIALOG_RET"
        fi
    fi
}

# show network connection
# parameters:
# none
# return values:
# none
show_connections() {
    declare -r INFO="$(netstat -antup)"

    show_info 'Network connections' "$INFO"
}

# show firewall config
# parameters:
# none
# return values:
# none
show_firewall() {
    declare -r INFO="$(iptables -L -n)"

    show_info 'Firewall rules' "$INFO"
}

# show install log
# parameters:
# none
# return values:
# none
show_install() {
    declare INFO

    if [ "$DISTRO" = 'redhat' ]; then
        INFO="$(cat /var/log/yum.log)"
    elif [ "$DISTRO" = 'debian' ]; then
        INFO="$(cat /var/log/apt/history.log)"
    fi

    show_info 'Install log' "$INFO"
}

# show pending updates
# parameters:
# none
# return values:
# none
show_update() {
    declare INFO

    if [ "$DISTRO" = 'redhat' ]; then
        INFO="$(yum -q list updates 2>/dev/null | sed '1d' | awk 'match($0, /(\S+)\s+(\S+)/, a) {print a[1]" ("a[2]")"}')"
    elif [ "$DISTRO" = 'debian' ]; then
        INFO="$(apt list --upgradable 2>/dev/null | grep 'upgradable' | awk 'match($0, /([^/]+)\S+ (\S+)/, a) {print a[1]" ("a[2]")"}')"
    fi

    [ -z "$INFO" ] && INFO='No pending updates'

    show_info 'Pending updates' "$INFO"
}

# check whether distro is Ubuntu, Debian or SUSE
# parameters:
# none
# return values:
# stderr - 0 if Ubuntu else 1
check_compatible() {
    cat /proc/version | grep -q -E '(Ubuntu|Debian|SUSE)'
}

# set setting
# parameters:
# $1 - setting
# return values:
# none
set_menu_setting() {
    sed -i -E "s/(declare -g $(echo "$1" | awk -F= '{print $1}')=).+/\1$(echo "$1" | awk -F= '{print $2}')/" "$0"
    eval "$1"
}

# select editor in dialog menu
# parameters:
# none
# return values:
# none
text_editor() {
    declare -a MENU_EDITOR

    for EDITOR in "${TEXT_EDITORS[@]}"; do
        which "$EDITOR" &>/dev/null && MENU_EDITOR+=("$EDITOR" "$EDITOR")
    done

    exec 3>&1
    DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --no-tags --extra-button --extra-label 'Help' --menu 'Select text editor' 0 0 0 "${MENU_EDITOR[@]}" 2>&1 1>&3)"
    RET_CODE="$?"
    exec 3>&-

    if [ "$RET_CODE" = 0 ]; then
        set_menu_setting "TXT_EDITOR='$DIALOG_RET'"
    elif [ "$RET_CODE" = 3 ]; then
        show_help "$HELP_TEXT_EDITOR"
    fi
}

# get update email address
# parameters:
# none
# return values:
# stdout - update email address
get_email_update() {
    grep -E '^Unattended-Upgrade::Mail "\S+";$' "$CONFIG_UPDATE" | awk 'match($0, /^Unattended-Upgrade::Mail "([^"]+)";$/, a) {print a[1]}'
}

# set update email address
# parameters:
# $1 - update email address
# return values:
# none
set_email_update() {
    sed -E -i "s/^Unattended-Upgrade::Mail \"[^\"]+\";$/Unattended-Upgrade::Mail \"$1\";/" "$CONFIG_UPDATE"
}

# get logwatch email address
# parameters:
# none
# return values:
# stdout - logwatch email address
get_email_logwatch() {
    grep -E '^MailTo="[^"]+"$' "$CONFIG_LOGWATCH" | awk 'match($0, /^MailTo="([^"]+)"$/, a) {print a[1]}'
}

# set logwatch email address
# parameters:
# $1 - logwatch email address
# return values:
# none
set_email_logwatch() {
    sed -E -i "s/^MailTo=\"[^\"]+\"$/MailTo=\"$1\"/" "$CONFIG_LOGWATCH"
}

# get reboot email address
# parameters:
# none
# return values:
# stdout - reboot email address
get_email_reboot() {
    grep -E 'mail -s' "$SCRIPT_REBOOT" | awk 'match($0, / (\S+)$/, a) {print a[1]}'
}

# set reboot email address
# parameters:
# $1 - reboot email address
# return values:
# none
set_email_reboot() {
    sed -E -i "s/ \S+$/ $1/" "$SCRIPT_REBOOT"
}

# get SA whitelist update email address
# parameters:
# none
# return values:
# stdout - get SA whitelist update email address
get_email_wlupdate() {
    grep -E '^EMAIL_RECIPIENT=' "$SCRIPT_WLUPDATE" | awk "match(\$0, /^EMAIL_RECIPIENT='([^']+)'$/, a) {print a[1]}"
}

# set get SA whitelist update email address
# parameters:
# $1 - get SA whitelist update email address
# return values:
# none
set_email_wlupdate() {
    sed -E -i "s/^EMAIL_RECIPIENT='[^']+'$/EMAIL_RECIPIENT='$1'/" "$SCRIPT_WLUPDATE"
}

# configure email addresses in dialog menu
# parameters:
# none
# return values:
# none
email_addresses() {
    declare DIALOG_RET RET_CODE EMAIL_ADDRESS EMAIL_CURRENT
    declare -a MENU_EMAIL

    while true; do
        MENU_EMAIL=()

        for EMAIL_ADDRESS in "${EMAIL_ADDRESSES[@]}"; do
            if [ "$(eval echo \"\$EMAIL_${EMAIL_ADDRESS^^}_CHECK\")" != 1 ] || "check_installed_$EMAIL_ADDRESS" 2>/dev/null || "${EMAIL_ADDRESS}_status" 2>/dev/null; then
                MENU_EMAIL+=("$EMAIL_ADDRESS" "$(eval echo \"\$LABEL_EMAIL_${EMAIL_ADDRESS^^}\") ($(get_email_$EMAIL_ADDRESS))")
            fi
        done

        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --no-tags --extra-button --extra-label 'Help' --menu 'Configure email address' 0 0 0 "${MENU_EMAIL[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            EMAIL_CURRENT="$(get_email_$DIALOG_RET)"

            exec 3>&1
            EMAIL_ADDRESS="$(get_input 'Email address' 'Enter email address' "$EMAIL_CURRENT")"
            RET_CODE="$?"
            exec 3>&-

            if [ "$RET_CODE" = 0 ] && ! [ -z "$EMAIL_ADDRESS" ] && [ "$EMAIL_ADDRESS" != "$EMAIL_CURRENT" ]; then
                "set_email_$DIALOG_RET" "$EMAIL_ADDRESS"
            fi
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$HELP_EMAIL_ADDRESSES"
        else
            break
        fi
    done
}

# list admin email addresses
# parameters:
# none
# return values:
# stdout - admin email addresses
admin_list() {
    awk "match(\$0, /^[^ ]+ (.*)$/, a) {print a[1]}" "$POSTFIX_ALIAS_ADMIN" | xargs -n 1
}

# add admin email address
# parameters:
# $1 - admin email address
# return values:
# none
admin_add() {
    sed -i "s/$/ $1/" "$POSTFIX_ALIAS_ADMIN"
    postmap "$POSTFIX_ALIAS_ADMIN"
}

# delete admin email address
# parameters:
# $1 - admin email address
# return values:
# none
admin_delete() {
    sed -i "s/ $1//" "$POSTFIX_ALIAS_ADMIN"
    postmap "$POSTFIX_ALIAS_ADMIN"
}

# configure admin email addresses
# parameters:
# none
# return values:
# none
admin_addresses() {
    manage_list 'Admin email addresses' 'email address' 'admin_list' 'admin_add' 'admin_delete'
}

# check automatic update status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 disabled
automatic_update_status() {
    declare OPTION

    for OPTION in                                                               \
        'APT::Periodic::Update-Package-Lists "1";'                              \
        'APT::Periodic::Download-Upgradeable-Packages "1";'                     \
        'APT::Periodic::AutocleanInterval "7";'                                 \
        'APT::Periodic::Unattended-Upgrade "1";'; do
        if ! [ -f "$CONFIG_UPDATE" ] || ! grep -q "^$OPTION$" "$CONFIG_UPDATE"; then
            return 1
        fi
    done    
}

# enable automatic update
# parameters:
# none
# return values:
# none
automatic_update_enable() {
    declare OPTION

    for OPTION in                                                               \
        'APT::Periodic::Update-Package-Lists "1";'                              \
        'APT::Periodic::Download-Upgradeable-Packages "1";'                     \
        'APT::Periodic::AutocleanInterval "7";'                                 \
        'APT::Periodic::Unattended-Upgrade "1";'; do
        if ! [ -f "$CONFIG_UPDATE" ] || ! grep -q "^$OPTION$" "$CONFIG_UPDATE"; then
            echo "$OPTION" >> "$CONFIG_UPDATE"
        fi
    done
}

# disable automatic update
# parameters:
# none
# return values:
# none
automatic_update_disable() {
    declare OPTION

    for OPTION in                                                               \
        'APT::Periodic::Update-Package-Lists "1";'                              \
        'APT::Periodic::Download-Upgradeable-Packages "1";'                     \
        'APT::Periodic::AutocleanInterval "7";'                                 \
        'APT::Periodic::Unattended-Upgrade "1";'; do
        sed -i "/^$OPTION$/d" "$CONFIG_UPDATE"
    done
}

# toggle automatic updates
# parameters:
# none
# return values:
# none
automatic_update() {
    toggle_setting 'automatic_update' 'Automatic update'
}

# restart sshd
# parameters:
# none
# return values:
# none
sshd_restart() {
    systemctl restart sshd
}

# check password authentication status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 disabled
pwauth_status() {
    grep -q '^PasswordAuthentication no$' "$CONFIG_SSHD" && return 1 || return 0
}

# enable password authentication
# parameters:
# none
# return values:
# none
pwauth_enable() {
    sed -i 's/^PasswordAuthentication no$/PasswordAuthentication yes/' "$CONFIG_SSHD"

    sshd_restart
}

# disable password authentication
# parameters:
# none
# return values:
# none
pwauth_disable() {
    if grep -q '^PasswordAuthentication yes$' "$CONFIG_SSHD"; then
        sed -i 's/^PasswordAuthentication yes$/PasswordAuthentication no/' "$CONFIG_SSHD"
    else
        echo 'PasswordAuthentication no' >> "$CONFIG_SSHD"
    fi

    sshd_restart
}

# toggle password authentication
# parameters:
# none
# return values:
# none
password_auth() {
    toggle_setting 'pwauth' 'SSH password authentication'
}

# check tsocks proxy status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 disabled
tsocks_status() {
    [ "$WGET" = 'wget' ] && return 1 || return 0
}

# enable tsocks proxy
# parameters:
# none
# return values:
# none
tsocks_enable() {
    set_menu_setting "WGET='tsocks wget'"
}

# disable tsocks proxy
# parameters:
# none
# return values:
# none
tsocks_disable() {
    set_menu_setting "WGET='wget'"
}

# toggle tsocks proxy
# parameters:
# none
# return values:
# none
tsocks_proxy() {
    toggle_setting 'tsocks' 'Tsocks proxy'
}

# check SNMP support status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 disabled
snmp_status() {
    grep -E -q '^rouser \S+$' "$FILE_SNMP" && return 0 || return 1
}

# enable SNMP support
# parameters:
# none
# return values:
# none
snmp_enable() {
    declare CLIENT_IP RET_CODE USER_NAME PASS_PHRASE CONFIG_FW

    exec 3>&1
    CLIENT_IP="$(get_input 'SNMP V3 configuration' 'Enter client IP')"
    RET_CODE="$?"
    exec 3>&-

    if [ "$RET_CODE" = 0 ] && ! [ -z "$CLIENT_IP" ]; then
                exec 3>&1
                USER_NAME="$(get_input 'SNMP V3 configuration' 'Enter user name')"
                RET_CODE="$?"
                exec 3>&-

                if [ "$RET_CODE" = 0 ] && ! [ -z "$USER_NAME" ]; then
                    exec 3>&1
                    PASS_PHRASE="$(get_input 'SNMP V3 configuration' 'Enter passphrase')"
                    RET_CODE="$?"
                    exec 3>&-

                    if [ "$RET_CODE" = 0 ] && ! [ -z "$PASS_PHRASE" ]; then
                        sed -i 's/^\s*agentAddress .*$/agentAddress tcp:161/' "$CONFIG_SNMP"
                        sed -i '/^\s*rocommunity .*$/d' "$CONFIG_SNMP"
                        sed -i '/^\s*rocommunity6 .*$/d' "$CONFIG_SNMP"
                        sed -i '/^\s*com2sec .*$/d' "$CONFIG_SNMP"
                        sed -i '/^\s*group .*$/d' "$CONFIG_SNMP"
                        sed -i '/^\s*access .*$/d' "$CONFIG_SNMP"

                        grep -q '^agentAddress tcp:161$' "$CONFIG_SNMP" || echo 'agentAddress tcp:161' >> "$CONFIG_SNMP"

                        systemctl stop snmpd &>/dev/null

                        net-snmp-create-v3-user -ro -a SHA -x AES -A "$PASS_PHRASE" -X "$PASS_PHRASE" "$USER_NAME" &>/dev/null

                        systemctl start snmpd &>/dev/null
                        enable_service snmpd &>/dev/null

                        CONFIG_FW="-i eth0 -p tcp --dport 161 -s $CLIENT_IP -j ACCEPT"

                        if ! grep -q "^$CONFIG_FW$" "$CONFIG_IPTABLES"; then
                            NUM_LINE="$(grep -n '^-A INPUT ' "$CONFIG_IPTABLES" | head -1 | awk -F: '{print $1}')"
                            sed -i "${NUM_LINE}i -A INPUT $CONFIG_FW" "$CONFIG_IPTABLES"
                            iptables -I INPUT 1 $CONFIG_FW &>/dev/null
                        fi

                        show_info 'SNMP info' 'SNMP enabled on TCP port 161.'$'\n\n''Test connection:'$'\n'"snmpget -v3 -u $USER_NAME -l authPriv -a SHA -x AES -A $PASS_PHRASE -X $PASS_PHRASE tcp:$(hostname -I | awk '{print $1}') SNMPv2-MIB::sysName.0"
                    fi
                fi
            fi
}

# disable SNMP support
# parameters:
# none
# return values:
# none
snmp_disable() {
    declare CONFIG_FW

    sed -i '/^rouser \S\+$/d' "$FILE_SNMP"

    systemctl stop snmpd &>/dev/null
    disable_service snmpd

    CONFIG_FW="$(grep -E '^-A INPUT -i eth0 -p tcp --dport 161 -s \S+ -j ACCEPT$' "$CONFIG_IPTABLES")"

    sed -i "/^-A $CONFIG_FW$/d" "$CONFIG_IPTABLES"
    iptables -D $CONFIG_FW &>/dev/null
}

# toggle SNMP support
# parameters:
# none
# return values:
# none
snmp_support() {
    toggle_setting 'snmp' 'SNMP support'
}

# select log action in dialog menu
# parameters:
# $1 - program log
# return values:
# none
log_action() {
    declare -r TAG_SEARCH='search'
    declare -r TAG_TAIL='tail'
    declare -r LABEL_SEARCH='Search logs'
    declare -r LABEL_TAIL='Tail current log'
    declare RET_CODE SEARCH_FILTER SEARCH_RESULT
    declare -a MENU_LOGACTION

    MENU_LOGACTION=()
    MENU_LOGACTION+=("$TAG_SEARCH" "$LABEL_SEARCH")
    MENU_LOGACTION+=("$TAG_TAIL" "$LABEL_TAIL")

    while true; do
        exec 3>&1
        LOG_ACTION="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --no-tags --extra-button --extra-label 'Help' --title '' --menu '' 0 0 0 "${MENU_LOGACTION[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            if [ "$LOG_ACTION" = "$TAG_SEARCH" ]; then
                exec 3>&1
                SEARCH_FILTER="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --title 'Search logs' --ok-label 'Current log' --extra-button --extra-label 'All logs' --inputbox 'Enter search filter' 0 0 '' 2>&1 1>&3)"
                RET_CODE="$?"
                exec 3>&-

                if ! [ -z "$SEARCH_FILTER" ]; then
                    if [ "$RET_CODE" = 0 ] || [ "$RET_CODE" = 3 ]; then
                        if [ "$RET_CODE" = 0 ]; then
                            SEARCH_RESULT="$(grep "$SEARCH_FILTER" "$(eval echo \"\$LOG_${1^^}_DIR\")/current.log")"
                        else
                            SEARCH_RESULT="$(grep "$SEARCH_FILTER" -h "$(eval echo \"\$LOG_${1^^}_DIR\")"/*.log)"
                        fi

                        [ -z "$SEARCH_RESULT" ] && SEARCH_RESULT='No result'

                        show_info 'Search results' "$SEARCH_RESULT"
                    fi
                fi
            elif [ "$LOG_ACTION" = "$TAG_TAIL" ]; then
                "$DIALOG" --clear --backtitle "$TITLE_MAIN" --title 'Tail current log' --tailbox "$(eval echo \"\$LOG_${1^^}_DIR\")/current.log" 40 120
            fi
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$HELP_LOG"
        else
            break
        fi
    done
}

# install Postfix
# parameters:
# none
# return values:
# none
install_postfix() {
    {
        DEBIAN_FRONTEND=noninteractive "$INSTALLER" -y -q install postfix

        postconf 'inet_protocols=all'
        postconf 'inet_protocols=ipv4'
        postconf 'mynetworks=127.0.0.0/8'

        [ -f /etc/postfix/makedefs.out ] && rm -f /etc/postfix/makedefs.out
    } 2>&1 | show_output 'Installing Postfix'
}

# install local DNS resolver
# parameters:
# none
# return values:
# none
install_resolver() {
    declare -r PACKED_CONFIG='
    H4sIANPPBV4AA7VXwW7bMAy99yuE3J2kw9oe+jGDYjOpMJnyJDltUuzfR0uKzLRVIQxOeihivmc+
    M9QjbQavDDrxfifo0ykLrTf2JFabo7SbVrYvsNkp7FbPEYDOQdscpVadnJhCjt7EWC/fGgyMxnst
    HrfbeJ0QLw2+daaXCgVe0ApVL3VjwQ0kAJw4gYshrZwHbAw2x0fxTgyEZ/H3Q4wC9z+e1lv6u8/R
    vdIebCPpE+g/55vSg43WTYrzJam1eW3mwFd3TA8MKHcaIpUid2fSJFYKKRuuUvH8aQAqAumzWU0G
    rbvdKlK1ORwUHhKpfZGIoIUdzr8CPl6e6eF3IM4GZQ/dhnBr+rYSRwiinXgQTp1BPGz750x1QGHl
    T6I7EU21c2SwpKfJ8VyLSRnX08FejtpXaUrYD7rut/8hzKseyqIOgGClrhKVsLcXRedA7qSDulIl
    cJC1lAI3dTCxqxRcwLcvTGtwrw5VoiJ00aKQrxhNN6g7VQl8+6K87cmfFFapSthFyxLuaca6g30B
    L6oAjVf7ul6N0EWzt1oB1j19hC6afcReehqQXZWAjF5Uw5+RyOCqFCTsEsfi88ipbhjwr8b+ruuY
    iF32RxvItevsPUIXzd4pN0xdUDdeEnhZBWEFqssfoLd3UU3ZqKPslKNKGCfcRN7073oonxzlYbrS
    BW1aqZ9uem6oBQ/TDp/2MqaBb3UFUtqbGIlvXaVMaa3hqfhadFWmzLqsIrxIfJUpJIvLAiOxRaNA
    ucx3RrraDwq0NIAZi4/v70g0ND+yLkO3QIuzjpHYnCwVIgwoXoh5uBUoeaQw1vVQKhDTJGA0PkdK
    zxTdmD8U8/Ivzk6WGXyUa5w9uNSCyfp4C3LrLNGCY3HS7HYFCvcSRvzkSaVeHM68DdN7XwZPeIWt
    HrvJxcC34fU72th66vT13thXabtmegd15PLfo4PfZOw/BKgIte8PAAA=
    '

    {
        "$INSTALLER" install -y $PACKAGE_BIND

        printf '%s' $PACKED_CONFIG | base64 -d | gunzip > "$CONFIG_RESOLVER"
        mkdir -p /var/log/named
        touch "$CONFIG_RESOLVER_FORWARD" "$CONFIG_RESOLVER_LOCAL"
        systemctl restart "$SERVICE_BIND"
    } 2>&1 | show_output 'Installing local DNS resolver'
}

# install Postfwd
# parameters:
# none
# return values:
# none
install_postfwd() {
    declare -r POSTFWD_USER='postfwd'

    {
        groupadd "$POSTFWD_USER"
        useradd -g "$POSTFWD_USER" "$POSTFWD_USER"

        mkdir -p /usr/local/postfwd/sbin
        "$WGET" "$INSTALL_POSTFWD_LINK" -O - > /usr/local/postfwd/sbin/postfwd
        chmod +x /usr/local/postfwd/sbin/postfwd
        "$WGET" https://raw.githubusercontent.com/postfwd/postfwd/master/bin/postfwd-script.sh -O - | sed "s/nobody/$POSTFWD_USER/" | sed '1a # chkconfig: - 85 15' > /etc/init.d/postfwd
        "$WGET" https://raw.githubusercontent.com/postfwd/postfwd/master/etc/postfwd.cf.sample -O - > "$CONFIG_POSTFWD"
        chmod +x /etc/init.d/postfwd

        "$INSTALLER" install -y $PACKAGE_POSTFWD

        systemctl daemon-reload
        systemctl start postfwd
        enable_service postfwd
    } 2>&1 | show_output 'Installing Postfwd'
}

# install Spamassassin
# parameters:
# none
# return values:
# none
install_spamassassin() {
    declare -r PACKED_CONFIG='
    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
    nqZP2brq06u9/PFttX3K19r3nEJ2Cf6mb7r12PtuzZtV27I4u8/XZ2/clc1blW/WpXF6St+7WuZF
    3bDw4lW/viFbL/PHX6OiE8PabNdV8cOI6NyVx42YvYjW3Kh9Se10J7XeQK2AvqO2IL2GE76kD0jd
    nvK35Vlp/P7fxtkHy/+Jk5+J+fPa/+n4H896y6x8KPL7TJXA7s+WRvVcbLZPzwbV6+sP46HpZG2Z
    yl2adaHrIuyybX38rw82au0Yu2+aF2VlbPdv7c1u6Pt4NtL1id0gfFgphRmEcXL8nPwi27nOijKH
    NVVs108le6t3pz7SPO0bXl2zegrb09iAqBrpW5Cn5v22zJgOU/rTP87a7qU1/VoZ2fe8rMpLF/48
    Tdbl9r5WetuN1PEKN9IvTqP8aZ1W2yLr3W+WP4Sb5OD97F/3H+D7nzP4PZnD74xO/H35nD5Wb48r
    GHql++4bp5af4eMqe8r+2pZp9Zdw4apI1y/ZWvhuAn89ltv14//+z3P+9JLl1U8MzkiiapH8Vx//
    dX+W916zKjX2o9H4/Q/6afnb3/Q613zPVCp9T7X28bAC2jqgMZZ6BXT12Khf6foV9nyU58tvn9Py
    edTLv9O/l+vyfmXMkM8K4M5t/bgUbB9ZkT/0a6YPe0+/NrXmI/PZt3R1yXYmUt/y4e8i8vePvepx
    lT6V+vuhgd3Oq73ObbxjoeO+c8teT9uB+fc+u9B/Tdd5tVV7Lt+g6bmISD2X75d7Ll8Xen7Cdz1C
    AtWomjr9LKVvK79uYG39qEdwwg9BulEzggMBvT/huy/dS3t/wndfui70/hfu6cZqky4bW4Zf386H
    gz5Ea73u/SPOvldWWvU2L2SVrp+2EAWVRrY2lpmxXjWzlPg3pk9fNHdNf5bQJ10Fj0kD0F8xwqNW
    avQMm8xDXjxsczAy7h/72Pxm7sTosLkYm7WeozE8z7ZxtNDPzLc5jZC5Xe1cbrpNHstZj+jfnmsa
    7mhXEClztP/N/0lAMF+Za3sFl66+o0IVYWp+hcGcGBVEhfcr+n9p2FTGW1Y8bgpwcg/Zpbhc5nk1
    LbI/SrxdZXH+Co5E81X/7fX/AFKc2bHDRAAA
    '
    declare -r PACKED_DEFAULT='
    H4sIAJTW8V4AA11TXWvbQBB816/YOg9pwZITaF4Cpri20xpSO8SBUOjLWXe2Lj7difuwq3+fWVmm
    TkEgpNudnZmdu6KRiuVIqq1IJo5CI2oRAh5tsyuaJVsKSw/aSiPaDH9eJ8/LxfLHPTVGiaDIKyHp
    eT6Z/ZoX3Cxpo7bOK0pA2BXoeKkUPmvR4oSCKpPXsSWvwz4UjLjYUuvS9bmFQhuiAs7nnhMBjt4U
    GKkvQ4qVovly8v1xPgNYjNyhA2CsiwBQsqCFBYCQQ1JWbAxmnmi1qAsJ9feoPg0po7ksOgsvgvIH
    XSrUTSthd4qio8HtgF8fMJ3tgcI/7gdtdbzPeo7jW5a4aqJ2llmuFVth+35W1jiMZEh3KirYMMpl
    /w3SJFJ0tYi6FMa0JKSESoZdA2TSc2btqKTGs/17JlM7qcyQgmPjS4GDZD7Rb5fIKiUhBhC12ENM
    gvl5Xou/eVlpI73qxrKjsJhVC9vGijErvcM6sQVouBsCIFmD1fAGaW/dkY6ViOd9StdFIFs9vSxW
    y/V4kOcl8hJVziwDRurm8NVZiPpv+h1+QJC3oj57/SfLf9KocrXqQipHlAfQ12bAVjxpuKkNr+y1
    y1uoXDKy7z0icop0DPS0mLEeLv3WJ4+d62KVJ3IeABej+x2IjTsozh67Au8CY8BUxu3igHBFFs6N
    nPkV8PxRB3UKLEeCQul1E+mojemsRX/XC6hQpdhTle5oiww0HxaP8/FgdBB+5JM9aS4aLTu5a6zF
    IqFk1EEZcttTd3a1XEzn7DMfns5u77qOqXf2zW363suVbjD75iLaTLhENaG8K/yQvtRILJBv0MWF
    uQ7kE3LAF0KA2K6KKN2IgJs5fV4txzfZOwSW0ItoBAAA
    '
    declare -r PACKED_WHITELIST='
    H4sIAOLW8V4AAz3LSwrDMAwE0L1PIci6iuWCky57kuDGamrqD/hDrl+7hSJmM280QTCxGQ/ny1X2
    rlQXDzHBPRb38DzUHGyF+Pv2zClA5LqneOkpzY8f3HvbSgqBM1oWouZWKtutL8+U3wVoUUgaJcqZ
    FJDE780r0G3A+hMNdJVIq8SFkJQWHziaE0qiAAAA
    '
    {
        if [ "$DISTRO" = 'suse' ]; then
            zypper ar -f https://download.opensuse.org/repositories/devel:/languages:/perl/"$(grep 'PRETTY_NAME' /etc/os-release | awk -F= '{print $2}' | sed 's/"//g' | sed 's/ /_/g')"/devel:languages:perl.repo
            zypper --gpg-auto-import-keys refresh
        fi

        "$INSTALLER" install -y $PACKAGE_SPAMASSASSIN

        grep -q '^spamd:' /etc/group || addgroup spamd
        grep -q '^spamd:' /etc/passwd || adduser --system --disabled-login --ingroup spamd spamd

        [ -d /home/spamd/.spamassassin ] || mkdir /home/spamd/.spamassassin
        [ -d /home/spamd/bayes_db ] || mkdir /home/spamd/bayes_db

        chown spamd:spamd -R /home/spamd

        [ -d "$DIR_CONFIG_SPAMASSASSIN" ] || mkdir "$DIR_CONFIG_SPAMASSASSIN"

        "$WGET" http://svn.apache.org/repos/asf/spamassassin/trunk/masses/plugins/HitFreqsRuleTiming.pm -O "$DIR_CONFIG_SPAMASSASSIN"/HitFreqsRuleTiming.pl
        "$WGET" https://mailfud.org/iXhash2/iXhash2-2.05.tar.gz -O - | tar -O -xz iXhash2-2.05/iXhash2.pm > "$DIR_CONFIG_SPAMASSASSIN"/iXhash2.pm

        printf '%s' $PACKED_CONFIG | base64 -d | gunzip > "$CONFIG_SPAMASSASSIN_LOCAL"
        printf '%s' $PACKED_DEFAULT | base64 -d | gunzip > /etc/default/spamassassin
        printf '%s' $PACKED_WHITELIST | base64 -d | gunzip > "$CONFIG_SPAMASSASSIN_WHITELIST"

        if [ -f /etc/spamassassin/v320.pre ]; then
            sed -i -E 's/^# (loadplugin Mail::SpamAssassin::Plugin::Shortcircuit)/\1/' /etc/spamassassin/v320.pre
            sed -i -E 's/^# (loadplugin Mail::SpamAssassin::Plugin::Rule2XSBody)/\1/' /etc/spamassassin/v320.pre
        else
            echo 'loadplugin Mail::SpamAssassin::Plugin::Shortcircuit'$'\n''loadplugin Mail::SpamAssassin::Plugin::Rule2XSBody' > /etc/spamassassin/v320.pre
        fi

        if [ -f /etc/spamassassin/v310.pre ]; then
            sed -i -E 's/^#(loadplugin Mail::SpamAssassin::Plugin::AWL)/\1/' /etc/spamassassin/v310.pre
            sed -i -E 's/^#(loadplugin Mail::SpamAssassin::Plugin::TextCat)/\1/' /etc/spamassassin/v310.pre
        else
            echo 'loadplugin Mail::SpamAssassin::Plugin::AWL'$'\n''loadplugin Mail::SpamAssassin::Plugin::TextCat' > /etc/spamassassin/v310.pre
        fi

        echo 'loadplugin Mail::SpamAssassin::Plugin::iXhash2 /etc/spamassassin/iXhash2.pm' >  /etc/spamassassin/local.pre

        [ -f '/etc/cron.daily/spamassassin' ] && rm -f /etc/cron.daily/spamassassin

        "$WGET" https://www.pccc.com/downloads/SpamAssassin/contrib/KAM.cf -O /etc/spamassassin/KAM.cf

        cpan Digest::SHA1

        spamassassin_restart
    } 2>&1 | show_output 'Installing Spamassassin'
}

# install Rspamd
# parameters:
# none
# return values:
# none
install_rspamd() {
    declare -r PACKED_PATCH='
    H4sIAEGp9F4AA51TXW+bMBR9bn7FFZNVwOABSUjGxJZf0Je+TFo35GCHoIGJbFO1L/vtMyk0CVmb
    ZZYx+OOee871wfd9UDtaU6VMLwWpWnoTBVHgB7EfzSAMk+kiCUMym80X8TIKY8BmN5hgjN8JnEM4
    T6afkmhKgvkyjJfTOOoDVyvwwzj0ohBw9w4XsFpNYGhVk9MK1HO9bip1tmwSZipvJD/sbBoJCkoB
    W04Zl0lRU51vbev7zwf5IH5gywHWTHw4auUGlJalKMimFMxWHtzeG+QEiAsfYU6CWwf0lovTqIHE
    jmrNpch6jpCCZe/DifsZHBv5XxEzHRHEHLvDQyRwrDHWQYoB6NkUql13bEYZPLBQZDkTfEHDN+R3
    PMyoqW5VAugee7DPMQjCpyTeFPQOFEptxHCnDjtdwTRXWqU2cT2jFptzDnGtcaIr1YZGLYyotjRr
    dVkRxtdtUduyrTi580BT9ctoR4Zjl4RBxxuqUnBDWt16sD9YNUW2k3xTPnlHXJzTS+GCXfTJqDBX
    G4W4IwTi7guIUsfsOTZtdVNxKgVKifvIpSob8/nipu4xZ86t9Ir/Hz66MhxNz6/mDYBDlLLMOI7r
    qn06OUxN4XUj2nrNpX10XfAFAqCCwYch5bAwzH+bGotGcKu/luNSGdC9F/iTNuk4gzSFDa0U73+N
    m4tHTvjnTV03gjyXvGKZ5KqttP1ixg7Cg1f9x377G4KijzzLab7lfTwrC2OJf8Xhht7kD6Fq9FLH
    BQAA
    '
    declare CODENAME

    {
        if [ "$DISTRO" = 'redhat' ]; then
            curl https://rspamd.com/rpm-stable/centos-7/rspamd.repo > /etc/yum.repos.d/rspamd.repo

            rpm --import https://rspamd.com/rpm-stable/gpg.key

            yum update -y
            yum install -y redis rspamd patch
        elif [ "$DISTRO" = 'debian' ]; then
            apt install -y lsb-release

            CODENAME="$(lsb_release -c -s)"

            "$WGET" https://rspamd.com/apt-stable/gpg.key -O - | apt-key add -

            echo "deb [arch=amd64] http://rspamd.com/apt-stable/ $CODENAME main" > /etc/apt/sources.list.d/rspamd.list
            echo "deb-src [arch=amd64] http://rspamd.com/apt-stable/ $CODENAME main" >> /etc/apt/sources.list.d/rspamd.list

            apt update
            apt install -y redis-server rspamd
        elif [ "$DISTRO" = 'suse' ]; then
            zypper ar -f https://download.opensuse.org/repositories/server:/mail/"$(grep 'PRETTY_NAME' /etc/os-release | awk -F= '{print $2}' | sed 's/"//g' | sed 's/ /_/g')"/server:mail.repo
            zypper --gpg-auto-import-keys refresh
            zypper install -y redis rspamd patch
        fi

        echo 'read_servers = "127.0.0.1";' > "$CONFIG_RSPAMD_REDIS"
        echo 'write_servers = "127.0.0.1";' > "$CONFIG_RSPAMD_REDIS"
        echo 'bind_socket = "127.0.0.1:11333";' > "$CONFIG_RSPAMD_NORMAL"
        echo 'bind_socket = "0.0.0.0:11334";'$'\n''secure_ip = "127.0.0.1";' > "$CONFIG_RSPAMD_CONTROLLER"
        echo 'bind_socket = "127.0.0.1:11332";'$'\n''upstream {'$'\n\t''local {'$'\n\t\t''hosts = "127.0.0.1";'$'\n\t\t''default = true;'$'\n\t''}'$'\n''}' > "$CONFIG_RSPAMD_PROXY"
        echo 'bind_socket = "127.0.0.1:11335";'$'\n''allow_update [ "127.0.0.1" ]' > "$CONFIG_RSPAMD_FUZZY"
        echo 'type = "syslog";'$'\n''facility = "mail";' > "$CONFIG_RSPAMD_LOGGING"

        printf '%s' $PACKED_PATCH | base64 -d | gunzip | patch /usr/share/rspamd/lualib/lua_scanners/spamassassin.lua

        rspamd_restart
    } 2>&1 | show_output 'Installing Rspamd'
}

# install Pyzor
# parameters:
# none
# return values:
# none
install_pyzor() {
    pip3 install pyzor 2>&1 | show_output 'Installing Pyzor'
}

# install Razor
# parameters:
# none
# return values:
# none
install_razor() {
    {
        if [ "$DISTRO" = 'redhat' ] || [ "$DISTRO" = 'suse' ]; then
            cpan -f Razor2:Client:Agent
        elif [ "$DISTRO" = 'debian' ]; then
            apt install -y razor
        fi
    } 2>&1 | show_output 'Installing Razor'
}

# install Oletools
# parameters:
# none
# return values:
# none
install_oletools() {
    {
        pip3 install -U https://github.com/decalage2/oletools/archive/master.zip
        pip3 install python-magic
        echo 'OLEFY_BINDADDRESS=127.0.0.1' > /etc/olefy.conf
    } 2>&1 | show_output 'Installing Oletools'
}

# install FuzzyOCR
# parameters:
# none
# return values:
# none
install_fuzzyocr() {
    {
        "$INSTALLER" install -y fuzzyocr
    } 2>&1 | show_output 'Installing FuzzyOCR'
}

# install ClamAV
# parameters:
# none
# return values:
# none
install_clamav() {
    declare -r PACKED_CONFIG='
    H4sIAJxd514AA2VVTW/jNhC961cQ2HMj2UbSXhVZ6RqQVqql7Ba9FDQ5lohQpEFSziq/vkN92Zsi
    QOx5HA5n5r0ZfyklUAvEAOUk7K0JbUsNhFyzkEna0etvnEKnVXhM432ePuzhJKh6aD7IWRvCwVEh
    bVAnZaXZGziy220ib8acG7LZ/v4Q4d8m+EJq6C7aUDPshQHmtBmIsERpRyxec5oIZzHemfbSkdB1
    F9KCAX/Q0Tcg+grGCC5Ug7FcC6vru3AtAXUVRqsOlCNXagQ9SbCkzsv94RjiR1ineUku2lqBJ8Gr
    BUOm8oKKUZVjEcSZHkYrNqwVV5iA2XiWWF6qmBkuDjg5U2khyOnPtZgjsN5YoRXZPAYvWkr9vp5V
    QyeFerPzten0RUj4dHBEEmrRge4d2fwR+fh165mx2ElvJVopDImv/NVDDxmoBovHBzPdVIOVupkj
    oX3Ujrq5CDRfKBNSuIFkxZ//ZkUSZ08eTpB+dbv0HcxJoxwmoDQgew6p8u1EqhYgVlQOH2C+0Q5I
    gm2Mvwd76ugJlXRjN0QiQilOs46C4nwWTFC5eBZKDvNDFchz0gJ7I7unKMIGGWiM7tXSaBRdv5Tm
    GSrTqS5sSdqdgHPgCG2ifDwtsnR7Y7Pcv9yMr3WerVe98U2bjkrxAePtFaxpY8l2BCpmxMXd/B5H
    9B9xqYcLHFlDNtOr1Y/5nfSncIUqinxpK9ArrOr3tC98x7LRBuXbCbYHNxF7yzXN5oAHLmGRxS4K
    EoMyHsMM1kFnJ6eyFbbF6ahEo6jrDXzGMeLrMfuExvKdDnYUd1VlubAddaxd6P+/UyI1fVuOqXHC
    p3xQDoyd018I8+WUr/E9ad6fyhyspc3ag6/QG2GdYKMLagc4KLYosMJsma+Ge9XcmjSdJrrrqOL3
    Y4P9qUDx5/68INtoHKRxYJDkCPlx6IERl2gHddZTW7xyxjpzyrDLK004rvgv973xaU7OqFIGtd4L
    u3QEv/pJScC4Sc2/wpS1cNscPpDPEUc7iqYcRxlNWpzEOO4ID2wn1d0tmafl3Hrv6f7KiCWPI3Bg
    +H2cjCgok2M6VpCJTrj5kgcx6B3+GK2+vz7vk/s7z/ZFUt3N049yt84TBhptzA15A9ohNq8oH8Av
    IQw47wXdzHth/nhAxLuMLVmXFvq/Kk/IbUV5zPfK5xUFzwOSqPl8ZbEq3ye/7GrTW+dHAvh6uAjj
    aexAoWLGUJL35WKyC4yKvOKPim857r//AAukEgEuBwAA
    '

    {
        "$INSTALLER" install -y clamav clamav-daemon clamav-unofficial-sigs
        printf '%s' $PACKED_CONFIG | base64 -d | gunzip > /etc/clamav/clamd.conf
        systemctl clamav-daemon restart
    } 2>&1 | show_output 'Installing ClamAV'
}

# install Sophos AV
# parameters:
# none
# return values:
# none
install_sophosav() {
    declare -r FILE_AV='sav-linux-free-9.tgz'
    declare -r FILE_INTERFACE='savdi-linux-64bit.tar'
    declare -r DIR_TMP='/tmp/TMPsophosav'
    declare -r PACKED_CONFIG='
    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
    pHYp4hIAAA==
    '
    declare -r PACKED_SCRIPT='
    H4sIAL226F4AA22QPW7DMAyFd51CQ1dFJ9Dgwi3ioYURJ+1geFBlKiWiH0Oi3Pr2VVN4K8CF5Hsf
    iTdeAtLEWsgm4UIYgxri8hkzH5o33m5BezS8CwTJagO81eBjYI2tAxWAvmK6HUinKxBj4wBpRQMT
    O28LKFt3GK6s79pndKDkqpNMJcis1xnnw4Ize/oGM1Q/KVlyki4a7eQH7houahkugczuMjFYLiz/
    h8ZFvgNP4KKe1Z1zQ+e4OF56/vDSdK/1F3aCfL8Yg7AaXUnA+oSrJjj7RVEqv30kMDRsmcArW5zb
    R8fo4U/Dxi5UkHMTe9c1oPlxU744QlEypD2UH/vzva1hAQAA
    '
    declare INSTALLER_AV INSTALLER_INTERFACE

    INSTALLER_AV=""

    if [ -f "/root/$FILE_AV" ]; then
        INSTALLER_AV="/root/$FILE_AV"
    else
        exec 3>&1
        INSTALLER_AV=$(get_file 'Select Sophos AV installer' '/root' 1)
        exec 3>&-
    fi

    if ! [ -z "$INSTALLER_AV" ]; then
        INSTALLER_INTERFACE=""

        if [ -f "/root/$FILE_INTERFACE" ]; then
            INSTALLER_INTERFACE="/root/$FILE_INTERFACE"
        else
            exec 3>&1
            INSTALLER_INTERFACE=$(get_file 'Select Sophos AV interface installer' '/root' 1)
            exec 3>&-
        fi

        if ! [ -z "$INSTALLER_INTERFACE" ]; then
            show_wait

            mkdir -p "$DIR_TMP"

            tar -xzf "$INSTALLER_AV" -C "$DIR_TMP"
            clear
            "$DIR_TMP"/sophos-av/install.sh

            {
                "$INSTALLER" install -y file

                ln -s /opt/sophos-av/lib64/libsavi.so.3 /usr/local/lib/libsavi.so.3
                ln -s /opt/sophos-av/lib64/libssp.so.0 /usr/local/lib/libssp.so.0

                tar -xf "$INSTALLER_INTERFACE" -C "$DIR_TMP"
                "$DIR_TMP"/savdi-install/savdi_install.sh
                cp "$DIR_TMP"/savdi-install/savdid /usr/local/bin/

                rm -rf "$DIR_TMP"

                printf '%s' $PACKED_CONFIG | base64 -d | gunzip > /etc/savdid.conf
                printf '%s' $PACKED_SCRIPT | base64 -d | gunzip > /etc/systemd/system/savdid.service

                systemctl daemon-reload
                systemctl enable sav-update.service
                systemctl start sav-update.service
                systemctl enable savdid
                systemctl start savdid
            } 2>&1 | show_output 'Installing Sophos AV'
        fi
    fi
}

# install Fail2ban
# parameters:
# none
# return values:
# none
install_fail2ban() {
    {
        [ -f /etc/apt/preferences.d/apt-listbugs ] && rm -f /etc/apt/preferences.d/apt-listbugs
        "$INSTALLER" install -y fail2ban
    } 2>&1 | show_output 'Installing Fail2ban'
}

# install OpenDKIM
# parameters:
# none
# return values:
# none
install_dkim() {
    "$INSTALLER" install -y opendkim 2>&1 | show_output 'Installing OpenDKIM'
}

# install SPF-check
# parameters:
# none
# return values:
# none
install_spf() {
    "$INSTALLER" install -y $PACKAGE_SPF 2>&1 | show_output 'Installing SPF-check'
}

# install Let's Encrypt Certificate
# parameters:
# none
# return values:
# none
install_acme() {
    declare -r HOST_NAME="$(hostname -f)"
    declare -r DIR_CERT="/root/.acme.sh/$HOST_NAME"
    declare -r DIR_SSL='/etc/ssl'
    declare -r PACKED_SCRIPT='
    H4sIADN+6F4AA1NW1E/KzNNPSizO4OLSLwaxMwtKEpNyUosVdD0VPP0CQkMUDBV0CxRKkgsUdHMh
    lG5KQX5RiYKFgYJuloKjs7NrQAiXflF+fom+XmJybqpecYY+lAaqTS7KzwNSGfm5qQqoijAsdIFa
    SIR1AL1vT3i5AAAA
    '

    {
        "$INSTALLER" install -y socat
        "$WGET" -O - https://get.acme.sh 2>/dev/null | sh
        /root/.acme.sh/acme.sh --uninstall-cronjob
        iptables -I INPUT 1 -p tcp -m tcp --dport 80 -j ACCEPT
        /root/.acme.sh/acme.sh --issue --standalone -d "$HOST_NAME"
        iptables -D INPUT -p tcp -m tcp --dport 80 -j ACCEPT

        if [ -f "$DIR_CERT/$HOST_NAME.cer" ]; then
            cp -f "$DIR_CERT/$HOST_NAME.cer" "$DIR_SSL/$HOST_NAME.cer"
            cp -f "$DIR_CERT/$HOST_NAME.key" "$DIR_SSL/$HOST_NAME.key"
            cp -f "$DIR_CERT/fullchain.cer" "$DIR_SSL/fullchain.cer"
            printf '%s' $PACKED_SCRIPT | base64 -d | gunzip | sed "s/__HOST_NAME__/$HOST_NAME/g" > /root/.acme.sh/get_cert.sh
            chmod +x /root/.acme.sh/get_cert.sh
            add_crontab '@daily /root/.acme.sh/get_cert.sh > /dev/null'
        fi
    } 2>&1 | show_output "Installing Let's Encrypt certificate"
}

# install Logwatch
# parameters:
# none
# return values:
# none
install_logwatch() {
    "$INSTALLER" install -y logwatch 2>&1 | show_output 'Installing Logwatch'
}

# install log-manager
# parameters:
# none
# return values:
# none
install_logmanager() {
    declare -r PACKED_SCRIPT='
    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
    n8cWPz5kIAAA
    '

    printf '%s' $PACKED_SCRIPT | base64 -d | gunzip > "$CRON_LOGMANAGER"
    chmod 700 "$CRON_LOGMANAGER"
    "$CRON_LOGMANAGER"
}

# install reboot alert
# parameters:
# none
# return values:
# none
install_reboot() {
    declare -r PACKED_SCRIPT='
    H4sIABqv+F0AA1NW1E/KzNMvzuBKTc7IV1BPzEksylVIK8rPVYiP9/APDon3c/R1jY9XV6hRyE3M
    zFHQLVZQD64sLknNVShKTcrPL1HIz0NXWgQU5gIA+EhgLFoAAAA=
    '

    mkdir -p "$(dirname "$SCRIPT_REBOOT")"
    printf '%s' $PACKED_SCRIPT | base64 -d | gunzip | sed "s/__HOST_NAME__/$(hostname -f)/g" > "$SCRIPT_REBOOT"

    add_crontab "$CRONTAB_REBOOT"
}

# install SNMP support
# parameters:
# none
# return values:
# none
install_snmp() {
    "$INSTALLER" install -y $PACKAGE_SNMP 2>&1 | show_output 'Installing SNMP support'
}

# setup cluster peer
# parameters:
# none
# return values:
# none
install_cluster() {
    declare -r SSH_KEY="$HOME/.ssh/id_ed25519"
    declare IP_ADDRESS RET_CODE SSH_PORT PASSWORD

    exec 3>&1
    IP_ADDRESS="$(get_input 'Peer IP address' 'Enter peer IP address')"
    RET_CODE="$?"
    exec 3>&-

    if [ "$RET_CODE" = 0 ]; then
        exec 3>&1
        SSH_PORT="$(get_input 'Peer SSH port' 'Enter peer SSH port' '22')"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            exec 3>&1
            PASSWORD="$(get_input 'SSH root password' 'Enter SSH root password (empty for key auth)')"
            RET_CODE="$?"
            exec 3>&-

            if [ "$RET_CODE" = 0 ]; then
                [ -f "$SSH_KEY" ] || ssh-keygen -t ed25519 -N '' -f "$SSH_KEY" &>/dev/null

                if [ -z "$PASSWORD" ]; then
                    ssh-copy-id -p "$SSH_PORT" -o 'StrictHostKeyChecking=accept-new' -i "$SSH_KEY" "root@$IP_ADDRESS" &>/dev/null
                else
                    which sshpass &>/dev/null || "$INSTALLER" install -y sshpass &>/dev/null

                    sshpass -p "$PASSWORD" ssh-copy-id -p "$SSH_PORT" -o 'StrictHostKeyChecking=accept-new' -i "$SSH_KEY" "root@$IP_ADDRESS" &>/dev/null
                fi

                if [ "$?" = 0 ]; then
                    sed -i '/^Host mx$/,/^$/d' "$CONFIG_SSH"
                    echo $'\n''Host mx'$'\n\t'"HostName $IP_ADDRESS"$'\n\t''User root'$'\n\t'"Port $SSH_PORT"$'\n\t'"IdentityFile $SSH_KEY"$'\n' >> "$CONFIG_SSH"

                    IP_ADDRESS="$(hostname -I | awk '{print $1}')"

                    ssh mx "[ -f '$SSH_KEY' ] || ssh-keygen -t ed25519 -N '' -f '$SSH_KEY' &>/dev/null; sed -i '/^Host mx$/,/^$/d' '$CONFIG_SSH'; echo $'\n''Host mx'$'\n\t''HostName $IP_ADDRESS'$'\n\t''User root'$'\n\t''Port $SSH_PORT'$'\n\t''IdentityFile $SSH_KEY' >> '$CONFIG_SSH'; ssh-keyscan -H $IP_ADDRESS 2>/dev/null | grep ecdsa-sha2-nistp256 >> '$HOME/.ssh/known_hosts'; cat '$SSH_KEY.pub'" >> "$HOME/.ssh/authorized_keys"
                fi
            fi
        fi
    fi
}

# determine installed package version
# parameters:
# package name
# return values:
# installed package version
version_current() {
    declare PACKAGE_INFO

    if [ "$DISTRO" = 'redhat' ]; then
        PACKAGE_INFO="$(yum -q info "$1" | sed -n '/^Installed Packages$/,/^$/p')"

        [ -z "$PACKAGE_INFO" ] || echo "$(echo "$PACKAGE_INFO" | grep -E '^(Version)' | awk '{print $3}').$(echo "$PACKAGE_INFO" | grep -E '^(Release)' | awk '{print $3}')"
    elif [ "$DISTRO" = 'debian' ]; then
        apt-cache policy "$1" | sed -n '2p' | sed -E 's/^.+\s+//'
    fi
}

# determine available package version
# parameters:
# package name
# return values:
# available package version
version_available() {
    declare PACKAGE_INFO

    if [ "$DISTRO" = 'redhat' ]; then
        PACKAGE_INFO="$(yum -q info "$1" | sed -n '/^Available Packages$/,/^$/p')"

        [ -z "$PACKAGE_INFO" ] || echo "$(echo "$PACKAGE_INFO" | grep -E '^(Version)' | awk '{print $3}').$(echo "$PACKAGE_INFO" | grep -E '^(Release)' | awk '{print $3}')"
    elif [ "$DISTRO" = 'debian' ]; then
        apt-cache policy "$1" | sed -n '3p' | sed -E 's/^.+\s+//'
    fi
}

# select feature to install in dialog menu
# parameters:
# none
# return values:
# none
menu_install() {
    declare -a MENU_INSTALL
    declare NAME_PACKAGE VERSION_CURRENT VERSION_AVAILABLE DIALOG_RET RET_CODE

    while true; do
        MENU_INSTALL=()

        for FEATURE in "${INSTALL_FEATURE[@]}"; do
            "check_installed_${FEATURE}" && MENU_INSTALL+=("$FEATURE" "$(eval echo \"\$LABEL_INSTALL_${FEATURE^^}\") (installed)" 'off') || MENU_INSTALL+=("$FEATURE" "$(eval echo \"\$LABEL_INSTALL_${FEATURE^^}\")" 'off')
        done

        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --no-tags --extra-button --extra-label 'Help' --title '' --checklist '' 0 0 0 "${MENU_INSTALL[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ] && ! [ -z "$DIALOG_RET" ]; then
            for FEATURE in $DIALOG_RET; do
                if "check_installed_$FEATURE"; then
                    NAME_PACKAGE="$(eval echo \"\$INSTALL_${FEATURE^^}_PACKAGE\")"

                    if [ -z "$NAME_PACKAGE" ]; then
                        get_yesno "'$(eval echo \"\$LABEL_INSTALL_${FEATURE^^}\")' already installed. Re-install?"

                        [ "$?" = 0 ] && "install_$FEATURE"
                    else
                        VERSION_CURRENT="$(version_current "$NAME_PACKAGE")"
                        VERSION_AVAILABLE="$(version_available "$NAME_PACKAGE")"

                        if [ -z "$VERSION_AVAILABLE" ] || [ "$VERSION_AVAILABLE" = "$VERSION_CURRENT" ]; then
                            get_yesno "'$(eval echo \"\$LABEL_INSTALL_${FEATURE^^}\")' already installed. Re-install?"

                            [ "$?" = 0 ] && "install_$FEATURE"
                        else
                            get_yesno "Update '$(eval echo \"\$LABEL_INSTALL_${FEATURE^^}\")' to version '$VERSION_AVAILABLE'?"

                            if [ "$?" = 0 ]; then
                                show_wait

                                "$INSTALLER" update -y "$NAME_PACKAGE" 2>&1 | show_output "Updating $(eval echo \"\$LABEL_INSTALL_${FEATURE^^}\")"
                            fi
                        fi
                    fi
                else
                    "install_$FEATURE"
                fi
            done
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$HELP_INSTALL_FEATURE"
        else
            break
        fi
    done
}

# select Postfix option in dialog menu
# parameters:
# none
# return values:
# none
menu_postfix() {
    declare -r TAG_FEATURE='postfix_feature'
    declare -r TAG_SERVER='postfix_server'
    declare -r TAG_CLIENT='postfix_client'
    declare -r TAG_INFO='postfix_info'
    declare -r TAG_SYNC='postfix_sync'
    declare -r LABEL_FEATURE='Settings'
    declare -r LABEL_SERVER='Server maps'
    declare -r LABEL_CLIENT='Client maps'
    declare -r LABEL_INFO='Info & Stats'
    declare -r LABEL_SYNC='Sync cluster'
    declare -a MENU_POSTFIX

    MENU_POSTFIX=()
    MENU_POSTFIX+=("$TAG_FEATURE" "$LABEL_FEATURE")
    MENU_POSTFIX+=("$TAG_SERVER" "$LABEL_SERVER")
    MENU_POSTFIX+=("$TAG_CLIENT" "$LABEL_CLIENT")
    MENU_POSTFIX+=("$TAG_INFO" "$LABEL_INFO")
    check_installed_cluster && MENU_POSTFIX+=("$TAG_SYNC" "$LABEL_SYNC")

    while true; do
        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --no-tags --extra-button --extra-label 'Help' --title 'Postfix' --menu '' 0 0 0 "${MENU_POSTFIX[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            "$DIALOG_RET"
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$HELP_POSTFIX"
        else
            break
        fi
    done
}

# select local DNS resolver option in dialog menu
# parameters:
# none
# return values:
# none
menu_resolver() {
    declare -r TAG_CONFIG='resolver_config'
    declare -r TAG_FORWARD='resolver_forward'
    declare -r TAG_LOCAL='resolver_local'
    declare -r TAG_SYNC='resolver_sync'
    declare -r LABEL_CONFIG='Config files'
    declare -r LABEL_FORWARD='Forward zones'
    declare -r LABEL_LOCAL='Local zones'
    declare -r LABEL_SYNC='Sync cluster'
    declare -a MENU_RESOLVER

    MENU_RESOLVER=()
    MENU_RESOLVER+=("$TAG_CONFIG" "$LABEL_CONFIG")
    MENU_RESOLVER+=("$TAG_FORWARD" "$LABEL_FORWARD")
    MENU_RESOLVER+=("$TAG_LOCAL" "$LABEL_LOCAL")
    check_installed_cluster && MENU_RESOLVER+=("$TAG_SYNC" "$LABEL_SYNC")

    while true; do
        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --no-tags --extra-button --extra-label 'Help' --title 'Local DNS resolver' --menu '' 0 0 0 "${MENU_RESOLVER[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            "$DIALOG_RET"
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$HELP_RESOLVER"
        else
            break
        fi
    done
}

# select Postfwd option in dialog menu
# parameters:
# none
# return values:
# none
menu_postfwd() {
    declare -r TAG_CONFIG='postfwd_config'
    declare -r TAG_SYNC='postfwd_sync'
    declare -r LABEL_CONFIG='Config files'
    declare -r LABEL_SYNC='Sync cluster'
    declare -a MENU_POSTFWD

    MENU_POSTFWD=()
    MENU_POSTFWD+=("$TAG_CONFIG" "$LABEL_CONFIG")
    check_installed_cluster && MENU_POSTFWD+=("$TAG_SYNC" "$LABEL_SYNC")

    while true; do
        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --no-tags --extra-button --extra-label 'Help' --title 'Postfwd' --menu '' 0 0 0 "${MENU_POSTFWD[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            "$DIALOG_RET"
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$HELP_POSTFWD"
        else
            break
        fi
    done
}

# select OpenDKIM option in dialog menu
# parameters:
# none
# return values:
# none
menu_dkim() {
    declare -r TAG_CONFIG='dkim_config'
    declare -r TAG_SYNC='dkim_sync'
    declare -r LABEL_CONFIG='Config files'
    declare -r LABEL_SYNC='Sync cluster'
    declare -a MENU_DKIM

    MENU_DKIM=()
    MENU_DKIM+=("$TAG_CONFIG" "$LABEL_CONFIG")
    check_installed_cluster && MENU_DKIM+=("$TAG_SYNC" "$LABEL_SYNC")

    while true; do
        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --no-tags --extra-button --extra-label 'Help' --title 'OpenDKIM' --menu '' 0 0 0 "${MENU_DKIM[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            "$DIALOG_RET"
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$HELP_DKIM"
        else
            break
        fi
    done
}

# select SPF-check option in dialog menu
# parameters:
# none
# return values:
# none
menu_spf() {
    declare -r TAG_CONFIG='spf_config'
    declare -r TAG_SYNC='spf_sync'
    declare -r LABEL_CONFIG='Config files'
    declare -r LABEL_SYNC='Sync cluster'
    declare -a MENU_SPF

    MENU_SPF=()
    MENU_SPF+=("$TAG_CONFIG" "$LABEL_CONFIG")
    check_installed_cluster && MENU_SPF+=("$TAG_SYNC" "$LABEL_SYNC")

    while true; do
        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --no-tags --extra-button --extra-label 'Help' --title 'SPF-check' --menu '' 0 0 0 "${MENU_SPF[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            "$DIALOG_RET"
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$HELP_SPF"
        else
            break
        fi
    done
}

# select Spamassassin option in dialog menu
# parameters:
# none
# return values:
# none
menu_spamassassin() {
    declare -r TAG_FEATURE='spamassassin_feature'
    declare -r TAG_CONFIG='spamassassin_config'
    declare -r TAG_INFO='spamassassin_info'
    declare -r TAG_SYNC='spamassassin_sync'
    declare -r LABEL_FEATURE='Settings'
    declare -r LABEL_CONFIG='Config files'
    declare -r LABEL_INFO='Info & Stats'
    declare -r LABEL_SYNC='Sync cluster'
    declare -a MENU_SPAMASSASSIN

    MENU_SPAMASSASSIN=()
    MENU_SPAMASSASSIN+=("$TAG_FEATURE" "$LABEL_FEATURE")
    MENU_SPAMASSASSIN+=("$TAG_CONFIG" "$LABEL_CONFIG")
    MENU_SPAMASSASSIN+=("$TAG_INFO" "$LABEL_INFO")
    check_installed_cluster && MENU_SPAMASSASSIN+=("$TAG_SYNC" "$LABEL_SYNC")

    while true; do
        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --no-tags --extra-button --extra-label 'Help' --title 'Spamassassin' --menu '' 0 0 0 "${MENU_SPAMASSASSIN[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            "$DIALOG_RET"
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$HELP_SPAMASSASSIN"
        else
            break
        fi
    done
}

# select Rspamd option in dialog menu
# parameters:
# none
# return values:
# none
menu_rspamd() {
    declare -r TAG_FEATURE='rspamd_feature'
    declare -r TAG_CONFIG='rspamd_config'
    declare -r TAG_INFO='rspamd_info'
    declare -r TAG_SYNC='rspamd_sync'
    declare -r LABEL_FEATURE='Settings'
    declare -r LABEL_CONFIG='Config files'
    declare -r LABEL_INFO='Info & Stats'
    declare -r LABEL_SYNC='Sync cluster'
    declare -a MENU_RSPAMD

    MENU_RSPAMD=()
    MENU_RSPAMD+=("$TAG_FEATURE" "$LABEL_FEATURE")
    MENU_RSPAMD+=("$TAG_CONFIG" "$LABEL_CONFIG")
    MENU_RSPAMD+=("$TAG_INFO" "$LABEL_INFO")
    check_installed_cluster && MENU_RSPAMD+=("$TAG_SYNC" "$LABEL_SYNC")

    while true; do
        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --no-tags --extra-button --extra-label 'Help' --title 'Rspamd' --menu '' 0 0 0 "${MENU_RSPAMD[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            "$DIALOG_RET"
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$HELP_RSPAMD"
        else
            break
        fi
    done
}

# select Fail2ban option in dialog menu
# parameters:
# none
# return values:
# none
menu_fail2ban() {
    declare -r TAG_CONFIG='fail2ban_config'
    declare -r TAG_JAIL='fail2ban_jail'
    declare -r TAG_SYNC='fail2ban_sync'
    declare -r LABEL_CONFIG='Config files'
    declare -r LABEL_JAIL='Jails'
    declare -r LABEL_SYNC='Sync cluster'
    declare -a MENU_FAIL2BAN

    MENU_FAIL2BAN=()
    MENU_FAIL2BAN+=("$TAG_CONFIG" "$LABEL_CONFIG")
    MENU_FAIL2BAN+=("$TAG_JAIL" "$LABEL_JAIL")
    check_installed_cluster && MENU_FAIL2BAN+=("$TAG_SYNC" "$LABEL_SYNC")

    while true; do
        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --no-tags --extra-button --extra-label 'Help' --title 'Fail2ban' --menu '' 0 0 0 "${MENU_FAIL2BAN[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            "$DIALOG_RET"
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$HELP_FAIL2BAN"
        else
            break
        fi
    done
}

# select addon in dialog menu
# parameters:
# none
# return values:
# none
menu_addon() {
    declare -a MENU_ADDON

    for TAG_ADDON in "${ADDON_CONFIG[@]}"; do
        "check_installed_$TAG_ADDON" && MENU_ADDON+=("$TAG_ADDON" "$(eval echo \"\$LABEL_ADDON_${TAG_ADDON^^}\")")
    done

    while true; do
        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --no-tags --extra-button --extra-label 'Help' --title 'Addon' --menu '' 0 0 0 "${MENU_ADDON[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            "menu_$DIALOG_RET"
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$HELP_ADDON"
        else
            break
        fi
    done
}

# select miscellaneous options in dialog menu
# parameters:
# none
# return values:
# none
menu_misc() {
    declare -r TAG_EDITOR='text_editor'
    declare -r TAG_EMAIL='email_addresses'
    declare -r TAG_ADMIN='admin_addresses'
    declare -r TAG_UPDATES='automatic_update'
    declare -r TAG_PWAUTH='password_auth'
    declare -r TAG_TSOCKS='tsocks_proxy'
    declare -r TAG_SNMP='snmp_support'
    declare -r TAG_CONNECTIONS='show_connections'
    declare -r TAG_FIREWALL='show_firewall'
    declare -r TAG_INSTALL='show_install'
    declare -r TAG_UPDATE='show_update'
    declare -r LABEL_EDITOR='Set text editor'
    declare -r LABEL_EMAIL='Set notification addresses'
    declare -r LABEL_ADMIN='Set admin addresses'
    declare -r LABEL_UPDATES='Automatic update'
    declare -r LABEL_PWAUTH='SSH password authentication'
    declare -r LABEL_TSOCKS='Tsocks proxy'
    declare -r LABEL_SNMP='SNMP support'
    declare -r LABEL_CONNECTIONS='Network connections'
    declare -r LABEL_FIREWALL='Firewall rules'
    declare -r LABEL_INSTALL='Install log'
    declare -r LABEL_UPDATE='Pending updates'
    declare -a MENU_MISC

    while true; do
        MENU_MISC=()
        MENU_MISC+=("$TAG_EDITOR" "$LABEL_EDITOR")
        MENU_MISC+=("$TAG_EMAIL" "$LABEL_EMAIL")
        MENU_MISC+=("$TAG_ADMIN" "$LABEL_ADMIN")
        if [ "$DISTRO" = 'debian' ]; then
            automatic_update_status && MENU_MISC+=("$TAG_UPDATES" "$LABEL_UPDATES (enabled)") || MENU_MISC+=("$TAG_UPDATES" "$LABEL_UPDATES (disabled)")
        fi
        pwauth_status && MENU_MISC+=("$TAG_PWAUTH" "$LABEL_PWAUTH (enabled)") || MENU_MISC+=("$TAG_PWAUTH" "$LABEL_PWAUTH (disabled)")
        if which tsocks &>/dev/null; then
            tsocks_status && MENU_MISC+=("$TAG_TSOCKS" "$LABEL_TSOCKS (enabled)") || MENU_MISC+=("$TAG_TSOCKS" "$LABEL_TSOCKS (disabled)")
        fi
        if check_installed_snmp; then
            snmp_status && MENU_MISC+=("$TAG_SNMP" "$LABEL_SNMP (enabled)") || MENU_MISC+=("$TAG_SNMP" "$LABEL_SNMP (disabled)")
        fi
        MENU_MISC+=("$TAG_CONNECTIONS" "$LABEL_CONNECTIONS")
        MENU_MISC+=("$TAG_FIREWALL" "$LABEL_FIREWALL")
        MENU_MISC+=("$TAG_INSTALL" "$LABEL_INSTALL")
        MENU_MISC+=("$TAG_UPDATE" "$LABEL_UPDATE")

        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --no-tags --extra-button --extra-label 'Help' --title 'Misc' --menu '' 0 0 0 "${MENU_MISC[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            "$DIALOG_RET"
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$HELP_MISC"
        else
            break
        fi
    done
}

# select log in dialog menu
# parameters:
# none
# return values:
# none
menu_log() {
    declare PROGRAM_LOG RET_CODE SEARCH_FILTER SEARCH_RESULT
    declare -a MENU_LOG

    MENU_LOG=()
    for PROGRAM_LOG in "${PROGRAM_LOGS[@]}"; do
        if [ "$(eval echo \"\$LOG_${PROGRAM_LOG^^}_CHECK\")" != 1 ] || "check_installed_$PROGRAM_LOG"; then
            MENU_LOG+=("$PROGRAM_LOG" "$(eval echo \"\$LOG_${PROGRAM_LOG^^}_LABEL\")")
        fi
    done

    while true; do
        exec 3>&1
        PROGRAM_LOG="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --no-tags --extra-button --extra-label 'Help' --title '' --menu '' 0 0 0 "${MENU_LOG[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            log_action "$PROGRAM_LOG"
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$HELP_LOG"
        else
            break
        fi
    done
}

# sync all config
# parameters:
# none
# return values:
# none
sync_all() {
    for CONFIG in postfix postfwd dkim spf spamassassin rspamd fail2ban; do
        "check_installed_$CONFIG" && "${CONFIG}_sync"
    done
}

# check for update and when available ask user whether to install it and show changelog
# parameters:
# none
# return values:
# none
check_update() {
    declare -r TMP_UPDATE='/tmp/TMPupdate'
    declare VERSION MAJOR_DL MINOR_DL BUILD_DL MAJOR_CURRENT MINOR_CURRENT BUILD_CURRENT MENU_SETTINGS

    rm -f "$TMP_UPDATE"
    "$WGET" "$LINK_UPDATE" -O "$TMP_UPDATE" &>/dev/null

    if [ "$?" = 0 ]; then
        VERSION="$(grep '^# menu.sh V' "$TMP_UPDATE" | awk -FV '{print $2}' | awk '{print $1}')"
        MAJOR_DL="$(echo "$VERSION" | awk -F. '{print $1}')"
        MINOR_DL="$(echo "$VERSION" | awk -F. '{print $2}')"
        BUILD_DL="$(echo "$VERSION" | awk -F. '{print $3}')"
        VERSION="$(grep '^# menu.sh V' "$0" | awk -FV '{print $2}' | awk '{print $1}')"
        MAJOR_CURRENT="$(echo "$VERSION" | awk -F. '{print $1}')"
        MINOR_CURRENT="$(echo "$VERSION" | awk -F. '{print $2}')"
        BUILD_CURRENT="$(echo "$VERSION" | awk -F. '{print $3}')"

        if [ "$MAJOR_DL" -gt "$MAJOR_CURRENT" ] ||
        ([ "$MAJOR_DL" = "$MAJOR_CURRENT" ] && [ "$MINOR_DL" -gt "$MINOR_CURRENT" ]) ||
        ([ "$MAJOR_DL" = "$MAJOR_CURRENT" ] && [ "$MINOR_DL" = "$MINOR_CURRENT" ] && [ "$BUILD_DL" -gt "$BUILD_CURRENT" ]); then
            get_yesno 'New update available. Install?'

            if [ "$?" = 0 ]; then
                INFO_START=$(expr $(grep -n '# Changelog:' "$TMP_UPDATE" | head -1 | awk -F: '{print $1}') + 1)
                INFO_END=$(expr $(grep -n '###################################################################################################' "$TMP_UPDATE" | head -2 | tail -1 | awk -F: '{print $1}') - 2)
                INFO_TEXT="$(sed -n "$INFO_START,$INFO_END p" "$TMP_UPDATE" | sed 's/^#//g' | sed 's/^ //g')"

                "$DIALOG" --clear --backtitle "$TITLE_MAIN" --title 'Changelog' --msgbox "$INFO_TEXT" 0 0

                MENU_SETTINGS="$(sed -n '/^# Menu settings$/,/^###################################################################################################$/p' "$0" | head -n -2 | tail -n +2)"

                while read SETTING; do
                    sed -i -E "s/($(echo "$SETTING" | awk -F= '{print $1}')=)\S+/\1$(echo "$SETTING" | awk -F= '{print $2}')/" "$TMP_UPDATE"
                done < <(echo "$MENU_SETTINGS")

                mv -f "$TMP_UPDATE" "$0"
                chmod +x "$0"
                "$0"
                exit 0
            fi
        fi
    else
        show_info 'Update failed' 'Cannot download most recent version.'

        rm -f "$TMP_UPDATE"
    fi
}

# write example configuration files
# parameters:
# none
# return values:
# none
write_examples() {
    [ -d "$DIR_MAPS" ] || mkdir -p "$DIR_MAPS"

    if ! [ -f "$CONFIG_POSTFIX_POSTSCREEN" ]; then
        echo '##################################' >> "$CONFIG_POSTFIX_POSTSCREEN"
        echo '# Postscreen IP whitelist (CIDR) #' >> "$CONFIG_POSTFIX_POSTSCREEN"
        echo '##################################' >> "$CONFIG_POSTFIX_POSTSCREEN"
        echo '#88.198.215.226    permit' >> "$CONFIG_POSTFIX_POSTSCREEN"
        echo '#85.10.249.206     permit' >> "$CONFIG_POSTFIX_POSTSCREEN"
    fi

    if ! [ -f "$CONFIG_POSTFIX_PSWLUPDATE" ]; then
        echo 'google.com' >> "$CONFIG_POSTFIX_PSWLUPDATE"
        echo 'microsoft.com' >> "$CONFIG_POSTFIX_PSWLUPDATE"
    fi

    if ! [ -f "$CONFIG_POSTFIX_CLIENT" ]; then
        echo '###############################' >> "$CONFIG_POSTFIX_CLIENT"
        echo '# Postfix IP whitelist (CIDR) #' >> "$CONFIG_POSTFIX_CLIENT"
        echo '###############################' >> "$CONFIG_POSTFIX_CLIENT"
        echo '#1.2.3.4       REJECT unwanted newsletters!' >> "$CONFIG_POSTFIX_CLIENT"
        echo '#1.2.3.0/24    OK' >> "$CONFIG_POSTFIX_CLIENT"
    fi

    if ! [ -f "$CONFIG_POSTFIX_SENDER" ]; then
        echo '##################################' >> "$CONFIG_POSTFIX_SENDER"
        echo '# Postfix sender access (regexp) #' >> "$CONFIG_POSTFIX_SENDER"
        echo '##################################' >> "$CONFIG_POSTFIX_SENDER"
        echo '#/.*@isdoll\.de$/    REJECT mydomain in your envelope sender not allowed! Use your own domain!' >> "$CONFIG_POSTFIX_SENDER"
    fi

    if ! [ -f "$CONFIG_POSTFIX_RECIPIENT" ]; then
        echo '#####################################' >> "$CONFIG_POSTFIX_RECIPIENT"
        echo '# Postfix recipient access (regexp) #' >> "$CONFIG_POSTFIX_RECIPIENT"
        echo '#####################################' >> "$CONFIG_POSTFIX_RECIPIENT"
        echo '#/mueller@isdoll\.de$/    REJECT user has moved!' >> "$CONFIG_POSTFIX_RECIPIENT"
    fi

    if ! [ -f "$CONFIG_POSTFIX_HELO" ]; then
        echo '################################' >> "$CONFIG_POSTFIX_HELO"
        echo '# Postfix HELO access (regexp) #' >> "$CONFIG_POSTFIX_HELO"
        echo '################################' >> "$CONFIG_POSTFIX_HELO"
    fi

    if ! [ -f "$CONFIG_POSTFIX_ESMTP" ]; then
        echo '###############################' >> "$CONFIG_POSTFIX_ESMTP"
        echo '# Postfix ESMTP access (CIDR) #' >> "$CONFIG_POSTFIX_ESMTP"
        echo '###############################' >> "$CONFIG_POSTFIX_ESMTP"
        echo '#130.180.71.126/32      silent-discard, auth' >> "$CONFIG_POSTFIX_ESMTP"
        echo '#212.202.158.254/32     silent-discard, auth' >> "$CONFIG_POSTFIX_ESMTP"
        echo '#0.0.0.0/0              silent-discard, etrn, enhancedstatuscodes, dsn, pipelining, auth' >> "$CONFIG_POSTFIX_ESMTP"
    fi

    if ! [ -f "$CONFIG_POSTFIX_HEADER" ]; then
        echo '##################################' >> "$CONFIG_POSTFIX_HEADER"
        echo '# Postfix header checks (regexp) #' >> "$CONFIG_POSTFIX_HEADER"
        echo '##################################' >> "$CONFIG_POSTFIX_HEADER"
        echo '#/^\s*Received: from \S+ \(\S+ \[\S+\]\)(.*)/    REPLACE Received: from [127.0.0.1] (localhost [127.0.0.1])$1' >> "$CONFIG_POSTFIX_HEADER"
        echo '#/^\s*User-Agent/        IGNORE' >> "$CONFIG_POSTFIX_HEADER"
        echo '#/^\s*X-Enigmail/        IGNORE' >> "$CONFIG_POSTFIX_HEADER"
        echo '#/^\s*X-Mailer/          IGNORE' >> "$CONFIG_POSTFIX_HEADER"
        echo '#/^\s*X-Originating-IP/  IGNORE' >> "$CONFIG_POSTFIX_HEADER"
    fi

    if ! [ -f "$CONFIG_POSTFIX_MIME" ]; then
        echo '#######################################' >> "$CONFIG_POSTFIX_MIME"
        echo '# Postfix MIME header checks (regexp) #' >> "$CONFIG_POSTFIX_MIME"
        echo '#######################################' >> "$CONFIG_POSTFIX_MIME"
        echo '# example file extension blacklist:' >> "$CONFIG_POSTFIX_MIME"
        echo '#/^\s*Content.(Disposition|Type).*name\s*=\s*"?.+\.(exe|pif|com|dll|vbs|bat|doc|dot|xls|xla|xlt|xlw|ppr|pot|ppa|pps|mdb|vsd|vdx)"?\s*$/ REJECT unwanted attachment' >> "$CONFIG_POSTFIX_MIME"
        echo '# example file extension whitelist:' >> "$CONFIG_POSTFIX_MIME"
        echo '#/^\s*Content.(Disposition|Type).*name\s*=\s*"?.+\.((?!txt|png|jpg|gif|tif|bmp|svg|pdf|zip|ics|pgp|gpg|key|p7s).)*"?\s*$/ REJECT unwanted attachment' >> "$CONFIG_POSTFIX_MIME"
    fi

    if ! [ -f "$CONFIG_POSTFIX_REWRITE" ]; then
        echo '###################################' >> "$CONFIG_POSTFIX_REWRITE"
        echo '# Postfix sender rewrite (regexp) #' >> "$CONFIG_POSTFIX_REWRITE"
        echo '###################################' >> "$CONFIG_POSTFIX_REWRITE"
        echo '#/^<.*>(.*)@(.*)>/   ${1}@${2}' >> "$CONFIG_POSTFIX_REWRITE"
    fi

    if ! [ -f "$CONFIG_POSTFIX_ROUTING" ]; then
        echo '###########################################' >> "$CONFIG_POSTFIX_ROUTING"
        echo '# Postfix sender-dependent routing (hash) #' >> "$CONFIG_POSTFIX_ROUTING"
        echo '###########################################' >> "$CONFIG_POSTFIX_ROUTING"
        echo '#mueller@isdoll.de     smtp:[127.0.0.1]:10026' >> "$CONFIG_POSTFIX_ROUTING"
        echo '#@isdoll.de            smtp:[127.0.0.1]:10026' >> "$CONFIG_POSTFIX_ROUTING"
        postmap "$CONFIG_POSTFIX_ROUTING" &>/dev/null
    fi

    if ! [ -f "$CONFIG_POSTFIX_MILTER" ]; then
        echo '################################' >> "$CONFIG_POSTFIX_MILTER"
        echo '# Postfix milter bypass (CIDR) #' >> "$CONFIG_POSTFIX_MILTER"
        echo '################################' >> "$CONFIG_POSTFIX_MILTER"
        echo '#127.0.0.0/8    DISABLE' >> "$CONFIG_POSTFIX_MILTER"
        echo '#127.0.0.0/8    inet:127.0.0.1:19127' >> "$CONFIG_POSTFIX_MILTER"
    fi

    if ! [ -f "$CONFIG_POSTFIX_ALIAS" ]; then
        echo '##################################' >> "$CONFIG_POSTFIX_ALIAS"
        echo '# Postfix virtual aliases (hash) #' >> "$CONFIG_POSTFIX_ALIAS"
        echo '##################################' >> "$CONFIG_POSTFIX_ALIAS"
        echo '#webmaster@example.com    admin@example.com' >> "$CONFIG_POSTFIX_ALIAS"
        echo '#@test.com                test@example.com' >> "$CONFIG_POSTFIX_ALIAS"
    fi

    [ -f "$POSTFIX_ALIAS_ADMIN" ] || echo "admins@$(hostname -d)" > "$POSTFIX_ALIAS_ADMIN"
}

# install dependency
# parameters:
# $1 - binary to check
# $2 - list of packages to install
# return values:
# none
install_dependency() {
    which "$1" &>/dev/null || "$INSTALLER" install -y $2 &>/dev/null
}

# perform basic setup
# parameters:
# none
# return values:
# none
base_setup() {
    declare -r CONFIG_BASH="$HOME/.bashrc"
    declare COUNTER POSTFIX_RESTART

    clear
    echo 'Performing base setup. This may take a while...'

    [ -x "$0" ] || chmod u+x "$0"

    if ! [ -f "$CONFIG_BASH" ] || ! grep -q "alias menu=$HOME/menu.sh" "$CONFIG_BASH"; then
        echo "alias menu=$HOME/menu.sh" >> "$CONFIG_BASH"
        source "$CONFIG_BASH"
    fi

    if [ "$DISTRO" = 'redhat' ] && ! [ -f '/etc/yum.repos.d/epel.repo' ]; then
        echo '... installing EPEL and updating system (this can take several minutes)'
        yum install -y epel-release &>/dev/null
        yum update -y &>/dev/null
    fi

    echo '... installing package dependencies'
    for COUNTER in $(seq 0 "$(expr "${#DEPENDENCY[@]}" / 2 - 1)"); do
        install_dependency "${DEPENDENCY[$(expr "$COUNTER" \* 2)]}" "${DEPENDENCY[$(expr "$COUNTER" \* 2 + 1)]}"
    done

    # for Debian-10 installing pip3 does NOT install python3-setuptools
    if [ "$DISTRO" = 'debian' ] && ! pip3 list 2>/dev/null | grep -q '^setuptools'; then
        echo '... installing Python3 setuptools'
        apt install -y python3-setuptools &>/dev/null
    fi

    echo '... setting up CPAN'
    echo | cpan &>/dev/null

    if which postfix &>/dev/null; then
        echo '... setting up base Postfix'
        [ -f /etc/postfix/makedefs.out ] && rm -f /etc/postfix/makedefs.out &>/dev/null

        POSTFIX_RESTART=0

        if ! postconf inet_interfaces | grep -q 'all'; then
            postconf 'inet_interfaces=all'

            POSTFIX_RESTART=1
        fi

        if ! postconf inet_protocols | grep -q 'ipv4'; then
            postconf 'inet_protocols=ipv4'

            POSTFIX_RESTART=1
        fi

        if [ "$(postconf mynetworks)" = 'mynetworks =' ]; then
            postconf 'mynetworks=127.0.0.0/8'

            POSTFIX_RESTART=1
        fi

        [ "$POSTFIX_RESTART" = 1 ] && postfix_restart
    fi

    echo '... done'
}

# main menu, select option in dialog menu
# parameters:
# none
# return values:
# none
menu_main() {
    declare -r TAG_MENU_INSTALL='menu_install'
    declare -r TAG_MENU_POSTFIX='menu_postfix'
    declare -r TAG_MENU_RSPAMD='menu_rspamd'
    declare -r TAG_MENU_ADDON='menu_addon'
    declare -r TAG_MENU_MISC='menu_misc'
    declare -r TAG_MENU_LOG='menu_log'
    declare -r TAG_SYNC_ALL='sync_all'
    declare -r LABEL_MENU_INSTALL='Install'
    declare -r LABEL_MENU_POSTFIX='Postfix'
    declare -r LABEL_MENU_RSPAMD='Rspamd'
    declare -r LABEL_MENU_ADDON='Addon'
    declare -r LABEL_MENU_MISC='Misc'
    declare -r LABEL_MENU_LOG='Log files'
    declare -r LABEL_SYNC_ALL='Sync cluster'
    declare -a MENU_MAIN
    declare DIALOG_RET RET_CODE TAG_ADDON

    while true; do
        MENU_MAIN=()
        MENU_MAIN+=("$TAG_MENU_INSTALL" "$LABEL_MENU_INSTALL")
        check_installed_postfix && MENU_MAIN+=("$TAG_MENU_POSTFIX" "$LABEL_MENU_POSTFIX")
        check_installed_rspamd && MENU_MAIN+=("$TAG_MENU_RSPAMD" "$LABEL_MENU_RSPAMD")
        for TAG_ADDON in "${ADDON_CONFIG[@]}"; do
            if "check_installed_$TAG_ADDON"; then
                MENU_MAIN+=("$TAG_MENU_ADDON" "$LABEL_MENU_ADDON")
                break
            fi
        done
        MENU_MAIN+=("$TAG_MENU_MISC" "$LABEL_MENU_MISC")
        check_installed_logmanager && MENU_MAIN+=("$TAG_MENU_LOG" "$LABEL_MENU_LOG")
        check_installed_cluster && MENU_MAIN+=("$TAG_SYNC_ALL" "$LABEL_SYNC_ALL")

        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Exit' --no-tags --extra-button --extra-label 'Help' --title "$TITLE_MAIN" --menu '' 0 0 0 "${MENU_MAIN[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            "$DIALOG_RET"
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$HELP_MAIN"
        else
            break
        fi
    done
}

echo "[$(date +'%F %T')] Starting menu..." >> "$LOG_MENU"

if [ -z "$DISTRO" ]; then
    echo 'Incompatible Linux distro' 'This tool only supports Redhat, Debian and SUSE Linux (and compatible).'
    exit 1
fi

{
    base_setup
    check_update
    write_examples
    menu_main
    clear
} 2>> "$LOG_MENU"
