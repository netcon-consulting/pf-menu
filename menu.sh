#!/bin/bash

# menu.sh V1.9.0 for Postfix
#
# Copyright (c) 2019-2020 NetCon Unternehmensberatung GmbH, netcon-consulting.com
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
# - improved file selection function
# - bugfix
#
###################################################################################################

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
declare -g -r CRON_LOGMANAGER='/etc/cron.daily/log_manager.sh'
declare -g -r SCRIPT_REBOOT='/etc/netcon-scripts/reboot-alert.sh'
declare -g -r CRONTAB_REBOOT='@reboot /etc/netcon-scripts/reboot-alert.sh'
declare -g -r CRON_RULES='/etc/cron.daily/update_rules.sh'
declare -g -r CONFIG_SSH="$HOME/.ssh/config"
declare -g -r PYZOR_PLUGIN='/usr/share/rspamd/plugins/pyzor.lua'
declare -g -r PYZOR_DIR='/opt/pyzorsocket'
declare -g -r PYZOR_SOCKET="$PYZOR_DIR/bin/pyzorsocket.py"
declare -g -r PYZOR_SERVICE='/etc/init.d/pyzorsocket'
declare -g -r PYZOR_USER='pyzorsocket'
declare -g -r RAZOR_PLUGIN='/usr/share/rspamd/plugins/razor.lua'
declare -g -r RAZOR_DIR='/opt/razorsocket'
declare -g -r RAZOR_SOCKET="$RAZOR_DIR/bin/razorsocket.py"
declare -g -r RAZOR_SERVICE='/etc/init.d/razorsocket'
declare -g -r RAZOR_USER='razorsocket'
declare -g -r CONFIG_UPDATE='/etc/apt/apt.conf.d/50unattended-upgrades'
declare -g -r CONFIG_LOGWATCH='/etc/logwatch/conf/logwatch.conf'

###################################################################################################
# Default settings
declare -g -r DEFAULT_EDITOR='vim'

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
INSTALL_FEATURE+=('fail2ban')
INSTALL_FEATURE+=('dkim')
INSTALL_FEATURE+=('spf')
INSTALL_FEATURE+=('logwatch')
INSTALL_FEATURE+=('logmanager')
INSTALL_FEATURE+=('reboot')
INSTALL_FEATURE+=('peer')

# Postfix
declare -g -r LABEL_INSTALL_POSTFIX='Postfix'
declare -g -r INSTALL_POSTFIX_PACKAGE='postfix'

# Local DNS resolver
declare -g -r LABEL_INSTALL_RESOLVER='Local DNS resolver'
declare -g -r INSTALL_RESOLVER_PACKAGE='bind9'

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
declare -g -r INSTALL_PYZOR_PACKAGE='pyzor'

# Razor
declare -g -r LABEL_INSTALL_RAZOR='Razor'
declare -g -r INSTALL_RAZOR_PACKAGE='razor'

# Fail2ban
declare -g -r LABEL_INSTALL_FAIL2BAN='Fail2ban'
declare -g -r INSTALL_FAIL2BAN_PACKAGE='fail2ban'

# OpenDKIM
declare -g -r LABEL_INSTALL_DKIM='OpenDKIM'
declare -g -r INSTALL_DKIM_PACKAGE='opendkim'

# SPF-Check
declare -g -r LABEL_INSTALL_SPF='SPF-check'
declare -g -r INSTALL_SPF_PACKAGE='postfix-policyd-spf-python'

# Logwatch
declare -g -r LABEL_INSTALL_LOGWATCH='Logwatch'
declare -g -r INSTALL_LOGWATCH_PACKAGE='logwatch'

# Log-manager
declare -g -r LABEL_INSTALL_LOGMANAGER='NetCon Log-manager'

# Reboot alert
declare -g -r LABEL_INSTALL_REBOOT='Reboot alert'

# Setup peer
declare -g -r LABEL_INSTALL_PEER='Setup cluster peer'

###################################################################################################
# Postfix server configs
declare -g -a POSTFIX_CONFIG_SERVER

POSTFIX_CONFIG_SERVER=()
POSTFIX_CONFIG_SERVER+=('postscreen')
POSTFIX_CONFIG_SERVER+=('client')
POSTFIX_CONFIG_SERVER+=('sender')
POSTFIX_CONFIG_SERVER+=('recipient')
POSTFIX_CONFIG_SERVER+=('helo')
POSTFIX_CONFIG_SERVER+=('esmtp')
POSTFIX_CONFIG_SERVER+=('rewrite')
POSTFIX_CONFIG_SERVER+=('milter')
POSTFIX_CONFIG_SERVER+=('header')

# Postscreen access IPs
declare -g -r LABEL_CONFIG_POSTFIX_POSTSCREEN='Postscreen access IPs'
declare -g -r CONFIG_POSTFIX_POSTSCREEN="$DIR_MAPS/check_postscreen_access_ips"

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
POSTFIX_FEATURE+=('rewrite')
POSTFIX_FEATURE+=('routing')
POSTFIX_FEATURE+=('milter')
POSTFIX_FEATURE+=('bounce')
POSTFIX_FEATURE+=('limit')
POSTFIX_FEATURE+=('postscreen')
POSTFIX_FEATURE+=('psdeep')
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

POSTFIX_TLS+=('smtp_tls_CAfile=/etc/ssl/certs/ca-bundle.crt')
POSTFIX_TLS+=('smtp_tls_security_level=may')
POSTFIX_TLS+=('smtp_use_tls=yes')
POSTFIX_TLS+=('smtpd_tls_CAfile=/etc/ssl/certs/ca-bundle.crt')
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

POSTFIX_HEADER+=("header_checks=regexp:$DIR_MAPS/check_header")

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

POSTFIX_POSTSCREEN+=("postscreen_access_list=permit_mynetworks cidr:$CONFIG_POSTFIX_POSTSCREEN")
POSTFIX_POSTSCREEN+=('postscreen_blacklist_action=enforce')
POSTFIX_POSTSCREEN+=('postscreen_command_time_limit=${stress?10}${stress:300}s')
POSTFIX_POSTSCREEN+=('postscreen_dnsbl_action=enforce')
POSTFIX_POSTSCREEN+=("postscreen_dnsbl_sites=$POSTSCREEN_BLACKLISTS")
POSTFIX_POSTSCREEN+=('postscreen_dnsbl_threshold=3')
POSTFIX_POSTSCREEN+=('postscreen_dnsbl_ttl=1h')
POSTFIX_POSTSCREEN+=('postscreen_greet_action=enforce')
POSTFIX_POSTSCREEN+=('postscreen_greet_wait=${stress?4}${stress:15}s')

# Postscreen Deep
declare -g -r POSTFIX_PSDEEP_LABEL='Postscreen Deep'

POSTFIX_PSDEEP+=('postscreen_bare_newline_enable=yes')
POSTFIX_PSDEEP+=('postscreen_bare_newline_action=enforce')
POSTFIX_PSDEEP+=('postscreen_non_smtp_command_action=enforce')
POSTFIX_PSDEEP+=('postscreen_non_smtp_command_enable=yes')
POSTFIX_PSDEEP+=('postscreen_pipelining_enable=yes')
POSTFIX_PSDEEP+=('postscreen_dnsbl_whitelist_threshold=-1')

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
ADDON_CONFIG+=('rspamd')
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

# Rspamd
declare -g -r LABEL_ADDON_RSPAMD='Rspamd'

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

# Main
declare -g -r LABEL_CONFIG_SPAMASSASSIN_LOCAL='Main'
declare -g -r CONFIG_SPAMASSASSIN_LOCAL="$DIR_CONFIG_SPAMASSASSIN/local.cf"

###################################################################################################
# Rspamd configs
declare -g -r CONFIG_RSPAMD_LOCAL="$DIR_CONFIG_RSPAMD/rspamd.conf.local"
declare -g -r CONFIG_RSPAMD_GREYLIST="$DIR_CONFIG_RSPAMD/local.d/greylist.conf"
declare -g -r CONFIG_RSPAMD_OPTIONS="$DIR_CONFIG_RSPAMD/local.d/options.inc"
declare -g -r CONFIG_RSPAMD_HISTORY="$DIR_CONFIG_RSPAMD/local.d/history_redis.conf"
declare -g -r CONFIG_RSPAMD_REDIS="$DIR_CONFIG_RSPAMD/local.d/redis.conf"
declare -g -r CONFIG_RSPAMD_SARULES="$DIR_CONFIG_RSPAMD/local.d/spamassassin.conf"
declare -g -r CONFIG_RSPAMD_CONTROLLER="$DIR_CONFIG_RSPAMD/local.d/worker-controller.inc"
declare -g -r CONFIG_RSPAMD_REPUTATION="$DIR_CONFIG_RSPAMD/local.d/url_reputation.conf"
declare -g -r CONFIG_RSPAMD_PHISHING="$DIR_CONFIG_RSPAMD/local.d/phishing.conf"
declare -g -r CONFIG_RSPAMD_ELASTIC="$DIR_CONFIG_RSPAMD/local.d/elastic.conf"
declare -g -r CONFIG_RSPAMD_ACTIONS="$DIR_CONFIG_RSPAMD/override.d/actions.conf"
declare -g -r CONFIG_RSPAMD_HEADERS="$DIR_CONFIG_RSPAMD/override.d/milter_headers.conf"
declare -g -r CONFIG_RSPAMD_BAYES="$DIR_CONFIG_RSPAMD/override.d/classifier-bayes.conf"
declare -g -r CONFIG_RSPAMD_MULTIMAP="$DIR_CONFIG_RSPAMD/local.d/multimap.conf"
declare -g -r CONFIG_RSPAMD_GROUPS="$DIR_CONFIG_RSPAMD/local.d/groups.conf"
declare -g -r CONFIG_RSPAMD_SIGNATURES="$DIR_CONFIG_RSPAMD/local.d/signatures_group.conf"

declare -g -a RSPAMD_CONFIG

RSPAMD_CONFIG=()
RSPAMD_CONFIG+=('whitelist_ip')
RSPAMD_CONFIG+=('whitelist_domain')
RSPAMD_CONFIG+=('whitelist_from')
RSPAMD_CONFIG+=('whitelist_to')
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
RSPAMD_FEATURE+=('sarules')
RSPAMD_FEATURE+=('rulesupdate')
RSPAMD_FEATURE+=('reputation')
RSPAMD_FEATURE+=('phishing')
RSPAMD_FEATURE+=('pyzor')
RSPAMD_FEATURE+=('razor')

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

declare -r RSPAMD_BWLIST_CUSTOM=1

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
declare -g -r RSPAMD_SARULES_LABEL='Heinlein SA rules'
declare -r RSPAMD_SARULES_CUSTOM=1

RSPAMD_SARULES+=("ruleset = \"$FILE_RULES\";" "$CONFIG_RSPAMD_SARULES")
RSPAMD_SARULES+=('alpha = 0.1;' "$CONFIG_RSPAMD_SARULES")

# Automatic SA rules update
declare -g -r RSPAMD_RULESUPDATE_LABEL='Automatic SA rules update'

declare -r RSPAMD_RULESUPDATE_CUSTOM=1

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

# Automatic update
declare -g -r LABEL_EMAIL_UPDATE='Automatic update'

# Logwatch
declare -g -r LABEL_EMAIL_LOGWATCH='Logwatch'
declare -g -r EMAIL_LOGWATCH_CHECK=1

# Reboot alert
declare -g -r LABEL_EMAIL_REBOOT='Reboot alert'
declare -g -r EMAIL_REBOOT_CHECK=1

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
# stderr - 0 if setting changed, 1 if not changed
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

# check whether Postfix is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_postfix() {
    which postfix &>/dev/null
    [ "$?" = 0 ] && return 0 || return 1
}

# check whether local DNS resolver is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_resolver() {
    which named &>/dev/null
    [ "$?" = 0 ] && return 0 || return 1
}

# check whether Postfwd3 is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_postfwd() {
    which /usr/local/postfwd/sbin/postfwd &>/dev/null
    [ "$?" = 0 ] && return 0 || return 1
}

# check whether Spamassassin is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_spamassassin() {
    which spamassassin &>/dev/null
    [ "$?" = 0 ] && return 0 || return 1
}

# check whether Rspamd is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_rspamd() {
    which rspamd &>/dev/null
    [ "$?" = 0 ] && return 0 || return 1
}

# check whether Pyzor is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_pyzor() {
    which pyzor &>/dev/null
    [ "$?" = 0 ] && return 0 || return 1
}

# check whether Razor is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_razor() {
    which razor-check &>/dev/null
    [ "$?" = 0 ] && return 0 || return 1
}

# check whether Fail2ban is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_fail2ban() {
    which fail2ban-client &>/dev/null
    [ "$?" = 0 ] && return 0 || return 1
}

# check whether OpenDKIM is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_dkim() {
    which opendkim &>/dev/null
    [ "$?" = 0 ] && return 0 || return 1
}

# check whether SPF-check is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_spf() {
    which policyd-spf &>/dev/null
    [ "$?" = 0 ] && return 0 || return 1
}

# check whether Logwatch is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_logwatch() {
    which logwatch &>/dev/null
    [ "$?" = 0 ] && return 0 || return 1
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
    if [ -f "$SCRIPT_REBOOT" ] && crontab -l | grep -q "$CRONTAB_REBOOT"; then
        return 0
    else
        return 1
    fi
}

# check whether peer is available
# parameters:
# none
# return values:
# error code - 0 for peer available, 1 for not available
check_installed_peer() {
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
    which daemonize &>/dev/null
    [ "$?" = 0 ] && return 0 || return 1
}

# check whether any Postfix plugin is available
# parameters:
# none
# return values:
# error code - 0 for peer available, 1 for not available
check_installed_plugin() {
    check_installed_postfwd || check_installed_dkim || check_installed_spf
}

# check Postfwd version
# parameters:
# none
# return values:
# stdout - version number
check_version_postfwd() {
    /usr/local/postfwd/sbin/postfwd -u postfwd -g postfwd --version | awk '{print $2}'
}

# check for update of Postfwd
# parameters:
# none
# return values:
# stdout - version number of update
check_update_postfwd() {
    wget "$INSTALL_POSTFWD_LINK" -O - 2>/dev/null | grep '^our $VERSION' | awk 'match($0, /= "([^"]+)";/, a) {print a[1]}'
}

###################################################################################################
# Postfix feature custom functions

# check TLS certificate/key Postfix parameter status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 disabled
tls_status() {
    if [ -z "$(postconf 'smtp_tls_cert_file' 2>/dev/null | sed -E "s/^smtp_tls_cert_file = ?//")" ]             \
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
            [ -f "$FILE_DHPARAM" ] || openssl dhparam -out "$FILE_DHPARAM" 2048 &>/dev/null

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
    if postconf -M '25/inet' 2>/dev/null | grep -q -E '^25\s+inet\s+n\s+-\s+n\s+-\s+1\s+postscreen$'                       \
        && postconf -M 'smtpd/pass' 2>/dev/null | grep -q -E '^smtpd\s+pass\s+-\s+-\s+n\s+-\s+-\s+smtpd$'                  \
        && postconf -M 'dnsblog/unix' 2>/dev/null | grep -q -E '^dnsblog\s+unix\s+-\s+-\s+n\s+-\s+0\s+dnsblog$'            \
        && postconf -M 'tlsproxy/unix' 2>/dev/null | grep -q -E '^tlsproxy\s+unix\s+-\s+-\s+n\s+-\s+0\s+tlsproxy$'; then
        return 0
    else
        return 1
    fi
}

# enable Postscreen
# parameters:
# none
# return values:
# none
postscreen_enable() {
    postconf -Me '25/inet=25 inet n - n - 1 postscreen' 2>/dev/null
    postconf -Me 'smtpd/pass=smtpd pass - - n - - smtpd' 2>/dev/null
    postconf -Me 'dnsblog/unix=dnsblog unix - - n - 0 dnsblog' 2>/dev/null
    postconf -Me 'tlsproxy/unix=tlsproxy unix - - n - 0 tlsproxy' 2>/dev/null
}

# disable Postscreen
# parameters:
# none
# return values:
# none
postscreen_disable() {
    postconf -MX '25/inet' 2>/dev/null
    postconf -MX 'smtpd/pass' 2>/dev/null
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
    postconf -MX 'smtpd/pass' 2>/dev/null
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

# check Rspamd status
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

# enable Rspamd
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

# disable Rspamd
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
        echo off
        return
    fi

    while read POSTFIX_SETTING; do
        SETTING_KEY="$(echo "$POSTFIX_SETTING" | awk -F= '{print $1}')"
        if [ "$(postconf "$SETTING_KEY" 2>/dev/null | sed -E "s/^$SETTING_KEY = ?//")" != "$(echo "$POSTFIX_SETTING" | sed "s/^$SETTING_KEY=//")" ]; then
            echo off
            return
        fi
    done < <(eval "for ELEMENT in \"\${POSTFIX_${1^^}[@]}\"; do echo \"\$ELEMENT\"; done")

    echo on
}

# enable given Postfix feature
# parameters:
# $1 - feature label
# return values:
# error code - 0 for changes made, 1 for no changes made
postfix_feature_enable() {
    declare POSTFIX_SETTING

    if [ "$(eval echo \"\$POSTFIX_${1^^}_CUSTOM\")" = 1 ] && ! "${1}_enable"; then
        return 1
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

    if [ "$(eval echo \"\$POSTFIX_${1^^}_CUSTOM\")" = 1 ] && ! "${1}_disable"; then
        return 1
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
                postconf 2>/dev/null | grep -q "hash:$FILE_CONFIG" && postmap "$FILE_CONFIG" &>/dev/null
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

# edit local DNS resolver config
# parameters:
# none
# return values:
# none
resolver_config() {
    edit_config "$CONFIG_RESOLVER" && systemctl reload bind9 &>/dev/null
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

        systemctl reload bind9 &>/dev/null
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

    systemctl reload bind9 &>/dev/null
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

        systemctl reload bind9 &>/dev/null
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

        systemctl reload bind9 &>/dev/null
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
                edit_zone "$DIALOG_RET" && systemctl reload bind9 &>/dev/null
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
    ssh mx systemctl reload bind9 &>/dev/null
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

# check Rspamd Spamassassin rules status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 for disabled
sarules_status() {
    [ -f "$FILE_RULES" ] && return 0 || return 1
}

# enable Rspamd Spamassassin rules
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
        wget "http://www.spamassassin.heinlein-support.de/$VERSION_RULES.tar.gz" -O "$FILE_DOWNLOAD" &>/dev/null

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

# disable Rspamd Spamassassin rules
# parameters:
# none
# return values:
# none
sarules_disable() {
    rm -f "$FILE_RULES"
}

# check Rspamd Spamassassin rules update status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 for disabled
rulesupdate_status() {
    [ -f "$CRON_RULES" ] && return 0 || return 1
}

# enable Rspamd Spamassassin rules update
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

# disable Rspamd Spamassassin rules update
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
        && [ -f "$PYZOR_SOCKET" ]                                                                                                                                                                                                                                                                                           \
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
# error code - 0 for enabled, 1 for disabled
pyzor_enable() {
    declare PACKED_SCRIPT

    if ! grep -q '^pyzor { }$' "$CONFIG_RSPAMD_LOCAL"; then
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
    printf '%s' $PACKED_SCRIPT | base64 -d | gunzip > "$PYZOR_SOCKET"
    chown "$PYZOR_USER:$PYZOR_USER" "$PYZOR_SOCKET"
    chmod 0700 "$PYZOR_SOCKET"

    PACKED_SCRIPT='
    H4sIAHmU510AA5VSXU/CMBR976+4jgXFZI5piAohxphpjBjIABM1xpRSWcNoZ9upCPx3R4E5Pnxw
    fbrnnntOz+0Ke26PcbeHVYgKqADx+FtIJciQalOTcEgEf2ODKjhwVgGvkoJ9qohksWaCV9cnIJaC
    UKU4HtH1Fgr8zsNlo15GraB5U9/P9fZRo3l1d33b8OuW+4GlG6Wwq5KeGivXntMt1Hp8agbtlOZ3
    XrttP9gQQEpjqQ9KMEGw/CgJBTgcrPa8xfgAjFQVrIzSx3QkOPum4CRpd8MCXBFrN2djNpWrj+Ix
    eMenR+X0eFA5r5xkysuw9kWGPIO9AMGh71CGFygWQYuEhGCv4q/dPSsk1Ynkq3E0m4cV8R9Zw0Sb
    rH3xybcDD1kU4SgCp+MH9ztD/zeBHIHz9v8EBCsKlu1ZwLihmfcrZROmzKpabckRcZ4i4m0G1okq
    bcKSbsnnZnd6HZbWl2t1FR6kv7RZKUzMzHQuM114Tpces99l0y+mwcsLU4UJMvBqFT/avA/GfwMA
    AA==
    '
    printf '%s' $PACKED_SCRIPT | base64 -d | gunzip > "$PYZOR_SERVICE"
    chmod +x "$PYZOR_SERVICE"

    check_installed_daemonize || apt install -y daemonize &>/dev/null

    systemctl daemon-reload
    systemctl start pyzorsocket
    update-rc.d pyzorsocket defaults
}

# disable Pyzor
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 for disabled
pyzor_disable() {
    sed -i '/^pyzor { }$/d' "$CONFIG_RSPAMD_LOCAL"
    sed -i 'H;/^symbols = {$/h;/^}$/!d;x;/\n\t"PYZOR" {/d' "$CONFIG_RSPAMD_SIGNATURES"
    [ "$(rspamd_feature_status 'razor')" = 'off' ] && sed -i '/^group "signatures" {$/,/^}$/d' "$CONFIG_RSPAMD_GROUPS"

    update-rc.d pyzorsocket remove
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
        && [ -f "$RAZOR_SOCKET" ]                                                                                                                                                                                                                                                                                           \
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
# error code - 0 for enabled, 1 for disabled
razor_enable() {
    declare PACKED_SCRIPT

    if ! grep -q '^razor { }$' "$CONFIG_RSPAMD_LOCAL"; then
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
    H4sIAHhCq1wAA31UUW/TMBB+Jr/CmIc6oktBvKBJfYBpaAhNqlh5GpPlJZfWm2MH29lWEP+ds+Ok
    WdXhl9iXu+/O932+N68XnbOLW6kX7c5vjf6QyaY11hNhN62wDoYzNEKqIprsgc0oWe4Gm3HD7s4Z
    Pexdd9taU4JzWW1NQ5wp78Ej1ANYknzWZ6uraJiT9daCqKTeXMqnr3pOrjyem+/wqwPnL4SuFBaR
    ZaUSzpHnZnbMNz/NMoKrgppso4k5UDWaSVplU5ElCcbC1lJBEQpQUgPLiwpKU+Hm+vTk/c0YIes+
    aEno2cX52Te6BwsrQvW5eLmF8p7l439QDo54P1rpgYe2sT8UrDWWnhLa6XttHjUpTdMgHP2bH94l
    4R/cqKcKLzVlrvi88+BWcc964pZTFoury/VqX2jjNgiQQuOH7VuU6girRi/TgmZ04Zt2sb5cWfEb
    y58T+kj3cOmKDGEL4bjzFilm+dShVAaTTKAtuE75wM0ooaIUSrFrOko3JjuJXQgpn9dwk2evpqQN
    gEvy7hkHPQWR+77K29AqNnOtaGZzMvux/nLycZb/h8WXELYHACN9E8JD7JxUE/7u8M7hV1F1TetY
    lZO3hP7UNHsx3V0BuldqPj6O/kWxwwc1vrWUsEVfjAlFoRo0S+YwBLCMYRYUn+yma0D7JKAKXGll
    66XRS3r+1CJ1JDadGE1EeuSJ/4BRiKriImEwiqcgkS2odhkPyC3xhijpPGjEeDk0DIwxNE6P43Eu
    Vd+LNwC4QVwhIf5lwRbQcexIhI7HgDgQ5ewDuqU+9n4HwyW6ebvbc4cxRRxuvDYWQmDvVEuN0j3m
    aPmo/AxFyrkWDXAexwvngRPO04TpCcr+AZfHVnq7BQAA
    '
    printf '%s' $PACKED_SCRIPT | base64 -d | gunzip > "$RAZOR_SOCKET"
    chown "$RAZOR_USER:$RAZOR_USER" "$RAZOR_SOCKET"
    chmod 0700 "$RAZOR_SOCKET"

    PACKED_SCRIPT='
    H4sIAKim510AA5VSXU/CMBR976+4jgXFZIyREBVCDDHTGDGYAT5ojCmlsIbRzrZTEfjvjgpzfPjg
    +nTPPfecntsVjtwB4+4AqxAVUAEk/hJSCTKh2tRDqohksWaC17ebEEtBqFIcT+lui4QTIviIjevg
    wHkNvBpCgd97bLWbFfQQdG6ax7mBY9TuXN1d37b9puW+Y+lGKeyqZKBmyrVXdAsFradO0E1pfu+1
    3/WDHQGkNJb6pARzBOuPklCAw8HqrlqMj8FI1cHKKENMp4KzLwpOAvauBbgi1m7OxmwqV5fjGXjV
    s3IlPR5ceBfVTHkd1r7MkOfUwIDg0DeowAsUi6BFQkKwN/G37p4VkupE8s04Wq7CiviPrGGiTdah
    +OD7gScsinAUgdPzg/vDof8bQU7BGf0/AsGKgmV7FjBuaOYBS9mEKbOq0VhzRJyniHifgXWiSruw
    pHvyudmDXqel7e1afYXH6Y9udgpzM7NYySx+PBdrj+Xvtukn0+DlhanCBBl4s4pvLtvVmoADAAA=
    '
    printf '%s' $PACKED_SCRIPT | base64 -d | gunzip > "$RAZOR_SERVICE"
    chmod +x "$RAZOR_SERVICE"

    check_installed_daemonize || apt install -y daemonize &>/dev/null

    systemctl daemon-reload
    systemctl start razorsocket
    update-rc.d razorsocket defaults
}

# disable Razor
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 for disabled
razor_disable() {
    sed -i '/^razor { }$/d' "$CONFIG_RSPAMD_LOCAL"
    sed -i 'H;/^symbols = {$/h;/^}$/!d;x;/\n\t"RAZOR" {/d' "$CONFIG_RSPAMD_SIGNATURES"
    [ "$(rspamd_feature_status 'pyzor')" = 'off' ] && sed -i '/^group "signatures" {$/,/^}$/d' "$CONFIG_RSPAMD_GROUPS"

    update-rc.d razorsocket remove
    systemctl stop razorsocket

    rm -rf "$RAZOR_PLUGIN" "$RAZOR_DIR" "$RAZOR_SERVICE"
    userdel -r "$RAZOR_USER" &>/dev/null
    groupdel "$RAZOR_USER" &>/dev/null

    systemctl daemon-reload
}

# checks status of given Rspamd feature
# parameters:
# $1 - feature label
# return values:
# stdout - feature status
rspamd_feature_status() {
    declare COUNTER RSPAMD_SETTING SETTING_KEY SETTING_VALUE FILE_CONFIG

    if [ "$(eval echo \"\$RSPAMD_${1^^}_CUSTOM\")" = 1 ] && ! "${1}_status"; then
        echo off
        return
    fi

    for COUNTER in $(seq 0 "$(expr "$(eval echo \"\${\#RSPAMD_${1^^}[@]}\")" / 2 - 1)"); do
        RSPAMD_SETTING="$(eval echo \"\${RSPAMD_${1^^}[\$\(expr $COUNTER \\\* 2\)]}\")"
        SETTING_KEY="$(echo "$RSPAMD_SETTING" | awk -F ' = ' '{print $1}')"
        SETTING_VALUE="$(echo "$RSPAMD_SETTING" | sed -E "s/^$SETTING_KEY = //")"
        FILE_CONFIG="$(eval echo \"\${RSPAMD_${1^^}[\$\(expr $COUNTER \\\* 2 + 1\)]}\")"

        if ! [ -f "$FILE_CONFIG" ] || [ "$(grep "^$SETTING_KEY = " "$FILE_CONFIG" | sed -E "s/^$SETTING_KEY = ?//")" != "$SETTING_VALUE" ]; then
            echo off
            return
        fi
    done

    echo on
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
    service rspamd restart &>/dev/null
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
    declare -a MENU_RSPAMD_CONFIG
    declare CONFIG DIALOG_RET RET_CODE FILE_CONFIG

    MENU_RSPAMD_CONFIG=()

    for CONFIG in "${RSPAMD_CONFIG[@]}"; do
        MENU_RSPAMD_CONFIG+=("$CONFIG" "$(eval echo \"\$LABEL_CONFIG_RSPAMD_${CONFIG^^}\")")
    done

    while true; do
        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --ok-label 'Select' --no-tags --extra-button --extra-label 'Help' --menu 'Choose Rspamd config to edit' 0 0 0 "${MENU_RSPAMD_CONFIG[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            edit_config "$(eval echo \"\$CONFIG_RSPAMD_${DIALOG_RET^^}\")" && systemctl reload rspamd &>/dev/null
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

    check_installed_peer && MENU_FAIL2BAN_CONFIG+=("$TAG_SYNC" 'Sync cluster')

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
    declare -r INFO="$(cat /var/log/apt/history.log)"

    show_info 'Install log' "$INFO"
}

# show pending updates
# parameters:
# none
# return values:
# none
show_update() {
    declare INFO
    
    INFO="$(apt list --upgradable 2>/dev/null | grep 'upgradable' | awk 'match($0, /([^/]+)\S+ (\S+)/, a) {print a[1]" ("a[2]")"}')"
    [ -z "$INFO" ] && INFO='No pending updates'

    show_info 'Pending updates' "$INFO"
}

# check whether distro is Ubuntu
# parameters:
# none
# return values:
# stderr - 0 if Ubuntu else 1
check_ubuntu() {
    cat /proc/version | grep -q 'Ubuntu'
}

# set setting
# parameters:
# $1 - setting
# return values:
# none
set_menu_setting() {
    sed -i -E "s/(declare -g $(echo "$1" | awk -F= '{print $1}')=)\S+/\1$(echo "$1" | awk -F= '{print $2}')/" "$0"
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
            if [ "$(eval echo \"\$EMAIL_${EMAIL_ADDRESS^^}_CHECK\")" != 1 ] || "check_installed_$EMAIL_ADDRESS"; then
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

# install Postfix
# parameters:
# none
# return values:
# none
install_postfix() {
    show_wait
    apt install -y postfix &>/dev/null
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

    show_wait
    apt install -y bind9 &>/dev/null

    printf '%s' $PACKED_CONFIG | base64 -d | gunzip > "$CONFIG_RESOLVER"
    mkdir -p /var/log/named
    systemctl restart bind9 &>/dev/null
}

# install Postfwd
# parameters:
# none
# return values:
# none
install_postfwd() {
    declare -r POSTFWD_USER='postfwd'

    show_wait

    groupadd "$POSTFWD_USER" &>/dev/null
    useradd -g "$POSTFWD_USER" "$POSTFWD_USER" &>/dev/null

    mkdir -p /usr/local/postfwd/sbin
    wget "$INSTALL_POSTFWD_LINK" -O - 2>/dev/null > /usr/local/postfwd/sbin/postfwd
    chmod +x /usr/local/postfwd/sbin/postfwd
    wget https://raw.githubusercontent.com/postfwd/postfwd/master/bin/postfwd-script.sh -O - 2>/dev/null | sed "s/nobody/$POSTFWD_USER/" > /etc/init.d/postfwd
    chmod +x /etc/init.d/postfwd

    apt install -y libnet-server-perl libnet-dns-perl &>/dev/null

    systemctl daemon-reload &>/dev/null
    systemctl start postfwd &>/dev/null
    update-rc.d postfwd defaults
}

# install Spamassassin
# parameters:
# none
# return values:
# none
install_spamassassin() {
    show_wait
    apt install -y geoip-bin geoip-database geoip-database-extra cpanminus libbsd-resource-perl libdbi-perl libencode-detect-perl libgeo-ip-perl liblwp-useragent-determined-perl libmail-dkim-perl libnet-cidr-perl libdigest-sha-perl libnet-patricia-perl monit postfix postfix-pcre sa-compile spamassassin spamc spf-tools-perl redis-server &>/dev/null
}

# install Rspamd
# parameters:
# none
# return values:
# none
install_rspamd() {
    declare CODENAME

    show_wait
    apt-get install -y lsb-release wget &>/dev/null
    CODENAME="$(lsb_release -c -s)"
    wget -O- https://rspamd.com/apt-stable/gpg.key 2>/dev/null | apt-key add - &>/dev/null
    echo "deb [arch=amd64] http://rspamd.com/apt-stable/ $CODENAME main" > /etc/apt/sources.list.d/rspamd.list
    echo "deb-src [arch=amd64] http://rspamd.com/apt-stable/ $CODENAME main" >> /etc/apt/sources.list.d/rspamd.list
    apt-get update &>/dev/null
    apt-get --no-install-recommends install -y rspamd &>/dev/null
}

# install Pyzor
# parameters:
# none
# return values:
# none
install_pyzor() {
    show_wait
    apt install -y pyzor &>/dev/null
}

# install Razor
# parameters:
# none
# return values:
# none
install_razor() {
    show_wait
    apt install -y razor &>/dev/null
}

# install Fail2ban
# parameters:
# none
# return values:
# none
install_fail2ban() {
    show_wait
    apt install -y fail2ban &>/dev/null
}

# install OpenDKIM
# parameters:
# none
# return values:
# none
install_dkim() {
    show_wait
    apt install -y opendkim &>/dev/null
}

# install SPF-check
# parameters:
# none
# return values:
# none
install_spf() {
    show_wait
    apt install -y postfix-policyd-spf-python &>/dev/null
}

# install Logwatch
# parameters:
# none
# return values:
# none
install_logwatch() {
    show_wait
    apt install -y logwatch &>/dev/null
}

# install log-manager
# parameters:
# none
# return values:
# none
install_logmanager() {
    declare -r PACKED_SCRIPT='
    H4sIAGGPzl0AA8VXbXPaRhD+zq/YCAiQWGDy1iapZ+rYJGbGph0cp01tlzlLB7qxdKfcnWzjNP+9
    u6cXBCadfuhMPZOgl719eXaf3VXz0eBKyMEVM1Gj0YRYLWYJk2zBdd9E8GnYf9bfbTTxzYFKl1os
    IgvdoAfPdoc/+vjfa5hwe6AknEnLteRRwqW54prZTC7gQ3J1tAOS20BJH/+ZLLZCLvqBSpzO/cxG
    Sr+BE6YDOBRcXxsuoZv0w+L6561ne+TpIRPxErSyzAq0z2QIqCUSNyyGudJww7RQmaGIYC5ibsCZ
    nCjLzRu8mPIvmdD42PIkjRk+dcdW4lbBFYeQz4XkIQgJT9C2nBdv8X6Avg20WRo80w+d9t8i9N9G
    3KkRJncPTzPrnl7xhZASowA1B4bA3ELIljvFZWna+UHiQaY1l7aUI4WB5rlCDLe0M9cqoRu0n2p+
    46IuxEWS8FDgCYSKhSEexKjoXA4V78PHCMUSzqSpP4dbEcfA4lu2RJtKWobxMnyE9ij2IM5CCgPT
    Z3jdgZgZC893yb6B20gEEapEtbFRwG4wZewKAxQyFDcizFDjst9ohDyIScpfgK/hcDydTU8/nx7/
    8mGvs45xZ0P09OwdSe9PD47Gn0Z7ncL7TbGT/fHxbDo6GP86Hk0+7nW0UnZTBq3N9j+M9p7vbrwo
    lOcvX718oPr32fvx8eh0/Mdob7j77AU0qTRO3i0t3xD9bX86GU8+zI4OD/devczl2ljJ/9cfkQgp
    FgJPMC9UGGWtax6IVFDl3QobgUnxfi7wRcKNwdZAhcY0SzhS3nGpNQS/9lJzm2mJDIyznGtSSd7g
    Wis9I1vdHnxtAP7xIFLgtYYe/AXOCd+Ad36sFn7Rgy7PW10sMSvRWO8SSNJrrafTa3yjSIKIB9c5
    fYy450Swld/uMVHGxSuVxcdB3jfy4MUcK1ejQSxjJisgEna3PVankJz6brTOnxnJzcifKmS0dI4x
    dPldquk3NuDHJQbs9ho6X1MtEPrWy2+dngcDGO6++PHlD6/w2l9YF/6q5Dy4fEvMk063g7RCGbz3
    5GWnNewAvws4Dw0FtMLIc4fmog5gZjDsUJhrRI8FeSsi3g9CfjMw4e//FYoOo3/GjryYOS8q8I7H
    px8dfxC4cI6ALTRPwfuz8O4BhEOCsJGHiYEcjj6ND0akgLjXKrW9hVBV+J2dItG32GitDm/LFD6y
    GvwQvLZXmqylu9JaJrHWDB7mcDOPR0yHLicZEcyF0ln506FGv7LQ9io9mFr6CQnTb/9zp0nYNVIQ
    YoHzAbnp5kg+N6rxWxu1q6nqkkSjANPhMuFH4HPwymNdYuEetYXa3Bh4xawuEpUwG0Td1u4ODP4s
    D150+0+MxQQu9rzuxenTnt++aH0e7U/bdHHyy+Tjkbs63P/c7qMvXv/JRW+AsxqLMc87Ox9e5gXm
    suzfoxOlu+tJRXYxiYTBjNCaIperqHcAJ+N6G2ZhIvJz9SKYKDfs/xmuPPf8TlgYNjD9CDxVC2c4
    h6v1opzxNO+xNPI0LLlBbtLaQAzP14xiL3EyGysJCTZwvqM6FA2RmZNRxSPKRJGyUGhKkENmMiJq
    kAC1r9lk/2REIrh68i0y9cGeJ5cS21of+QXTmq71YHxojgdW6SW6ghAR5AiGsTtlRAhMN2Jpilsq
    xoV4aKxHncle2ZwfUSbDopxKKw8YmlyjJfDTDbkc/djwSrAJC27dpKCqr0DurPZSB6tZJrGQ15Aq
    LCxaPSsFtJccnE2ntLggWAS2k1xBUqTE1WjPq1kOqdtiKfHKfqBQ1KRKuuWtqIPqhMvKOuTF3QDn
    VT6qa+54W9iFPLoY5Gw63/VfXz69ILe2saZvma71ySatpzVM1APvco7N0Ye6n/3F/fb+2azKnMUE
    2jIvBEN0c/lH4ti1E4tM3ot0i/41KXQb/IMV/NjQ9aZT1I3WyroGWm9d3eKhyZXAWiV9x3hwvxWS
    f+UANYjyemNf2TjUqIs3SzI9+GipdwdqI1kaklytwlf0zxtE1Ql87BUk+7T92W8nfjvsuYJ28lZl
    2L9qTaBUkL+OJe6N863vv0OTMg6jEB6crFYrA13XKe8Y9lcOZ1eZtFmPWgPkzRX7tqH1SBf3b/If
    pykfTF+gkz/r5J+GKTPmNoTHjxFcdSvXz20Pp1EyN0bu5kNSxWG5UBXfKEUyZLhWCC7VnSd9Z9+3
    yxRTAn5iBT5+mmcTz6Igv+MB6MTV7ddvcPF23WhBmzXDtW+gTeNVyVcOYJFiCW7zoaZmqx+0qMBP
    8FPVbMphih/8mzth42/GjHjpuRAAAA==
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
    declare CRONTAB_CURRENT

    mkdir -p "$(dirname "$SCRIPT_REBOOT")"
    printf '%s' $PACKED_SCRIPT | base64 -d | gunzip | sed "s/__HOST_NAME__/$(hostname -f)/g" > "$SCRIPT_REBOOT"

    CRONTAB_CURRENT="$(crontab -l)"

    echo "$CRONTAB_CURRENT" | grep -q "$CRONTAB_REBOOT" || echo "$CRONTAB_CURRENT"$'\n'"$CRONTAB_REBOOT" | crontab -
}

# setup peer
# parameters:
# none
# return values:
# none
install_peer() {
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
                    which sshpass &>/dev/null || apt install -y sshpass &>/dev/null

                    sshpass -p "$PASSWORD" ssh-copy-id -p "$SSH_PORT" -o 'StrictHostKeyChecking=accept-new' -i "$SSH_KEY" "root@$IP_ADDRESS" &>/dev/null
                fi

                if [ "$?" = 0 ]; then
                    echo $'\n''Host mx'$'\n\t'"HostName $IP_ADDRESS"$'\n\t''User root'$'\n\t'"Port $SSH_PORT"$'\n\t'"IdentityFile $SSH_KEY"$'\n' >> "$CONFIG_SSH"

                    IP_ADDRESS="$(hostname -I | awk '{print $1}')"

                    ssh mx "[ -f '$SSH_KEY' ] || ssh-keygen -t ed25519 -N '' -f '$SSH_KEY' &>/dev/null; echo $'\n''Host mx'$'\n\t''HostName $IP_ADDRESS'$'\n\t''User root'$'\n\t''Port $SSH_PORT'$'\n\t''IdentityFile $SSH_KEY' >> '$CONFIG_SSH'; ssh-keyscan -H $IP_ADDRESS 2>/dev/null | grep ecdsa-sha2-nistp256 >> '$HOME/.ssh/known_hosts'; cat '$SSH_KEY.pub'" >> "$HOME/.ssh/authorized_keys"
                fi
            fi
        fi
    fi
}

# select feature to install in dialog menu
# parameters:
# none
# return values:
# none
menu_install() {
    declare -a MENU_INSTALL
    declare NAME_PACKAGE PACKAGE_INFO 

    while true; do
        MENU_INSTALL=()

        for FEATURE in "${INSTALL_FEATURE[@]}"; do
            if "check_installed_${FEATURE}"; then
                NAME_PACKAGE="$(eval echo \"\$INSTALL_${FEATURE^^}_PACKAGE\")"

                if [ -z "$NAME_PACKAGE" ]; then
                    if [ "$(eval echo \"\$INSTALL_${FEATURE^^}_CUSTOM\")" = 1 ]; then
                        VERSION_CURRENT="$(check_version_$FEATURE)"
                        VERSION_AVAILABLE="$(check_update_$FEATURE)"

                        if [ "$VERSION_CURRENT" = "$VERSION_AVAILABLE" ]; then
                            MENU_INSTALL+=("$FEATURE" "$(eval echo \"\$LABEL_INSTALL_${FEATURE^^}\") ($VERSION_CURRENT installed)")
                        else
                            MENU_INSTALL+=("$FEATURE" "$(eval echo \"\$LABEL_INSTALL_${FEATURE^^}\") ($VERSION_CURRENT installed, $VERSION_AVAILABLE available)")
                        fi
                    else
                        MENU_INSTALL+=("$FEATURE" "$(eval echo \"\$LABEL_INSTALL_${FEATURE^^}\") (installed)")
                    fi
                else
                    PACKAGE_INFO="$(apt-cache policy "$NAME_PACKAGE")"
                    VERSION_CURRENT="$(echo "$PACKAGE_INFO" | sed -n '2p' | sed -E 's/^.+\s+//')"
                    VERSION_AVAILABLE="$(echo "$PACKAGE_INFO" | sed -n '3p' | sed -E 's/^.+\s+//')"

                    if [ "$VERSION_CURRENT" = "$VERSION_AVAILABLE" ]; then
                        MENU_INSTALL+=("$FEATURE" "$(eval echo \"\$LABEL_INSTALL_${FEATURE^^}\") ($VERSION_CURRENT installed)")
                    else
                        MENU_INSTALL+=("$FEATURE" "$(eval echo \"\$LABEL_INSTALL_${FEATURE^^}\") ($VERSION_CURRENT installed, $VERSION_AVAILABLE available)")
                    fi
                fi
            else
                MENU_INSTALL+=("$FEATURE" "$(eval echo \"\$LABEL_INSTALL_${FEATURE^^}\")")
            fi
        done

        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --no-tags --extra-button --extra-label 'Help' --title '' --menu '' 0 0 0 "${MENU_INSTALL[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            if "check_installed_$DIALOG_RET"; then
                NAME_PACKAGE="$(eval echo \"\$INSTALL_${DIALOG_RET^^}_PACKAGE\")"

                if [ -z "$NAME_PACKAGE" ]; then
                    get_yesno "'$(eval echo \"\$LABEL_INSTALL_${DIALOG_RET^^}\")' already installed. Re-install?"

                    [ "$?" = 0 ] && "install_$DIALOG_RET"
                else
                    PACKAGE_INFO="$(apt-cache policy "$NAME_PACKAGE")"
                    VERSION_CURRENT="$(echo "$PACKAGE_INFO" | sed -n '2p' | sed -E 's/^.+\s+//')"
                    VERSION_AVAILABLE="$(echo "$PACKAGE_INFO" | sed -n '3p' | sed -E 's/^.+\s+//')"

                    if [ "$VERSION_CURRENT" = "$VERSION_AVAILABLE" ]; then
                        get_yesno "'$(eval echo \"\$LABEL_INSTALL_${DIALOG_RET^^}\")' already installed. Re-install?"

                        [ "$?" = 0 ] && "install_$DIALOG_RET"
                    else                        
                        get_yesno "Install '$(eval echo \"\$LABEL_INSTALL_${DIALOG_RET^^}\")' update?"

                        if [ "$?" = 0 ]; then
                            show_wait

                            apt update "$NAME_PACKAGE" &>/dev/null
                        fi
                    fi
                fi
            else
                get_yesno "Install '$(eval echo \"\$LABEL_INSTALL_${DIALOG_RET^^}\")'?"

                [ "$?" = 0 ] && "install_$DIALOG_RET"
            fi
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
    check_installed_peer && MENU_POSTFIX+=("$TAG_SYNC" "$LABEL_SYNC")

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
    declare -r LABEL_CONFIG='Config'
    declare -r LABEL_FORWARD='Forward zones'
    declare -r LABEL_LOCAL='Local zones'
    declare -r LABEL_SYNC='Sync cluster'
    declare -a MENU_RESOLVER

    MENU_RESOLVER=()
    MENU_RESOLVER+=("$TAG_CONFIG" "$LABEL_CONFIG")
    MENU_RESOLVER+=("$TAG_FORWARD" "$LABEL_FORWARD")
    MENU_RESOLVER+=("$TAG_LOCAL" "$LABEL_LOCAL")
    check_installed_peer && MENU_RESOLVER+=("$TAG_SYNC" "$LABEL_SYNC")

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
    declare -r LABEL_CONFIG='Config'
    declare -r LABEL_SYNC='Sync cluster'
    declare -a MENU_POSTFWD

    MENU_POSTFWD=()
    MENU_POSTFWD+=("$TAG_CONFIG" "$LABEL_CONFIG")
    check_installed_peer && MENU_POSTFWD+=("$TAG_SYNC" "$LABEL_SYNC")

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
    declare -r LABEL_CONFIG='Config'
    declare -r LABEL_SYNC='Sync cluster'
    declare -a MENU_DKIM

    MENU_DKIM=()
    MENU_DKIM+=("$TAG_CONFIG" "$LABEL_CONFIG")
    check_installed_peer && MENU_DKIM+=("$TAG_SYNC" "$LABEL_SYNC")

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
    declare -r LABEL_CONFIG='Config'
    declare -r LABEL_SYNC='Sync cluster'
    declare -a MENU_SPF

    MENU_SPF=()
    MENU_SPF+=("$TAG_CONFIG" "$LABEL_CONFIG")
    check_installed_peer && MENU_SPF+=("$TAG_SYNC" "$LABEL_SYNC")

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
    declare -r TAG_CONFIG='spamassassin_config'
    declare -r TAG_INFO='spamassassin_info'
    declare -r TAG_SYNC='spamassassin_sync'
    declare -r LABEL_CONFIG='Config'
    declare -r LABEL_INFO='Info & Stats'
    declare -r LABEL_SYNC='Sync cluster'
    declare -a MENU_SPAMASSASSIN

    MENU_SPAMASSASSIN=()
    MENU_SPAMASSASSIN+=("$TAG_CONFIG" "$LABEL_CONFIG")
    MENU_SPAMASSASSIN+=("$TAG_INFO" "$LABEL_INFO")
    check_installed_peer && MENU_SPAMASSASSIN+=("$TAG_SYNC" "$LABEL_SYNC")

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
    declare -r LABEL_FEATURE='Feature'
    declare -r LABEL_CONFIG='Config'
    declare -r LABEL_INFO='Info & Stats'
    declare -r LABEL_SYNC='Sync cluster'
    declare -a MENU_RSPAMD

    MENU_RSPAMD=()
    MENU_RSPAMD+=("$TAG_FEATURE" "$LABEL_FEATURE")
    MENU_RSPAMD+=("$TAG_CONFIG" "$LABEL_CONFIG")
    MENU_RSPAMD+=("$TAG_INFO" "$LABEL_INFO")
    check_installed_peer && MENU_RSPAMD+=("$TAG_SYNC" "$LABEL_SYNC")

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
    declare -r LABEL_CONFIG='Config'
    declare -r LABEL_JAIL='Jails'
    declare -r LABEL_SYNC='Sync cluster'
    declare -a MENU_FAIL2BAN

    MENU_FAIL2BAN=()
    MENU_FAIL2BAN+=("$TAG_CONFIG" "$LABEL_CONFIG")
    MENU_FAIL2BAN+=("$TAG_JAIL" "$LABEL_JAIL")
    check_installed_peer && MENU_FAIL2BAN+=("$TAG_SYNC" "$LABEL_SYNC")

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
    declare -r TAG_UPDATES='automatic_update'
    declare -r TAG_CONNECTIONS='show_connections'
    declare -r TAG_FIREWALL='show_firewall'
    declare -r TAG_INSTALL='show_install'
    declare -r TAG_UPDATE='show_update'
    declare -r LABEL_EDITOR='Set text editor'
    declare -r LABEL_EMAIL='Set notification addresses'
    declare -r LABEL_UPDATES='Automatic update'
    declare -r LABEL_CONNECTIONS='Network connections'
    declare -r LABEL_FIREWALL='Firewall rules'
    declare -r LABEL_INSTALL='Install log'
    declare -r LABEL_UPDATE='Pending updates'
    declare -a MENU_MISC

    while true; do
        MENU_MISC=()
        MENU_MISC+=("$TAG_EDITOR" "$LABEL_EDITOR")
        MENU_MISC+=("$TAG_EMAIL" "$LABEL_EMAIL")
        automatic_update_status && MENU_MISC+=("$TAG_UPDATES" "$LABEL_UPDATES (enabled)") || MENU_MISC+=("$TAG_UPDATES" "$LABEL_UPDATES (disabled)")
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
        if [ "$(eval echo \"\$LOG_${PROGRAM_LOG^^}_CHECK\")" != 1 ] || check_installed_$PROGRAM_LOG; then
            MENU_LOG+=("$PROGRAM_LOG" "$(eval echo \"\$LOG_${PROGRAM_LOG^^}_LABEL\")")
        fi
    done

    while true; do
        exec 3>&1
        PROGRAM_LOG="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --no-tags --extra-button --extra-label 'Help' --title '' --menu '' 0 0 0 "${MENU_LOG[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            exec 3>&1
            SEARCH_FILTER="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --title 'Search logs' --ok-label 'Current log' --extra-button --extra-label 'All logs' --inputbox 'Enter search filter' 0 0 '' 2>&1 1>&3)"
            RET_CODE="$?"
            exec 3>&-

            if ! [ -z "$SEARCH_FILTER" ]; then
                if [ "$RET_CODE" = 0 ] || [ "$RET_CODE" = 3 ]; then
                    if [ "$RET_CODE" = 0 ]; then
                        SEARCH_RESULT="$(grep "$SEARCH_FILTER" "$(eval echo \"\$LOG_${PROGRAM_LOG^^}_DIR\")/current.log")"
                    else
                        SEARCH_RESULT="$(grep "$SEARCH_FILTER" -h "$(eval echo \"\$LOG_${PROGRAM_LOG^^}_DIR\")"/*.log)"
                    fi

                    [ -z "$SEARCH_RESULT" ] && SEARCH_RESULT='No result'

                    show_info 'Search results' "$SEARCH_RESULT"
                fi
            fi
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
    wget "$LINK_UPDATE" -O "$TMP_UPDATE" &>/dev/null

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
                INFO_START=$(expr $(grep -n '# Changelog:' $TMP_UPDATE | head -1 | awk -F: '{print $1}') + 1)
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
        echo '#88.198.215.226    permit' >> $CONFIG_POSTFIX_POSTSCREEN
        echo '#85.10.249.206     permit' >> $CONFIG_POSTFIX_POSTSCREEN
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
}

# root menu, select option in dialog menu
# parameters:
# none
# return values:
# none
declare -r CONFIG_BASH="$HOME/.bashrc"
declare -r TAG_MENU_INSTALL='menu_install'
declare -r TAG_MENU_POSTFIX='menu_postfix'
declare -r TAG_MENU_ADDON='menu_addon'
declare -r TAG_MENU_MISC='menu_misc'
declare -r TAG_MENU_LOG='menu_log'
declare -r TAG_MENU_SYNC_ALL='sync_all'
declare -r LABEL_MENU_INSTALL='Install'
declare -r LABEL_MENU_POSTFIX='Postfix'
declare -r LABEL_MENU_ADDON='Addon'
declare -r LABEL_MENU_MISC='Misc'
declare -r LABEL_MENU_LOG='Log files'
declare -r LABEL_SYNC_ALL='Sync cluster'
declare -a MENU_MAIN
declare DIALOG_RET RET_CODE TAG_ADDON

if ! check_ubuntu; then
    show_info 'Incompatible Linux distro' 'This tool only supports Ubuntu 18.04 or later.'
    clear
    exit 1
fi

if ! [ -f "$CONFIG_BASH" ] || ! grep -q "alias menu=$HOME/menu.sh" "$CONFIG_BASH"; then
    echo "alias menu=$HOME/menu.sh" >> "$CONFIG_BASH"
fi

check_update
write_examples

while true; do
    MENU_MAIN=()
    MENU_MAIN+=("$TAG_MENU_INSTALL" "$LABEL_MENU_INSTALL")
    check_installed_postfix && MENU_MAIN+=("$TAG_MENU_POSTFIX" "$LABEL_MENU_POSTFIX")
    for TAG_ADDON in "${ADDON_CONFIG[@]}"; do
        if "check_installed_$TAG_ADDON"; then
            MENU_MAIN+=("$TAG_MENU_ADDON" "$LABEL_MENU_ADDON")
            break
        fi
    done
    MENU_MAIN+=("$TAG_MENU_MISC" "$LABEL_MENU_MISC")
    check_installed_logmanager && MENU_MAIN+=("$TAG_MENU_LOG" "$LABEL_MENU_LOG")
    check_installed_peer && MENU_MAIN+=("$TAG_SYNC_ALL" "$LABEL_SYNC_ALL")

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
clear
