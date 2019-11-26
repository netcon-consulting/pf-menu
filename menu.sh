#!/bin/bash

# menu.sh V1.0.0 for Postfix
#
# Copyright (c) 2019 NetCon Unternehmensberatung GmbH, netcon-consulting.com
#
# Authors:
# Marc Dierksen (m.dierksen@netcon-consulting.com)
# Iyad Dassouki (i.dassouki@netcon-consulting.com)

###################################################################################################
# NetCon Postfix Made Easy
#
# This tool will help with various setup tasks for mailservers supporting the configuration of
# Postfix, Postfwd, OpenDKIM, SPF-check, Spamassassin, Rspamd and Fail2ban.
#
# Changelog:
# - initial release
#
###################################################################################################

declare -g -r VERSION_MENU="$(grep '^# menu.sh V' "$0" | awk '{print $3}')"
declare -g -r DIALOG='dialog'
declare -g -r TXT_EDITOR='vim'
declare -g -r LINK_GITHUB='https://raw.githubusercontent.com/netcon-consulting/pf-menu/master'
declare -g -r LINK_UPDATE="$LINK_GITHUB/menu.sh"
declare -g -r TITLE_MAIN='NetCon Postfix Made Easy'
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
declare -g -r CRON_RULES='/etc/cron.daily/update_rules.sh'
declare -g -r CONFIG_SSH="$HOME/.ssh/config"

###################################################################################################
# Install features
declare -g -a INSTALL_FEATURE

INSTALL_FEATURE=()
INSTALL_FEATURE+=('postfwd')
INSTALL_FEATURE+=('spamassassin')
INSTALL_FEATURE+=('rspamd')
INSTALL_FEATURE+=('fail2ban')
INSTALL_FEATURE+=('dkim')
INSTALL_FEATURE+=('spf')
INSTALL_FEATURE+=('logmanager')
INSTALL_FEATURE+=('peer')

declare -g -r LABEL_INSTALL_POSTFWD='Postfwd'
declare -g -r LABEL_INSTALL_SPAMASSASSIN='Spamassassin'
declare -g -r LABEL_INSTALL_RSPAMD='Rspamd'
declare -g -r LABEL_INSTALL_FAIL2BAN='Fail2ban'
declare -g -r LABEL_INSTALL_DKIM='OpenDKIM'
declare -g -r LABEL_INSTALL_SPF='SPF-check'
declare -g -r LABEL_INSTALL_LOGMANAGER='Log-manager'
declare -g -r LABEL_INSTALL_PEER='Setup peer'

###################################################################################################
# Postfix configs
declare -g -a POSTFIX_CONFIG

POSTFIX_CONFIG=()
POSTFIX_CONFIG+=('postscreen')
POSTFIX_CONFIG+=('client')
POSTFIX_CONFIG+=('sender')
POSTFIX_CONFIG+=('recipient')
POSTFIX_CONFIG+=('helo')
POSTFIX_CONFIG+=('transport')
POSTFIX_CONFIG+=('esmtp')
POSTFIX_CONFIG+=('rewrite')
POSTFIX_CONFIG+=('routing')
POSTFIX_CONFIG+=('milter')
POSTFIX_CONFIG+=('header')

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

# Transport map
declare -g -r LABEL_CONFIG_POSTFIX_TRANSPORT='Transport map'
declare -g -r CONFIG_POSTFIX_TRANSPORT="$DIR_MAPS/transport"

# ESMTP restrictions
declare -g -r LABEL_CONFIG_POSTFIX_ESMTP='ESMTP restrictions'
declare -g -r CONFIG_POSTFIX_ESMTP="$DIR_MAPS/esmtp_access"

# Sender rewriting
declare -g -r LABEL_CONFIG_POSTFIX_REWRITE='Sender rewriting'
declare -g -r CONFIG_POSTFIX_REWRITE="$DIR_MAPS/sender_canonical_maps"

# Sender-dependent routing
declare -g -r LABEL_CONFIG_POSTFIX_ROUTING='Sender-dependent routing'
declare -g -r CONFIG_POSTFIX_ROUTING="$DIR_MAPS/relayhost_map"

# Milter bypass
declare -g -r LABEL_CONFIG_POSTFIX_MILTER='Milter bypass'
declare -g -r CONFIG_POSTFIX_MILTER="$DIR_MAPS/smtpd_milter_map"

# Header checks
declare -g -r LABEL_CONFIG_POSTFIX_HEADER='Header checks'
declare -g -r CONFIG_POSTFIX_HEADER="$DIR_MAPS/check_header"

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
POSTFIX_FEATURE+=('postscreen')
POSTFIX_FEATURE+=('psdeep')
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

POSTFIX_HEADER+=("header_checks = regexp:$DIR_MAPS/check_header")

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

# Recipient restrictions
declare -g -r RECIPIENT_ACCESS="check_client_access cidr:$CONFIG_POSTFIX_CLIENT, check_sender_access regexp:$CONFIG_POSTFIX_SENDER, check_recipient_access regexp:$CONFIG_POSTFIX_RECIPIENT, check_helo_access regexp:$CONFIG_POSTFIX_HELO"

declare -g -r POSTFIX_RECIPIENT_LABEL='Recipient restrictions'
declare -g -r POSTFIX_RECIPIENT_CUSTOM=1
declare -g -r POSTFIX_RECIPIENT_FORCE=1

POSTFIX_RECIPIENT+=('smtpd_delay_reject=yes')
POSTFIX_RECIPIENT+=('smtpd_helo_required=yes')

# Postfwd
declare -g -r POSTFWD_ACCESS='check_policy_service inet:127.0.0.1:10040'

declare -g -r POSTFIX_POSTFWD_LABEL='Postfwd'
declare -g -r POSTFIX_POSTFWD_CHECK=1
declare -g -r POSTFIX_POSTFWD_CUSTOM=1

POSTFIX_POSTFWD+=('127.0.0.1:10040_time_limit=3600')

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
# Postfix plugin configs
declare -g -a POSTFIX_PLUGIN

POSTFIX_PLUGIN=()
POSTFIX_PLUGIN+=('postfwd')
POSTFIX_PLUGIN+=('dkim')
POSTFIX_PLUGIN+=('spf')

# Postfwd
declare -g -r LABEL_CONFIG_PLUGIN_POSTFWD='Postfwd'
declare -g -r CONFIG_PLUGIN_POSTFWD='/etc/postfix/postfwd.cf'

# OpenDKIM
declare -g -r LABEL_CONFIG_PLUGIN_DKIM='OpenDKIM'
declare -g -r CONFIG_PLUGIN_DKIM='/etc/opendkim.conf'

# SPF
declare -g -r LABEL_CONFIG_PLUGIN_SPF='SPF-check'
declare -g -r CONFIG_PLUGIN_SPF='/etc/postfix-policyd-spf-python/policyd-spf.conf'

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

# phishing detection
declare -g -r RSPAMD_PHISHING_LABEL='Phishing detection'

RSPAMD_PHISHING+=('phishtank_enabled = true;' "$CONFIG_RSPAMD_PHISHING")
RSPAMD_PHISHING+=('phishtank_map = "https://rspamd.com/phishtank/online-valid.json.zst";' "$CONFIG_RSPAMD_PHISHING")

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

* Postfwd - Install Postfwd
* Spamassassin - Install Spamassassin
* Rspamd - Install Rspamd
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
* Postfwd (if installed) - Enable Postfwd
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
* Phishing detection - Enable detection of phishing attempts'

declare -g -r HELP_RSPAMD_CONFIG='Select Rspamd config to edit. Sync option only available if peer setup.'

declare -g -r HELP_FAIL2BAN_CONFIG='Select Fail2ban config to edit. Sync option only available if peer setup.'

declare -g -r HELP_OTHER_INFO='Show other info and stats.

* Network connections - Show network connections
* Firewall rules - Show currently active firewall rules'

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
# $3 - default
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

# select file in dialog fselect (IMPORTANT: function call needs to be preceeded by 'exec 3>&1' and followed by 'exec 3>&-')
# parameters:
# $1 - dialog title
# $2 - directory
# return values:
# stdout - selected file path
# error code - 0 for Ok, 1 for Cancel
get_file() {
    declare DIALOG_RET RET_CODE

    DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --title "$1" --fselect "$2" 14 58 2>&1 1>&3)"
    RET_CODE="$?"

    if [ "$RET_CODE" = 0 ]; then
        if [ -f "$DIALOG_RET" ]; then
            echo "$DIALOG_RET"
        else
            show_info 'File error' "Selected file '$DIALOG_RET' does not exist." 2>&1 1>&3
            return 1
        fi
    fi

    return "$RET_CODE"
}

# check whether postfwd is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_postfwd() {
    which postfwd &>/dev/null
    [ "$?" = 0 ] && return 0 || return 1
}

# check whether spamassassin is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_spamassassin() {
    which spamassassin &>/dev/null
    [ "$?" = 0 ] && return 0 || return 1
}

# check whether rspamd is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_rspamd() {
    which rspamd &>/dev/null
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

# check whether log-manager is installed
# parameters:
# none
# return values:
# error code - 0 for installed, 1 for not installed
check_installed_logmanager() {
    [ -f "$CRON_LOGMANAGER" ] && return 0 || return 1
}

# check whether peer is available
# parameters:
# none
# return values:
# error code - 0 for peer available, 1 for not available
check_installed_peer() {
    if [ -f "$CONFIG_SSH"] && grep -q '^Host mx$' "$CONFIG_SSH"; then
        return 0
    else
        return 1
    fi
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
    if [ -z "$(postconf 'smtp_tls_cert_file' | sed -E "s/^smtp_tls_cert_file = ?//")" ]             \
        || [ -z "$(postconf 'smtp_tls_key_file' | sed -E "s/^smtp_tls_cert_file = ?//")" ]          \
        || [ -z "$(postconf 'smtpd_tls_cert_file' | sed -E "s/^smtpd_tls_cert_file = ?//")" ]       \
        || [ -z "$(postconf 'smtpd_tls_key_file' | sed -E "s/^smtpd_tls_cert_file = ?//")" ]; then
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

            postconf "smtp_tls_cert_file=$FILE_CERT"
            postconf "smtp_tls_key_file=$FILE_KEY"
            postconf "smtpd_tls_cert_file=$FILE_CERT"
            postconf "smtpd_tls_key_file=$FILE_KEY"

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
        postconf "$POSTFIX_SETTING=$(postconf -d "$POSTFIX_SETTING" | sed -E "s/^$POSTFIX_SETTING = ?//")"
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
        [ "$(postconf "$SETTING_KEY")" != "$(postconf -d "$SETTING_KEY")" ] && return 0
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
            postconf "$SETTING_KEY=$EMAIL_BOUNCE"
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
        postconf "$SETTING_KEY=$(postconf -d "$SETTING_KEY" | sed -E "s/^$SETTING_KEY = ?//")"
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
    postconf -Me '25/inet=25 inet n - n - 1 postscreen'
    postconf -Me 'smtpd/pass=smtpd pass - - n - - smtpd'
    postconf -Me 'dnsblog/unix=dnsblog unix - - n - 0 dnsblog'
    postconf -Me 'tlsproxy/unix=tlsproxy unix - - n - 0 tlsproxy'
}

# disable Postscreen
# parameters:
# none
# return values:
# none
postscreen_disable() {
    postconf -MX '25/inet'
    postconf -MX 'smtpd/pass'
    postconf -MX 'dnsblog/unix'
    postconf -MX 'tlsproxy/unix'
}

# check recipient restrictions status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 for disabled
recipient_status() {
    if [ "$(postconf 'smtpd_recipient_restrictions')" != "$(postconf -d 'smtpd_recipient_restrictions')" ]; then
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
    if [ "$(postconf 'address_verify_transport_maps' | sed -E 's/^address_verify_transport_maps = ?//')" = "hash:$CONFIG_POSTFIX_TRANSPORT" ]               \
        && [ -z "$(postconf 'address_verify_map' | sed -E 's/^address_verify_map = ?//')" ]                                                                 \
        && [ "$(postconf 'unverified_recipient_reject_reason' | sed -E 's/^unverified_recipient_reject_reason = ?//')" = "User doesn't exist" ]; then
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
    postconf "address_verify_transport_maps=hash:$CONFIG_POSTFIX_TRANSPORT"
    postconf 'address_verify_map='
    postconf "unverified_recipient_reject_reason=User doesn't exist"
}

# disable unverified recipient restriction
# parameters:
# none
# return values:
# none
unverified_disable() {
    postconf "address_verify_transport_maps=$(postconf -d 'address_verify_transport_maps')"
    postconf "address_verify_map=$(postconf -d 'address_verify_map')"
    postconf "unverified_recipient_reject_reason=$(postconf -d 'unverified_recipient_reject_reason')"
}

# enable recipient restrictions
# parameters:
# none
# return values:
# error code - 0 for changes made, 1 for no changes made
recipient_enable() {
    declare -a MENU_RESTRICTION
    declare RESTRICTION_CURRENT POSTFWD_ACTIVE LIST_RESTRICTION RESTRICTION DIALOG_RET RET_CODE RESTRICTION_NEW

    RESTRICTION_CURRENT="$(postconf 'smtpd_recipient_restrictions' | sed -E 's/^smtpd_recipient_restrictions = ?//')"

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
        [ "$POSTFWD_ACTIVE" = 1 ] && RESTRICTION_NEW+=" $POSTFWD_ACCESS"

        if [ "$RESTRICTION_NEW" != "$RESTRICTION_CURRENT" ]; then
            postconf "smtpd_recipient_restrictions=$RESTRICTION_NEW"

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
    declare -r RESTRICTION_DEFAULT="$(postconf -d 'smtpd_recipient_restrictions' | sed -E 's/^smtpd_recipient_restrictions = ?//')"

    if postfwd_status; then
        if [ -z "$RESTRICTION_DEFAULT" ]; then
            postconf "smtpd_recipient_restrictions=$POSTFWD_ACCESS"
        else
            postconf "smtpd_recipient_restrictions=$RESTRICTION_DEFAULT, $POSTFWD_ACCESS"
        fi
    else
        postconf "smtpd_recipient_restrictions=$RESTRICTION_DEFAULT"
    fi
}

# check Postfwd status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 for disabled
postfwd_status() {
    if postconf 'smtpd_recipient_restrictions' | sed -E 's/^smtpd_recipient_restrictions = ?//' 2>/dev/null | grep -E -q "(^| )$POSTFWD_ACCESS($|,)"; then
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
    postconf "smtpd_recipient_restrictions=$(postconf 'smtpd_recipient_restrictions' | sed -E 's/^smtpd_recipient_restrictions = ?//'), $POSTFWD_ACCESS"
}

# disable Postfwd
# parameters:
# none
# return values:
# none
postfwd_disable() {
    postconf "smtpd_recipient_restrictions=$(postconf 'smtpd_recipient_restrictions' | sed -E 's/^smtpd_recipient_restrictions = ?//' | sed -E "s/(, )?$POSTFWD_ACCESS//g")"
}

# check Spamassassin status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 for disabled
spamassassin_status() {
    if postconf -M 'smtpd/pass' 2>/dev/null | grep -q -E '^smtpd\s+pass\s+-\s+-\s+y\s+-\s+-\s+smtpd\s+ -o\s+ content_filter=spamassassin$'                                                                                                              \
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
    postconf -Me 'smtpd/pass=smtpd pass - - y - - smtpd -o content_filter=spamassassin'
    postconf -Me 'spamassassin/unix=spamassassin unix - n n - - pipe user=spamd argv=/usr/bin/spamc -s 1024000 -f -e /usr/sbin/sendmail -oi -f ${sender} ${recipient}'
}

# disable Spamassassin
# parameters:
# none
# return values:
# none
spamassassin_disable() {
    postconf -MX 'smtpd/pass'
    postconf -MX 'spamassassin/unix'
}

# check Rspamd status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 for disabled
rspamd_status() {
    if postconf smtpd_milters | sed -E 's/^smtpd_milters = ?//' | grep -q 'inet:127.0.0.1:11332'; then
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

    LIST_MILTER="$(postconf smtpd_milters | sed -E 's/^smtpd_milters = ?//')"

    [ -z "$LIST_MILTER" ] && LIST_MILTER='inet:127.0.0.1:11332' || LIST_MILTER+=', inet:127.0.0.1:11332'
    
    postconf "smtpd_milters=$LIST_MILTER"
}

# disable Rspamd
# parameters:
# none
# return values:
# none
rspamd_disable() {
    declare LIST_MILTER

    LIST_MILTER="$(postconf smtpd_milters | sed -E 's/^smtpd_milters = ?//')"

    if [ "$LIST_MILTER" = 'inet:127.0.0.1:11332' ]; then
        LIST_MILTER=''
    elif echo "$LIST_MILTER" | grep -E -q ', ?inet:127.0.0.1:11332'; then
        LIST_MILTER="$(echo "$LIST_MILTER" | sed -E 's/, ?inet:127.0.0.1:11332//')"
    else
        LIST_MILTER="$(echo "$LIST_MILTER" | sed -E 's/inet:127.0.0.1:11332, //')"
    fi

    postconf "smtpd_milters=$LIST_MILTER"
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
    postconf -Me 'policyd-spf/unix=policyd-spf unix - n n - 0 spawn user=policyd-spf argv=/usr/bin/policyd-spf'
}

# disable SPF-check
# parameters:
# none
# return values:
# none
spf_disable() {
    postconf -MX 'policyd-spf/unix'
}

# check Rspamd status
# parameters:
# none
# return values:
# error code - 0 for enabled, 1 for disabled
dkim_status() {
    if postconf smtpd_milters | sed -E 's/^smtpd_milters = ?//' | grep -q 'inet:127.0.0.1:10001'; then
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

    LIST_MILTER="$(postconf smtpd_milters | sed -E 's/^smtpd_milters = ?//')"

    [ -z "$LIST_MILTER" ] && LIST_MILTER='inet:127.0.0.1:10001' || LIST_MILTER+=', inet:127.0.0.1:10001'
    
    postconf "smtpd_milters=$LIST_MILTER"
}

# disable Rspamd
# parameters:
# none
# return values:
# none
dkim_disable() {
    declare LIST_MILTER

    LIST_MILTER="$(postconf smtpd_milters | sed -E 's/^smtpd_milters = ?//')"

    if [ "$LIST_MILTER" = 'inet:127.0.0.1:10001' ]; then
        LIST_MILTER=''
    elif echo "$LIST_MILTER" | grep -E -q ', ?inet:127.0.0.1:10001'; then
        LIST_MILTER="$(echo "$LIST_MILTER" | sed -E 's/, ?inet:127.0.0.1:10001//')"
    else
        LIST_MILTER="$(echo "$LIST_MILTER" | sed -E 's/inet:127.0.0.1:10001, //')"
    fi

    postconf "smtpd_milters=$LIST_MILTER"
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
        if [ "$(postconf "$SETTING_KEY" | sed -E "s/^$SETTING_KEY = ?//")" != "$(echo "$POSTFIX_SETTING" | sed "s/^$SETTING_KEY=//")" ]; then
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
        postconf "$POSTFIX_SETTING"
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
        postconf "$SETTING_KEY=$(postconf -d "$SETTING_KEY" | sed -E "s/^$SETTING_KEY = ?//")"
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

# sync Postfix config with other peer
# parameters:
# none
# return values:
# none
sync_postfix() {
    show_wait
    rsync -avzh -e ssh "$DIR_MAPS" mx:"$DIR_MAPS" &>/dev/null
    ssh mx postfix reload &>/dev/null
}

# select Postfix configuration file for editing in dialog menu
# parameters:
# none
# return values:
# none
postfix_config() {
    declare -r TAG_SYNC='sync'
    declare -r TMP_CONFIG='/tmp/TMPconfig'
    declare -a MENU_POSTFIX_CONFIG
    declare CONFIG DIALOG_RET RET_CODE FILE_CONFIG

    MENU_POSTFIX_CONFIG=()

    for CONFIG in "${POSTFIX_CONFIG[@]}"; do
        MENU_POSTFIX_CONFIG+=("$CONFIG" "$(eval echo \"\$LABEL_CONFIG_POSTFIX_${CONFIG^^}\")")
    done

    check_installed_peer && MENU_POSTFIX_CONFIG+=("$TAG_SYNC" 'Sync Postfix config')

    while true; do
        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --ok-label 'Select' --no-tags --extra-button --extra-label 'Help' --menu 'Choose Postfix config to edit' 0 0 0 "${MENU_POSTFIX_CONFIG[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            if [ "$DIALOG_RET" = "$TAG_SYNC" ]; then
                sync_postfix
            else
                FILE_CONFIG="$(eval echo \"\$CONFIG_POSTFIX_${DIALOG_RET^^}\")"

                if [ -f "$FILE_CONFIG" ]; then
                    cp -f "$FILE_CONFIG" "$TMP_CONFIG"
                else
                    touch "$TMP_CONFIG"
                fi

                "$TXT_EDITOR" "$TMP_CONFIG"

                diff -N -s "$TMP_CONFIG" "$FILE_CONFIG" &>/dev/null

                if [ "$?" != 0 ]; then
                    cp -f "$TMP_CONFIG" "$FILE_CONFIG"
                    postconf | grep -q "hash:$FILE_CONFIG" && postmap "$FILE_CONFIG"
                    postfix reload &>/dev/null
                fi

                rm -f "$TMP_CONFIG"
            fi
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$HELP_POSTFIX_CONFIG"
        else
            break
        fi
    done
}

# sync Postfix plugin config with other peer
# parameters:
# none
# return values:
# none
sync_plugin() {
    show_wait
    if check_installed_dkim; then
        rsync -avzh -e ssh "$CONFIG_PLUGIN_DKIM" mx:"$CONFIG_PLUGIN_DKIM" &>/dev/null
        ssh mx systemctl reload opendkim &>/dev/null
    fi
    if check_installed_spf; then
        rsync -avzh -e ssh "$CONFIG_PLUGIN_SPF" mx:"$CONFIG_PLUGIN_SPF" &>/dev/null
    fi
    if check_installed_postfwd; then
        rsync -avzh -e ssh "$CONFIG_PLUGIN_POSTFWD" mx:"$CONFIG_PLUGIN_POSTFWD" &>/dev/null
        ssh mx systemctl reload postfwd &>/dev/null
    fi
}

# select Postfix plugin configuration file for editing in dialog menu
# parameters:
# none
# return values:
# none
postfix_plugin() {
    declare -r TAG_SYNC='sync'
    declare -r TMP_CONFIG='/tmp/TMPconfig'
    declare -a MENU_POSTFIX_PLUGIN
    declare PLUGIN DIALOG_RET RET_CODE FILE_CONFIG

    MENU_POSTFIX_PLUGIN=()

    for PLUGIN in "${POSTFIX_PLUGIN[@]}"; do
        check_installed_${PLUGIN} && MENU_POSTFIX_PLUGIN+=("$PLUGIN" "$(eval echo \"\$LABEL_CONFIG_PLUGIN_${PLUGIN^^}\")")
    done

    check_installed_peer && MENU_POSTFIX_PLUGIN+=("$TAG_SYNC" 'Sync Postfix plugin config')

    while true; do
        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --ok-label 'Select' --no-tags --extra-button --extra-label 'Help' --menu 'Choose Postfix config to edit' 0 0 0 "${MENU_POSTFIX_PLUGIN[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            if [ "$DIALOG_RET" = "$TAG_SYNC" ]; then
                sync_plugin
            else
                FILE_CONFIG="$(eval echo \"\$CONFIG_PLUGIN_${DIALOG_RET^^}\")"

                if [ -f "$FILE_CONFIG" ]; then
                    cp -f "$FILE_CONFIG" "$TMP_CONFIG"
                else
                    touch "$TMP_CONFIG"
                fi

                "$TXT_EDITOR" "$TMP_CONFIG"

                diff -N -s "$TMP_CONFIG" "$FILE_CONFIG" &>/dev/null

                if [ "$?" != 0 ]; then
                    cp -f "$TMP_CONFIG" "$FILE_CONFIG"
                    case "$DIALOG_RET" in
                        'postfwd')
                            systemctl reload postfwd &>/dev/null;;
                        'dkim')
                            systemctl reload opendkim &>/dev/null;;
                    esac
                fi

                rm -f "$TMP_CONFIG"
            fi
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$HELP_POSTFIX_PLUGIN"
        else
            break
        fi
    done
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

# search Postfix logs and show results
# parameters:
# none
# return values:
# none
search_log() {
    declare DIALOG_RET RET_CODE INFO

    exec 3>&1
    DIALOG_RET="$($DIALOG --clear --backtitle "$TITLE_MAIN" --inputbox 'Enter search string' 0 0 2>&1 1>&3)"
    RET_CODE=$?
    exec 3>&-
    if [ $RET_CODE = 0 ]; then
        INFO="$(grep -i -e "$DIALOG_RET" $DIR_LOG_POSTFIX/$1.log)"

        show_info 'Postfix log' "$INFO"
    fi  
}

# select Postfix info to show in dialog menu
# parameters:
# none
# return values:
# none
postfix_info() {
    declare -r TAG_LOGCURRENT='logcurrent'
    declare -r TAG_LOGALL='logall'
    declare -a MENU_POSTFIX_INFO
    declare DIALOG_RET RET_CODE

    MENU_POSTFIX_INFO=()
    MENU_POSTFIX_INFO+=('queues' 'Queues')
    MENU_POSTFIX_INFO+=('processes' 'Processes')
    MENU_POSTFIX_INFO+=("$TAG_LOGCURRENT" 'Current log')
    MENU_POSTFIX_INFO+=("$TAG_LOGALL" 'All logs')

    while true; do
        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --ok-label 'Select' --no-tags --extra-button --extra-label 'Help' --menu 'Choose Postfix info to show' 0 0 0 "${MENU_POSTFIX_INFO[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            if [ "$DIALOG_RET" = "$TAG_LOGCURRENT" ]; then
                search_log 'current'
            elif [ "$DIALOG_RET" = "$TAG_LOGALL" ]; then
                search_log '*'
            else
                "show_$DIALOG_RET"
            fi
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$HELP_POSTFIX_INFO"
        else
            break
        fi
    done
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

    printf '%s' "$PACKED_SCRIPT" | base64 -d | gunzip > "$CRON_RULES"
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

# sync Rspamd config with other peer
# parameters:
# none
# return values:
# none
sync_rspamd() {
    show_wait
    rsync -avzh -e ssh "$DIR_LIB_RSPAMD/$CONFIG_RSPAMD_WHITELIST_IP" mx:"$DIR_LIB_RSPAMD/$CONFIG_RSPAMD_WHITELIST_IP" &>/dev/null
    rsync -avzh -e ssh "$DIR_LIB_RSPAMD/$CONFIG_RSPAMD_WHITELIST_DOMAIN" mx:"$DIR_LIB_RSPAMD/$CONFIG_RSPAMD_WHITELIST_DOMAIN" &>/dev/null
    rsync -avzh -e ssh "$DIR_LIB_RSPAMD/$CONFIG_RSPAMD_WHITELIST_FROM" mx:"$DIR_LIB_RSPAMD/$CONFIG_RSPAMD_WHITELIST_FROM" &>/dev/null
    rsync -avzh -e ssh "$DIR_LIB_RSPAMD/$CONFIG_RSPAMD_WHITELIST_TO" mx:"$DIR_LIB_RSPAMD/$CONFIG_RSPAMD_WHITELIST_TO" &>/dev/null
    rsync -avzh -e ssh "$DIR_LIB_RSPAMD/$CONFIG_RSPAMD_BLACKLIST_COUNTRY" mx:"$DIR_LIB_RSPAMD/$CONFIG_RSPAMD_BLACKLIST_COUNTRY" &>/dev/null
    ssh mx systemctl reload rspamd &>/dev/null
}

# select Rspamd configuration file for editing in dialog menu
# parameters:
# none
# return values:
# none
rspamd_config() {
    declare -r TAG_SYNC='sync'
    declare -r TMP_CONFIG='/tmp/TMPconfig'
    declare -a MENU_RSPAMD_CONFIG
    declare CONFIG DIALOG_RET RET_CODE FILE_CONFIG

    MENU_RSPAMD_CONFIG=()

    for CONFIG in "${RSPAMD_CONFIG[@]}"; do
        MENU_RSPAMD_CONFIG+=("$CONFIG" "$(eval echo \"\$LABEL_CONFIG_RSPAMD_${CONFIG^^}\")")
    done

    check_installed_peer && MENU_RSPAMD_CONFIG+=("$TAG_SYNC" 'Sync Rspamd config')

    while true; do
        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --ok-label 'Select' --no-tags --extra-button --extra-label 'Help' --menu 'Choose Rspamd config to edit' 0 0 0 "${MENU_RSPAMD_CONFIG[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            if [ "$DIALOG_RET" = "$TAG_SYNC" ]; then
                sync_rspamd
            else
                FILE_CONFIG="$(eval echo \"\$CONFIG_RSPAMD_${DIALOG_RET^^}\")"

                if [ -f "$FILE_CONFIG" ]; then
                    cp -f "$FILE_CONFIG" "$TMP_CONFIG"
                else
                    touch "$TMP_CONFIG"
                fi

                "$TXT_EDITOR" "$TMP_CONFIG"

                diff -N -s "$TMP_CONFIG" "$FILE_CONFIG" &>/dev/null

                if [ "$?" != 0 ]; then
                    cp -f "$TMP_CONFIG" "$FILE_CONFIG"
                    systemctl reload rspamd &>/dev/null
                fi

                rm -f "$TMP_CONFIG"
            fi
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$HELP_RSPAMD_CONFIG"
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
sync_spamassassin() {
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
    declare -r TAG_SYNC='sync'
    declare -r TMP_CONFIG='/tmp/TMPconfig'
    declare -a MENU_SPAMASSASSIN_CONFIG
    declare CONFIG DIALOG_RET RET_CODE FILE_CONFIG

    MENU_SPAMASSASSIN_CONFIG=()

    for CONFIG in "${SPAMASSASSIN_CONFIG[@]}"; do
        MENU_SPAMASSASSIN_CONFIG+=("$CONFIG" "$(eval echo \"\$LABEL_CONFIG_SPAMASSASSIN_${CONFIG^^}\")")
    done

    check_installed_peer && MENU_SPAMASSASSIN_CONFIG+=("$TAG_SYNC" 'Sync Spamassassin config')

    while true; do
        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --ok-label 'Select' --no-tags --extra-button --extra-label 'Help' --menu 'Choose Spamassassin config to edit' 0 0 0 "${MENU_SPAMASSASSIN_CONFIG[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            if [ "$DIALOG_RET" = "$TAG_SYNC" ]; then
                sync_spamassassin
            else
                FILE_CONFIG="$(eval echo \"\$CONFIG_SPAMASSASSIN_${DIALOG_RET^^}\")"

                if [ -f "$FILE_CONFIG" ]; then
                    cp -f "$FILE_CONFIG" "$TMP_CONFIG"
                else
                    touch "$TMP_CONFIG"
                fi

                "$TXT_EDITOR" "$TMP_CONFIG"

                diff -N -s "$TMP_CONFIG" "$FILE_CONFIG" &>/dev/null

                if [ "$?" != 0 ]; then
                    cp -f "$TMP_CONFIG" "$FILE_CONFIG"
                    systemctl reload spamassassin &>/dev/null
                fi

                rm -f "$TMP_CONFIG"
            fi
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

# sync Fail2ban config with other peer
# parameters:
# none
# return values:
# none
sync_fail2ban() {
    show_wait
    rsync -avzh -e ssh "$CONFIG_FAIL2BAN" mx:"$CONFIG_FAIL2BAN"
    ssh mx systemctl restart fail2ban
}

# select Fail2ban configuration file for editing in dialog menu
# parameters:
# none
# return values:
# none
fail2ban_config() {
    declare -r TAG_SYNC='sync'
    declare -r TMP_CONFIG='/tmp/TMPconfig'
    declare -a MENU_FAIL2BAN_CONFIG
    declare CONFIG DIALOG_RET RET_CODE FILE_CONFIG

    MENU_FAIL2BAN_CONFIG=()

    for CONFIG in "${FAIL2BAN_CONFIG[@]}"; do
        MENU_FAIL2BAN_CONFIG+=("$CONFIG" "$(eval echo \"\$LABEL_CONFIG_FAIL2BAN_${CONFIG^^}\")")
    done

    check_installed_peer && MENU_FAIL2BAN_CONFIG+=("$TAG_SYNC" 'Sync Fail2ban config')

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

                rm -f "$TMP_CONFIG"

                if [ -d "$FILE_CONFIG" ]; then
                    exec 3>&1
                    FILE_CONFIG="$(get_file 'Select config file' "$FILE_CONFIG")"
                    RET_CODE="$?"
                    exec 3>&-

                    if [ "$RET_CODE" = 0 ] && ! [ -z "$FILE_CONFIG" ]; then
                        cp -f "$FILE_CONFIG" "$TMP_CONFIG"
                    fi
                elif [ -f "$FILE_CONFIG" ]; then
                    cp -f "$FILE_CONFIG" "$TMP_CONFIG"
                else
                    touch "$TMP_CONFIG"
                fi

                if [ -f "$TMP_CONFIG" ]; then
                    "$TXT_EDITOR" "$TMP_CONFIG"

                    diff -N -s "$TMP_CONFIG" "$FILE_CONFIG" &>/dev/null

                    if [ "$?" != 0 ]; then
                        cp -f "$TMP_CONFIG" "$FILE_CONFIG"
                        systemctl restart fail2ban
                    fi

                    rm -f "$TMP_CONFIG"
                fi
            fi
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$HELP_FAIL2BAN_CONFIG"
        else
            break
        fi
    done
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

# select other info to show in dialog menu
# parameters:
# none
# return values:
# none
other_info() {
    declare -a MENU_OTHER_INFO
    declare DIALOG_RET RET_CODE

    MENU_OTHER_INFO=()
    MENU_OTHER_INFO+=('connections' 'Network connections')
    MENU_OTHER_INFO+=('firewall' 'Firewall rules')

    while true; do
        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --backtitle "$TITLE_MAIN" --cancel-label 'Back' --ok-label 'Select' --no-tags --extra-button --extra-label 'Help' --menu 'Choose info to show' 0 0 0 "${MENU_OTHER_INFO[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-

        if [ "$RET_CODE" = 0 ]; then
            "show_$DIALOG_RET"
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$HELP_OTHER_INFO"
        else
            break
        fi
    done
}

# check whether distro is Ubuntu
# parameters:
# none
# return values:
# stderr - 0 if Ubuntu else 1
check_ubuntu() {
    cat /proc/version | grep -q 'Ubuntu'
}

# install Postfwd
# parameters:
# none
# return values:
# none
install_postfwd() {
    show_wait
    apt install -y postfwd &>/dev/null
}

# install Spamassassin
# parameters:
# none
# return values:
# none
install_spamassassin() {
    show_wait
    apt install -y geoip-bin geoip-database geoip-database-extra cpanminus libbsd-resource-perl libdbi-perl libencode-detect-perl libgeo-ip-perl liblwp-useragent-determined-perl libmail-dkim-perl libnet-cidr-perl libdigest-sha-perl libnet-patricia-perl monit postfix postfix-pcre sa-compile spamassassin spamc spf-tools-perl redis-server pyzor razor &>/dev/null
}

# install Rspamd
# parameters:
# none
# return values:
# none
install_rspamd() {
    show_wait
    apt-get install -y lsb-release wget &>/dev/null
    CODENAME="$(lsb_release -c -s)"
    wget -O- https://rspamd.com/apt-stable/gpg.key 2>/dev/null | apt-key add - &>/dev/null
    echo "deb [arch=amd64] http://rspamd.com/apt-stable/ $CODENAME main" > /etc/apt/sources.list.d/rspamd.list
    echo "deb-src [arch=amd64] http://rspamd.com/apt-stable/ $CODENAME main" >> /etc/apt/sources.list.d/rspamd.list
    apt-get update &>/dev/null
    apt-get --no-install-recommends install -y rspamd &>/dev/null
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

# install log manager
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

    printf '%s' "$PACKED_SCRIPT" | base64 -d | gunzip > "$CRON_LOGMANAGER"
    chmod 700 "$CRON_LOGMANAGER"
    "$CRON_LOGMANAGER"
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
                    which sshpass &>/dev/null || apt install -y sshpass

                    sshpass -p "$PASSWORD" ssh-copy-id -p "$SSH_PORT" -o 'StrictHostKeyChecking=accept-new' -i "$SSH_KEY" "root@$IP_ADDRESS" &>/dev/null
                fi

                if [ "$?" = 0 ]; then
                    echo $'\n'"Host mx"$'\n\t'"HostName $IP_ADDRESS"$'\n\t''User root'$'\n\t'"Port $SSH_PORT"$'\n\t'"IdentityFile $SSH_KEY"$'\n\t' >> "$CONFIG_SSH"

                    IP_ADDRESS="$(hostname -I | awk '{print $1}')"

                    ssh mx "[ -f '$SSH_KEY' ] || ssh-keygen -t ed25519 -N '' -f '$SSH_KEY' &>/dev/null; echo $'\n''Host mx'$'\n\t''HostName $IP_ADDRESS'$'\n\t''User root'$'\n\t''Port $SSH_PORT'$'\n\t''IdentityFile $SSH_KEY' >> '$CONFIG_SSH'; ssh-keyscan -H $IP_ADDRESS 2>/dev/null | grep ecdsa-sha2-nistp256 >> '$HOME/.ssh/known_hosts'; cat '$SSH_KEY.pub'" >> "$HOME/.ssh/authorized_keys"
                fi
            fi
        fi
    fi
}

# sync all config
# parameters:
# none
# return values:
# none
sync_all() {
    sync_postfix
    sync_plugin
    check_installed_spamassassin && sync_spamassassin
    check_installed_rspamd && sync_rspamd
    check_installed_fail2ban && sync_fail2ban
}

# select feature to install in dialog menu
# parameters:
# none
# return values:
# none
install_feature() {
    declare -a MENU_INSTALL

    while true; do
        MENU_INSTALL=()

        for FEATURE in "${INSTALL_FEATURE[@]}"; do
            "check_installed_${FEATURE}" && MENU_INSTALL+=("$FEATURE" "$(eval echo \"\$LABEL_INSTALL_${FEATURE^^}\") (installed)") || MENU_INSTALL+=("$FEATURE" "$(eval echo \"\$LABEL_INSTALL_${FEATURE^^}\")")
        done

        exec 3>&1
        DIALOG_RET="$("$DIALOG" --clear --title "$TITLE_MAIN $VERSION_MENU" --cancel-label 'Back' --no-tags --extra-button --extra-label 'Help' --menu '' 0 0 0 "${MENU_INSTALL[@]}" 2>&1 1>&3)"
        RET_CODE="$?"
        exec 3>&-
        if [ "$RET_CODE" = 0 ]; then
            "install_${DIALOG_RET}"
        elif [ "$RET_CODE" = 3 ]; then
            show_help "$HELP_INSTALL_FEATURE"
        else
            break
        fi
    done
}

# check for update and when available ask user whether to install it and show changelog
# parameters:
# none
# return values:
# none
check_update() {
    declare -r TMP_UPDATE='/tmp/TMPupdate'
    declare VERSION MAJOR_DL MINOR_DL BUILD_DL MAJOR_CURRENT MINOR_CURRENT BUILD_CURRENT

    rm -f "$TMP_UPDATE"
    wget "$LINK_UPDATE" -O "$TMP_UPDATE" &>/dev/null

    if [ -f "$TMP_UPDATE" ]; then
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
            "$DIALOG" --clear --backtitle "$TITLE_MAIN" --yesno 'New update available. Install?' 0 40
            if [ "$?" = 0 ]; then
                INFO_START=$(expr $(grep -n '# Changelog:' $TMP_UPDATE | head -1 | awk -F: '{print $1}') + 1)
                INFO_END=$(expr $(grep -n '###################################################################################################' "$TMP_UPDATE" | head -2 | tail -1 | awk -F: '{print $1}') - 2)
                INFO_TEXT="$(sed -n "$INFO_START,$INFO_END p" "$TMP_UPDATE" | sed 's/^#//g' | sed 's/^ //g')"
                "$DIALOG" --clear --backtitle "$TITLE_MAIN" --title 'Changelog' --msgbox "$INFO_TEXT" 0 0
                mv -f "$TMP_UPDATE" "$0"
                "$0"
                exit 0
            fi
        fi
    else
        show_info 'Update failed' 'Cannot download most recent version.'
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
        postmap "$CONFIG_POSTFIX_ROUTING"
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
declare -r TAG_INSTALL_FEATURE='install_feature'
declare -r TAG_POSTFIX_FEATURE='postfix_feature'
declare -r TAG_POSTFIX_CONFIG='postfix_config'
declare -r TAG_POSTFIX_PLUGIN='postfix_plugin'
declare -r TAG_POSTFIX_INFO='postfix_info'
declare -r TAG_SPAMASSASSIN_CONFIG='spamassassin_config'
declare -r TAG_SPAMASSASSIN_INFO='spamassassin_info'
declare -r TAG_RSPAMD_FEATURE='rspamd_feature'
declare -r TAG_RSPAMD_CONFIG='rspamd_config'
declare -r TAG_FAIL2BAN_CONFIG='fail2ban_config'
declare -r TAG_OTHER_INFO='other_info'
declare -r TAG_SYNC_ALL='sync_all'
declare -r LABEL_SEPARATOR='====================='
declare -r LABEL_INSTALL_FEATURE='Install feature'
declare -r LABEL_POSTFIX_FEATURE='Postfix feature'
declare -r LABEL_POSTFIX_CONFIG='Postfix config'
declare -r LABEL_POSTFIX_PLUGIN='Postfix plugin config'
declare -r LABEL_POSTFIX_INFO='Postfix info'
declare -r LABEL_SPAMASSASSIN_CONFIG='Spamassassin config'
declare -r LABEL_SPAMASSASSIN_INFO='Spamassassin info'
declare -r LABEL_RSPAMD_FEATURE='Rspamd feature'
declare -r LABEL_RSPAMD_CONFIG='Rspamd config'
declare -r LABEL_FAIL2BAN_CONFIG='Fail2ban config'
declare -r LABEL_OTHER_INFO='Other info'
declare -r LABEL_SYNC_ALL='Sync all config'
declare -a MENU_MAIN
declare DIALOG_RET RET_CODE

if ! [ -f "$CONFIG_BASH" ] || ! grep -q "alias menu=$HOME/menu.sh" "$CONFIG_BASH"; then
    echo "alias menu=$HOME/menu.sh" >> "$CONFIG_BASH"
fi

check_update
write examples

while true; do
    MENU_MAIN=()
    if check_ubuntu; then
        MENU_MAIN+=("$TAG_INSTALL_FEATURE" "$LABEL_INSTALL_FEATURE")
        MENU_MAIN+=('' "$LABEL_SEPARATOR")
    fi
    MENU_MAIN+=("$TAG_POSTFIX_FEATURE" "$LABEL_POSTFIX_FEATURE")
    MENU_MAIN+=("$TAG_POSTFIX_CONFIG" "$LABEL_POSTFIX_CONFIG")
    if check_installed_plugin; then
        MENU_MAIN+=("$TAG_POSTFIX_PLUGIN" "$LABEL_POSTFIX_PLUGIN")
    fi
    MENU_MAIN+=("$TAG_POSTFIX_INFO" "$LABEL_POSTFIX_INFO")
    MENU_MAIN+=('' "$LABEL_SEPARATOR")
    if check_installed_spamassassin; then
        MENU_MAIN+=("$TAG_SPAMASSASSIN_CONFIG" "$LABEL_SPAMASSASSIN_CONFIG")
        MENU_MAIN+=("$TAG_SPAMASSASSIN_INFO" "$LABEL_SPAMASSASSIN_INFO")
        MENU_MAIN+=('' "$LABEL_SEPARATOR")
    fi
    if check_installed_rspamd; then
        MENU_MAIN+=("$TAG_RSPAMD_FEATURE" "$LABEL_RSPAMD_FEATURE")
        MENU_MAIN+=("$TAG_RSPAMD_CONFIG" "$LABEL_RSPAMD_CONFIG")
        MENU_MAIN+=('' "$LABEL_SEPARATOR")
    fi
    if check_installed_fail2ban; then
        MENU_MAIN+=("$TAG_FAIL2BAN_CONFIG" "$LABEL_FAIL2BAN_CONFIG")
        MENU_MAIN+=('' "$LABEL_SEPARATOR")
    fi
    MENU_MAIN+=("$TAG_OTHER_INFO" "$LABEL_OTHER_INFO")
    if check_installed_peer; then
        MENU_MAIN+=('' "$LABEL_SEPARATOR")
        MENU_MAIN+=("$TAG_SYNC_ALL" "$LABEL_SYNC_ALL")
    fi
    exec 3>&1
    DIALOG_RET="$("$DIALOG" --clear --title "$TITLE_MAIN $VERSION_MENU" --cancel-label 'Exit' --no-tags --extra-button --extra-label 'Help' --menu '' 0 0 0 "${MENU_MAIN[@]}" 2>&1 1>&3)"
    RET_CODE="$?"
    exec 3>&-
    if [ "$RET_CODE" = 0 ]; then
        [ -z "$DIALOG_RET" ] || "$DIALOG_RET"
    elif [ "$RET_CODE" = 3 ]; then
        show_help "$HELP_MAIN"
    else
        break
    fi
done
clear
