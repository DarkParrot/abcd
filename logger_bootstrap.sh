#! /usr/bin/env bash
# shellcheck disable=SC1091,SC2129

# This is the script that is used to provision the logger host

# Override existing DNS Settings using netplan, but don't do it for Terraform AWS builds
if ! curl -s 169.254.169.254 --connect-timeout 2 >/dev/null; then
  echo -e "    eth1:\n      dhcp4: true\n      nameservers:\n        addresses: [9.9.9.9,149.112.112.112]" >>/etc/netplan/01-netcfg.yaml
  netplan apply
fi

# Kill systemd-resolvd, just use plain ol' /etc/resolv.conf
systemctl disable systemd-resolved
systemctl stop systemd-resolved
rm /etc/resolv.conf
echo 'nameserver 9.9.9.9' >> /etc/resolv.conf
echo 'nameserver 149.112.112.112' >> /etc/resolv.conf
# echo 'nameserver 192.168.56.102' >> /etc/resolv.conf

# Source variables from logger_variables.sh
# shellcheck disable=SC1091
source /vagrant/logger_variables.sh 2>/dev/null ||
  source /home/vagrant/logger_variables.sh 2>/dev/null ||
  echo "Unable to locate logger_variables.sh"


export DEBIAN_FRONTEND=noninteractive
echo "apt-fast apt-fast/maxdownloads string 10" | debconf-set-selections
echo "apt-fast apt-fast/dlflag boolean true" | debconf-set-selections


install_splunk() {
  # Check if Splunk is already installed
  if [ -f "/opt/splunk/bin/splunk" ]; then
    echo "[$(date +%H:%M:%S)]: Splunk is already installed"
  else
    echo "[$(date +%H:%M:%S)]: Installing Splunk..."
    # Get download.splunk.com into the DNS cache. Sometimes resolution randomly fails during wget below
    dig @9.9.9.9 download.splunk.com >/dev/null
    dig @9.9.9.9 splunk.com >/dev/null
    dig @9.9.9.9 www.splunk.com >/dev/null

    # Try to resolve the latest version of Splunk by parsing the HTML on the downloads page
    echo "[$(date +%H:%M:%S)]: Attempting to autoresolve the latest version of Splunk..."
    LATEST_SPLUNK=$(curl https://www.splunk.com/en_us/download/splunk-enterprise.html | grep -i deb | grep -Eo "data-link=\"................................................................................................................................" | cut -d '"' -f 2)
    # Sanity check what was returned from the auto-parse attempt
    if [[ "$(echo "$LATEST_SPLUNK" | grep -c "^https:")" -eq 1 ]] && [[ "$(echo "$LATEST_SPLUNK" | grep -c "\.deb$")" -eq 1 ]]; then
      echo "[$(date +%H:%M:%S)]: The URL to the latest Splunk version was automatically resolved as: $LATEST_SPLUNK"
      echo "[$(date +%H:%M:%S)]: Attempting to download..."
      wget --progress=bar:force -P /opt "$LATEST_SPLUNK"
    else
      echo "[$(date +%H:%M:%S)]: Unable to auto-resolve the latest Splunk version. Falling back to hardcoded URL..."
      # Download Hardcoded Splunk
      wget --progress=bar:force -O /opt/splunk-8.0.2-a7f645ddaf91-linux-2.6-amd64.deb 'https://download.splunk.com/products/splunk/releases/8.0.2/linux/splunk-8.0.2-a7f645ddaf91-linux-2.6-amd64.deb&wget=true'
    fi
    if ! ls /opt/splunk*.deb 1>/dev/null 2>&1; then
      echo "Something went wrong while trying to download Splunk. This script cannot continue. Exiting."
      exit 1
    fi
    if ! dpkg -i /opt/splunk*.deb >/dev/null; then
      echo "Something went wrong while trying to install Splunk. This script cannot continue. Exiting."
      exit 1
    fi

    /opt/splunk/bin/splunk start --accept-license --answer-yes --no-prompt --seed-passwd changeme
    /opt/splunk/bin/splunk add index wineventlog -auth 'admin:changeme'
    #/opt/splunk/bin/splunk add index osquery -auth 'admin:changeme'
    #/opt/splunk/bin/splunk add index osquery-status -auth 'admin:changeme'
    /opt/splunk/bin/splunk add index sysmon -auth 'admin:changeme'
    /opt/splunk/bin/splunk add index powershell -auth 'admin:changeme'
    #/opt/splunk/bin/splunk add index zeek -auth 'admin:changeme'
    #/opt/splunk/bin/splunk add index suricata -auth 'admin:changeme'
    #/opt/splunk/bin/splunk add index threathunting -auth 'admin:changeme'
    #/opt/splunk/bin/splunk add index evtx_attack_samples -auth 'admin:changeme'
    #/opt/splunk/bin/splunk add index msexchange -auth 'admin:changeme'
    /opt/splunk/bin/splunk install app /vagrant/resources/splunk_forwarder/splunk-add-on-for-microsoft-windows_700.tgz -auth 'admin:changeme'
    /opt/splunk/bin/splunk install app /vagrant/resources/splunk_server/splunk-add-on-for-microsoft-sysmon_1062.tgz -auth 'admin:changeme'
    #/opt/splunk/bin/splunk install app /vagrant/resources/splunk_server/asn-lookup-generator_110.tgz -auth 'admin:changeme'
    /opt/splunk/bin/splunk install app /vagrant/resources/splunk_server/lookup-file-editor_331.tgz -auth 'admin:changeme'
    #/opt/splunk/bin/splunk install app /vagrant/resources/splunk_server/splunk-add-on-for-zeek-aka-bro_400.tgz -auth 'admin:changeme'
    /opt/splunk/bin/splunk install app /vagrant/resources/splunk_server/force-directed-app-for-splunk_200.tgz -auth 'admin:changeme'
    /opt/splunk/bin/splunk install app /vagrant/resources/splunk_server/punchcard-custom-visualization_130.tgz -auth 'admin:changeme'
    /opt/splunk/bin/splunk install app /vagrant/resources/splunk_server/sankey-diagram-custom-visualization_130.tgz -auth 'admin:changeme'
    /opt/splunk/bin/splunk install app /vagrant/resources/splunk_server/link-analysis-app-for-splunk_161.tgz -auth 'admin:changeme'
    #/opt/splunk/bin/splunk install app /vagrant/resources/splunk_server/threathunting_1492.tgz -auth 'admin:changeme'

    # Fix ASNGen App - https://github.com/doksu/TA-asngen/issues/18#issuecomment-685691630
    #echo 'python.version = python2' >>/opt/splunk/etc/apps/TA-asngen/default/commands.conf

    # Install the Maxmind license key for the ASNgen App if it was provided
    #if [ -n "$MAXMIND_LICENSE" ]; then
    #  mkdir /opt/splunk/etc/apps/TA-asngen/local
    #  cp /opt/splunk/etc/apps/TA-asngen/default/asngen.conf /opt/splunk/etc/apps/TA-asngen/local/asngen.conf
    #  sed -i "s/license_key =/license_key = $MAXMIND_LICENSE/g" /opt/splunk/etc/apps/TA-asngen/local/asngen.conf
    #fi

    # Install a Splunk license if it was provided
    if [ -n "$BASE64_ENCODED_SPLUNK_LICENSE" ]; then
      echo "$BASE64_ENCODED_SPLUNK_LICENSE" | base64 -d >/tmp/Splunk.License
      /opt/splunk/bin/splunk add licenses /tmp/Splunk.License -auth 'admin:changeme'
      rm /tmp/Splunk.License
    fi

    # Replace the props.conf for Sysmon TA and Windows TA
    # Removed all the 'rename = xmlwineventlog' directives
    # I know youre not supposed to modify files in "default",
    # but for some reason adding them to "local" wasnt working
    cp /vagrant/resources/splunk_server/windows_ta_props.conf /opt/splunk/etc/apps/Splunk_TA_windows/default/props.conf
    cp /vagrant/resources/splunk_server/sysmon_ta_props.conf /opt/splunk/etc/apps/TA-microsoft-sysmon/default/props.conf

    # Add props.conf to Splunk Zeek TA to properly parse timestamp
    # and avoid grouping events as a single event
   # mkdir /opt/splunk/etc/apps/Splunk_TA_bro/local && cp /vagrant/resources/splunk_server/zeek_ta_props.conf /opt/splunk/etc/apps/Splunk_TA_bro/local/props.conf

    # Add custom Macro definitions for ThreatHunting App
    #cp /vagrant/resources/splunk_server/macros.conf /opt/splunk/etc/apps/ThreatHunting/default/macros.conf
    # Fix some misc stuff
    # shellcheck disable=SC2016
    #sed -i 's/index=windows/`windows`/g' /opt/splunk/etc/apps/ThreatHunting/default/data/ui/views/computer_investigator.xml
    # shellcheck disable=SC2016
    #sed -i 's/$host$)/$host$*)/g' /opt/splunk/etc/apps/ThreatHunting/default/data/ui/views/computer_investigator.xml
    # This is probably horrible and may break some stuff, but I'm hoping it fixes more than it breaks
    #find /opt/splunk/etc/apps/ThreatHunting -type f ! -path "/opt/splunk/etc/apps/ThreatHunting/default/props.conf" -exec sed -i -e 's/host_fqdn/ComputerName/g' {} \;
    #find /opt/splunk/etc/apps/ThreatHunting -type f ! -path "/opt/splunk/etc/apps/ThreatHunting/default/props.conf" -exec sed -i -e 's/event_id/EventCode/g' {} \;

    # Fix Windows TA macros
    mkdir /opt/splunk/etc/apps/Splunk_TA_windows/local
    cp /opt/splunk/etc/apps/Splunk_TA_windows/default/macros.conf /opt/splunk/etc/apps/Splunk_TA_windows/local
    sed -i 's/wineventlog_windows/wineventlog/g' /opt/splunk/etc/apps/Splunk_TA_windows/local/macros.conf
    # Fix Force Directed App until 2.0.1 is released (https://answers.splunk.com/answers/668959/invalid-key-in-stanza-default-value-light.html#answer-669418)
    rm /opt/splunk/etc/apps/force_directed_viz/default/savedsearches.conf

    # Add a Splunk TCP input on port 9997
    echo -e "[splunktcp://9997]\nconnection_host = ip" >/opt/splunk/etc/apps/search/local/inputs.conf
    # Add props.conf and transforms.conf
    cp /vagrant/resources/splunk_server/props.conf /opt/splunk/etc/apps/search/local/
    cp /vagrant/resources/splunk_server/transforms.conf /opt/splunk/etc/apps/search/local/
    cp /opt/splunk/etc/system/default/limits.conf /opt/splunk/etc/system/local/limits.conf
    # Bump the memtable limits to allow for the ASN lookup table
    sed -i.bak 's/max_memtable_bytes = 10000000/max_memtable_bytes = 30000000/g' /opt/splunk/etc/system/local/limits.conf

    # Skip Splunk Tour and Change Password Dialog
    echo "[$(date +%H:%M:%S)]: Disabling the Splunk tour prompt..."
    touch /opt/splunk/etc/.ui_login
    mkdir -p /opt/splunk/etc/users/admin/search/local
    echo -e "[search-tour]\nviewed = 1" >/opt/splunk/etc/system/local/ui-tour.conf
    # Source: https://answers.splunk.com/answers/660728/how-to-disable-the-modal-pop-up-help-us-to-improve.html
    if [ ! -d "/opt/splunk/etc/users/admin/user-prefs/local" ]; then
      mkdir -p "/opt/splunk/etc/users/admin/user-prefs/local"
    fi
    echo '[general]
render_version_messages = 1
dismissedInstrumentationOptInVersion = 4
notification_python_3_impact = false
display.page.home.dashboardId = /servicesNS/nobody/search/data/ui/views/logger_dashboard' >/opt/splunk/etc/users/admin/user-prefs/local/user-prefs.conf
    # Enable SSL Login for Splunk
    echo -e "[settings]\nenableSplunkWebSSL = true" >/opt/splunk/etc/system/local/web.conf
    # Copy over the Logger Dashboard
    if [ ! -d "/opt/splunk/etc/apps/search/local/data/ui/views" ]; then
      mkdir -p "/opt/splunk/etc/apps/search/local/data/ui/views"
    fi
    cp /vagrant/resources/splunk_server/logger_dashboard.xml /opt/splunk/etc/apps/search/local/data/ui/views || echo "Unable to find dashboard"
    # Reboot Splunk to make changes take effect
    /opt/splunk/bin/splunk restart
    /opt/splunk/bin/splunk enable boot-start
  fi
  # Include Splunk and Zeek in the PATH
  #echo export PATH="$PATH:/opt/splunk/bin:/opt/zeek/bin" >>~/.bashrc
  echo "export SPLUNK_HOME=/opt/splunk" >>~/.bashrc
}

configure_splunk_inputs() {
  echo "[$(date +%H:%M:%S)]: Configuring Splunk Inputs..."
  # Suricata
  crudini --set /opt/splunk/etc/apps/search/local/inputs.conf monitor:///var/log/suricata index suricata
  crudini --set /opt/splunk/etc/apps/search/local/inputs.conf monitor:///var/log/suricata sourcetype suricata:json
  crudini --set /opt/splunk/etc/apps/search/local/inputs.conf monitor:///var/log/suricata whitelist 'eve.json'
  crudini --set /opt/splunk/etc/apps/search/local/inputs.conf monitor:///var/log/suricata disabled 0
  crudini --set /opt/splunk/etc/apps/search/local/props.conf suricata:json TRUNCATE 0

  # Fleet
  /opt/splunk/bin/splunk add monitor "/var/log/fleet/osquery_result" -index osquery -sourcetype 'osquery:json' -auth 'admin:changeme' --accept-license --answer-yes --no-prompt
  /opt/splunk/bin/splunk add monitor "/var/log/fleet/osquery_status" -index osquery-status -sourcetype 'osquery:status' -auth 'admin:changeme' --accept-license --answer-yes --no-prompt

  # Zeek
  mkdir -p /opt/splunk/etc/apps/Splunk_TA_bro/local && touch /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf
  crudini --set /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf monitor:///opt/zeek/spool/manager index zeek
  crudini --set /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf monitor:///opt/zeek/spool/manager sourcetype zeek:json
  crudini --set /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf monitor:///opt/zeek/spool/manager whitelist '.*\.log$'
  crudini --set /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf monitor:///opt/zeek/spool/manager blacklist '.*(communication|stderr)\.log$'
  crudini --set /opt/splunk/etc/apps/Splunk_TA_bro/local/inputs.conf monitor:///opt/zeek/spool/manager disabled 0

  # Ensure permissions are correct and restart splunk
  chown -R splunk:splunk /opt/splunk/etc/apps/Splunk_TA_bro
  /opt/splunk/bin/splunk restart
}

main() {
  install_splunk
  configure_splunk_inputs
}


# Allow custom modes via CLI args
if [ -n "$1" ]; then
  eval "$1"
else
  main
fi
exit 0
