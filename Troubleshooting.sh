#!/bin/sh
set -o noglob

# Description:
#   Diagnostics script to check if your machine meets the prerequisites to be able to install a Securiti Pod into it.
#   The script can also be used to set the prerequisites if required.
#
# Usage:
#   curl ... | ENV_VAR=... sh -s -- [COMMAND] [OPTION]
#       or
#   ENV_VAR=... ./poddiagnostics.sh [COMMAND] [OPTION]
#
# Example:
#     curl ... | SECURITI_SKIP_TIME_SYNC_CHECK="true" sh -s -- install --scan
#
# Environment variables:
#
#   - SECURITI_FIREWALL_CONFIG_ENABLED
#     If set to true, will configure the firewall
#     Default: false
#
#   - SECURITI_INSTALL_DIR
#     Directory for downloading and staging installer files
#     Default: /mnt
#
#   - SECURITI_INSTALL_NAMESPACE
#     Kubernetes namespace where Securiti Pod is installed
#     Default: default
#
#   - SECURITI_SKIP_FIREWALL_DISABLE
#     If set to true, will not disable the firewall
#     Default: false
#
#   - SECURITI_SKIP_PRE_REQ_CHECKS
#     If set to true, will not check the pre-requisites
#     Default: false
#
#   - SECURITI_SKIP_DISK_CHECKS
#     If set to true, will not check the disk pre-requisite
#     Default: false
#
#   - SECURITI_SKIP_TIME_SYNC_CHECK
#     If set to true, will not check whether time is synced is synced across nodes
#     Default: false
#
#   - SECURITI_SKIP_NETWORK_TESTS
#     If set to true, will not check for any network related issues
#     Default: false
#
#   - SECURITI_SKIP_KERNEL_DEFAULTS
#     If set to true, will not validate kernel defaults for kubelet.
#     Default: false
#
#   - SECURITI_SKIP_COMPUTE_CHECKS
#     If set to true, will not check VM ram, cpu, AVX and architecture requirements.
#     Default: false

# --- variable used to drive the Securiti diagnostics
SECURITI_SKIP_COMPUTE_CHECKS="${SECURITI_SKIP_COMPUTE_CHECKS:-false}"
SECURITI_SKIP_PRE_REQ_CHECKS="${SECURITI_SKIP_PRE_REQ_CHECKS:-false}"
SECURITI_SKIP_DISK_CHECKS="${SECURITI_SKIP_DISK_CHECKS:-false}"
SECURITI_SKIP_TIME_SYNC_CHECK="${SECURITI_SKIP_TIME_SYNC_CHECK:-false}"
SECURITI_SKIP_NETWORK_TESTS="${SECURITI_SKIP_NETWORK_TESTS:-false}"
SECURITI_FIREWALL_CONFIG_ENABLED="${SECURITI_FIREWALL_CONFIG_ENABLED:-false}"
SECURITI_SKIP_FIREWALL_DISABLE="${SECURITI_SKIP_FIREWALL_DISABLE:-false}"
SECURITI_INSTALL_DIR="${SECURITI_INSTALL_DIR:-"/mnt"}"
SECURITI_SKIP_KERNEL_DEFAULTS="${SECURITI_SKIP_KERNEL_DEFAULTS:-"false"}"
SECURITI_INSTALL_NAMESPACE="${SECURITI_INSTALL_NAMESPACE:-"default"}"

# --- internal variables
TMP_DIR="/tmp"
K8S_CLUSTER_SERVICE_CIDR="10.43.0.0/16"
K8S_CLUSTER_POD_CIDR="10.42.0.0/16"
ROOT_DIR="/"
MIN_INSTALL_DIR_SIZE=100
MIN_ROOT_SIZE=75
MIN_TMP_SIZE=50
MIN_DISK_RATE=50
MIN_MEMORY=64
MIN_CPU=16
MIN_FILE_DESCRIPTOR_LIMIT_HARD=100000
MIN_FILE_DESCRIPTOR_LIMIT_SOFT=100000
# in case separate mounts are used for each of these
CUSTOM_INSTALLATION_DIR="$SECURITI_INSTALL_DIR/installation"
K3S_DIR="$SECURITI_INSTALL_DIR/rancher"
APP_DIR="$SECURITI_INSTALL_DIR/securiti-app"
CUSTOM_INSTALLATION_DIR_MIN_SIZE="$MIN_INSTALL_DIR_SIZE"
K3S_DIR_MIN_SIZE="$MIN_INSTALL_DIR_SIZE"
APP_DIR_MIN_SIZE="$MIN_INSTALL_DIR_SIZE"
# TODO: SELINUX support - See https://docs.k3s.io/advanced#selinux-support
ENABLE_SELINUX=false

# --- Dynamically configured variables
host_url="app2.securiti.ai"
package_url="packages2.securiti.ai"
s3_bucket="privaci-jakarta-registry.s3.ap-southeast-3.amazonaws.com"
starport_layer_bucket="prod-ap-southeast-3-starport-layer-bucket.s3.ap-southeast-3.amazonaws.com"
cloudfront_url="d2nhybc0go9etk.cloudfront.net"

# --- Local use variables
errors=""

# --- helper functions for logs ---
info() {
    printf '[INFO] %s\n' "$@" >&2
}
warn() {
    printf "\e[1;93m[WARNING] %s\e[0m\n" "$@" >&2
}
fatal() {
    errors="$(printf "%s\n\t$*" "$errors")"
    printf "\e[1;31m[ERROR] %s\e[0m\n" "$@" >&2
}
fail() {
    printf "\e[1;31m[FAIL] %s\e[0m\n" "$@" >&2
    exit 1
}

# START validations
# --- require root user for installation
require_root_user() {
    if [ "$(id -u)" -ne 0 ]; then
        fail "The script needs root access to run properly."
    fi
}

# --- require 64-bit architecture
require_64bit_architecture() {
    if ! uname -i | grep -Fq x86_64; then
        fatal "x86_64 architecture requirement not met."
    fi
}

# --- ensure CPU meets the given AVX requirements
require_avx_cpu() {
    info "Checking AVX support"
    if grep -iFq avx /proc/cpuinfo; then
        info "Done checking AVX status"
        return 0
    fi
    fatal "CPU does not support AVX"
}

# --- load kernel modules
load_kernel_modules() {
    info "Loading required kernel modules"
    file="/etc/modules-load.d/99-securiti.conf"

    if ! lsmod | grep -Fq br_netfilter; then
        info "Adding kernel module br_netfilter"
        modprobe br_netfilter
    fi
    if ! lsmod | grep -Fq overlay; then
        info "Adding kernel module overlay"
        modprobe overlay
    fi
    if ! lsmod | grep -Fq ebtables; then
        info "Adding kernel module ebtables"
        modprobe ebtables
    fi
    if ! lsmod | grep -Fq ebtable_filter; then
        info "Adding kernel module ebtable_filter"
        modprobe ebtable_filter
    fi
    if ! lsmod | grep -Fq ip_tables; then
        info "Adding kernel module ip_tables"
        modprobe ip_tables
    fi
    if ! lsmod | grep -Fq iptable_filter; then
        info "Adding kernel module iptable_filter"
        modprobe iptable_filter
    fi
    if ! lsmod | grep -Fq iptable_nat; then
        info "Adding kernel module iptable_nat"
        modprobe iptable_nat
    fi

    {
        echo br_netfilter
        echo overlay
        echo ebtables
        echo ebtable_filter
        echo ip_tables
        echo iptable_filter
        echo iptable_nat
    } >"$file"

    info "Done loading required kernel modules"
}

# --- setting sysctl
set_sysctl_config() {
    info "Setting sysctl configs"
    file="/etc/sysctl.d/99-securiti.conf"
    {
        echo "kernel.pid_max=4194304"
        echo "fs.inotify.max_user_watches=1048576"
        echo "vm.max_map_count=262144"
        echo "fs.may_detach_mounts=1"
        echo "net.ipv4.conf.all.forwarding=1"
        echo "net.bridge.bridge-nf-call-iptables=1"
        # https://docs.k3s.io/security/hardening-guide?_highlight=protect&_highlight=kernel&_highlight=defaults#ensure-protect-kernel-defaults-is-set
        # note that max_root_bytes is no longer available in many kernels https://github.com/rancher/rancher/issues/35772
        echo "vm.panic_on_oom=0"
        echo "vm.overcommit_memory=1"
        echo "kernel.panic=10"
        echo "kernel.panic_on_oops=1"
    } >"$file"
    sysctl --system

    info "Done setting sysctl configs"
}

# --- validate sysctl settings
validate_sysctl_config() {
    info "Validating sysctl config"
    if [ "$(sysctl -n kernel.pid_max)" != "4194304" ]; then
        fatal "kernel.pid_max must be set to 4194304."
    fi

    if [ "$(sysctl -n vm.max_map_count)" != "262144" ]; then
        fatal "vm.max_map_count must be set to 262144."
    fi

    if [ "$(sysctl -n net.ipv4.conf.all.forwarding)" != "1" ]; then
        fatal "net.ipv4.conf.all.forwarding must be set to 1."
    fi

    if [ "$(sysctl -n net.bridge.bridge-nf-call-iptables)" != "1" ]; then
        fatal "net.bridge.bridge-nf-call-iptables must be set to 1."
    fi

    if [ "$(sysctl -n fs.inotify.max_user_watches)" != "1048576" ]; then
        fatal "fs.inotify.max_user_watches must be set to 1048576."
    fi
    warn_or_fatal=fatal
    if [ "$SECURITI_SKIP_KERNEL_DEFAULTS" = true ]; then
        warn_or_fatal=warn
    fi
    if [ "$(sysctl -n vm.panic_on_oom)" != "0" ]; then
        "$warn_or_fatal" "vm.panic_on_oom must be set to 0."
    fi

    if [ "$(sysctl -n vm.overcommit_memory)" != "1" ]; then
        "$warn_or_fatal" "vm.overcommit_memory must be set to 1."
    fi

    if [ "$(sysctl -n kernel.panic)" != "10" ]; then
        "$warn_or_fatal" "kernel.panic must be set to 10."
    fi

    if [ "$(sysctl -n kernel.panic_on_oops)" != "1" ]; then
        "$warn_or_fatal" "kernel.panic_on_oops must be set to 1."
    fi

    info "Done validating sysctl config"
}

# --- set minimum file descriptor limits
set_file_descriptor_limits() {
    # set max open files for future processes
    file="/etc/security/limits.d/99-securiti.conf"
    {
        echo "*       soft nofile $MIN_FILE_DESCRIPTOR_LIMIT_SOFT"
        echo "root    soft nofile $MIN_FILE_DESCRIPTOR_LIMIT_SOFT"
        echo "*       hard nofile $MIN_FILE_DESCRIPTOR_LIMIT_HARD"
        echo "root    hard nofile $MIN_FILE_DESCRIPTOR_LIMIT_HARD"
    } >$file
    # set max open files for this process
    prlimit --nofile="$MIN_FILE_DESCRIPTOR_LIMIT_SOFT":"$MIN_FILE_DESCRIPTOR_LIMIT_HARD" --pid $$
}

# --- check if the minimum file descriptor limits meets the requirements
validate_file_descriptor_limits() {
    # using prlimit because ulimit results in a shellcheck error
    current_limits=$(prlimit -n | tr -dc '0-9 ' | sed -e 's/^ *//g')
    soft_limit=$(echo "$current_limits" | cut -d ' ' -f 1)
    hard_limit=$(echo "$current_limits" | cut -d ' ' -f 2)
    if [ "$soft_limit" -lt "$MIN_FILE_DESCRIPTOR_LIMIT_SOFT" ]; then
        fatal "File descriptor soft limit of $soft_limit is lower than the expected minimum of $MIN_FILE_DESCRIPTOR_LIMIT_SOFT "
    fi

    if [ "$hard_limit" -lt "$MIN_FILE_DESCRIPTOR_LIMIT_HARD" ]; then
        fatal "File descriptor hard limit of $hard_limit is lower than the expected minimum of $MIN_FILE_DESCRIPTOR_LIMIT_HARD "
    fi
}

# --- check if a command exists
command_exists() {
    command -v "$@" >/dev/null 2>&1
}

# --- check if selinux is enabled
selinux_enabled() {
    if command_exists "selinuxenabled"; then
        if selinuxenabled; then
            return 0
        fi
        return 1
    fi
    if command_exists "sestatus"; then
        if sestatus | grep 'SELinux status' | awk '{ print $3 }' | grep -iqF enabled; then
            return 0
        fi
    fi
    return 1
}

# --- check if selinux is enforced
selinux_enforced() {
    if command_exists "getenforce"; then
        if getenforce | grep -iqF enforcing; then
            return 0
        fi
    fi
    if command_exists "sestatus"; then
        if sestatus | grep 'SELinux mode' | awk '{ print $3 }' | grep -iqF enforcing; then
            return 0
        fi
    fi
    return 1
}

# --- check selinux status
check_selinux_status() {
    if [ "$ENABLE_SELINUX" = "true" ]; then
        info "Leaving SELinux config intact"
        return 0
    fi
    info "Checking SELinux status"
    file="/etc/selinux/config"
    if selinux_enabled && selinux_enforced; then
        fatal "SELinux should be disabled"
    fi
    info "Done checking SELinux status"
}

# --- disable SELinux
disable_selinux() {
    file="/etc/selinux/config"
    info "Disabling SELinux"
    if [ -f "$file" ]; then
        sed -i s/^SELINUX=.*$/SELINUX=disabled/ "$file"
    else
        echo 'SELINUX=disabled' >"$file"
    fi
    if selinux_enforced; then
        setenforce 0
    fi
    info "Done disabling SELinux"
}

# --- create thp service
create_thp_service() {
    cat >"/etc/systemd/system/securiti-disable-thp.service" <<EOF
[Unit]
Description=Disable Transparent Huge Pages

[Service]
Type=oneshot
ExecStart=/bin/sh -c "echo never > /sys/kernel/mm/transparent_hugepage/enabled"

[Install]
WantedBy=multi-user.target
EOF
}

# --- ensure thp is disabled
ensure_thp_disabled() {
    if [ ! -d /sys/kernel/mm/transparent_hugepage ]; then
        return 0
    fi
    info "Disabling THP"
    echo never >/sys/kernel/mm/transparent_hugepage/enabled

    # retain the setting after a reboot
    service_file="/etc/systemd/system/securiti-disable-thp.service"

    if [ ! -f "$service_file" ]; then
        create_thp_service
    fi

    systemctl enable securiti-disable-thp.service

    info "Done disabling THP"
}

# --- ensure disk space is available
check_disk_space() {
    mount_point="$1"
    min_size_gb="$2"
    info "Checking disk space on $mount_point"
    actual_disk_size=$(df -BG --output=avail "$mount_point" | tail -n 1 | awk '{print $1}' | head -c-2)
    if [ "$actual_disk_size" -lt "$min_size_gb" ]; then
        fatal "Minimum disk size requirement of ${min_size_gb}GB not met for $mount_point"
    fi
    info "Done checking disk space on $mount_point"
}

# --- ensure disk speed meets minimum requirements
check_disk_speed() {
    mount_point="$1"
    disk_rate_reqs="$2"

    info "Checking disk transfer rate on $mount_point"

    disk_rate_str=$(dd if=/dev/zero of="$mount_point/output" conv=fdatasync bs=350k count=1k 2>&1)
    disk_rate=$(echo "${disk_rate_str##*s,}" | tr -dc '0-9.')
    rm -rf "$mount_point/output"

    if echo "$disk_rate_str" | grep -iFq "GB/s"; then
        disk_rate=$(awk "BEGIN { printf \"%.2f\", $disk_rate * 1000 }")
    fi
    # remove decimal points as floating points are not properly supported as numbers
    disk_rate=${disk_rate%.*}

    if [ "$disk_rate" -lt "$disk_rate_reqs" ]; then
        fatal "Disk Transfer Rate Test Failed: Disk transfer rate of $disk_rate MB/s is below the desired rate of $disk_rate_reqs MB/s on the disk mounted on $mount_point"
    fi

    info "Done checking disk transfer rate on $mount_point"
    return 0
}

# --- validate that disk pre-reqs are met
validate_disk_pre_reqs() {
    if [ "${SECURITI_SKIP_DISK_CHECKS}" = "true" ]; then
        return
    fi
    info "Validating disk pre-reqs"
    check_disk_space "$SECURITI_INSTALL_DIR" "$MIN_INSTALL_DIR_SIZE"
    check_disk_speed "$SECURITI_INSTALL_DIR" "$MIN_DISK_RATE"
    check_disk_space "$ROOT_DIR" "$MIN_ROOT_SIZE"
    check_disk_speed "$ROOT_DIR" "$MIN_DISK_RATE"
    check_disk_space "$TMP_DIR" "$MIN_TMP_SIZE"
    check_disk_speed "$TMP_DIR" "$MIN_DISK_RATE"

    # if separate mounts are used, we will need to check these paths separately as well
    if [ -d "$CUSTOM_INSTALLATION_DIR" ]; then
        check_disk_space "$CUSTOM_INSTALLATION_DIR" "$CUSTOM_INSTALLATION_DIR_MIN_SIZE"
        check_disk_speed "$CUSTOM_INSTALLATION_DIR" "$MIN_DISK_RATE"
    fi
    if [ -d "$K3S_DIR" ]; then
        check_disk_space "$K3S_DIR" "$K3S_DIR_MIN_SIZE"
        check_disk_speed "$K3S_DIR" "$MIN_DISK_RATE"
    fi
    if [ -d "$APP_DIR" ]; then
        check_disk_space "$APP_DIR" "$APP_DIR_MIN_SIZE"
        check_disk_speed "$APP_DIR" "$MIN_DISK_RATE"
    fi

    info "Done validating disk pre-reqs"
}

# --- configure firewalld
configure_firewalld() {
    # Configuring firewalld if active
    if systemctl -q is-active firewalld; then
        info "Configuring firewalld"
        firewall-cmd --permanent --add-port=6443/tcp                                     #apiserver
        firewall-cmd --permanent --zone=trusted --add-source="$K8S_CLUSTER_POD_CIDR"     #pods
        firewall-cmd --permanent --zone=trusted --add-source="$K8S_CLUSTER_SERVICE_CIDR" #services
        firewall-cmd --reload
        info "Done configuring firewalld"
    fi
}

# --- configure ufw
configure_ufw() {
    # Configuring ufw if active
    if command_exists "ufw"; then
        if ufw status | grep -iFq 'Status: active'; then
            info "Configuring ufw"
            ufw allow 6443/tcp                                #apiserver
            ufw allow from "$K8S_CLUSTER_POD_CIDR" to any     #pods
            ufw allow from "$K8S_CLUSTER_SERVICE_CIDR" to any #services
            info "Done configuring ufw"
        fi
    fi
}

# --- configure firewall
configure_firewall() {
    configure_firewalld
    configure_ufw
}

# --- disable firewalld
disable_firewalld() {
    if systemctl -q is-active firewalld; then
        info "Disabling firewalld"
        systemctl disable firewalld --now
        info "Done disabling Firewalld"
    fi
}

# --- disable ufw
disable_ufw() {
    if command_exists "ufw"; then
        if ufw status | grep -iFq 'Status: active'; then
            info "Disabling UFW"
            ufw disable
            if systemctl -q is-active ufw; then
                systemctl disable ufw --now
            fi
            info "Done disabling UFW"
        fi
    fi
}

# --- disable firewall
disable_firewall() {
    disable_firewalld
    disable_ufw
}

# --- disable or configure firewall
disable_or_config_firewall() {
    info "Checking firewall status"
    if [ "$SECURITI_FIREWALL_CONFIG_ENABLED" = "true" ]; then
        configure_firewall
        return
    fi

    if [ "$SECURITI_SKIP_FIREWALL_DISABLE" != "true" ]; then
        disable_firewall
    fi
    info "Done checking firewall status"
}

# --- disable conflicting services that would fail k3s boot
disable_conflicting_services() {
    # https://docs.k3s.io/advanced#red-hat-enterprise-linux--centos--fedora
    if systemctl -q is-enabled nm-cloud-setup.timer 2>/dev/null || systemctl -q is-active nm-cloud-setup.timer; then
        info "Disabling nm-cloud-setup.timer"
        systemctl disable nm-cloud-setup.timer --now
        info "Disabled nm-cloud-setup.timer"
    fi
    if systemctl -q is-enabled nm-cloud-setup.service 2>/dev/null || systemctl -q is-active nm-cloud-setup.service; then
        info "Disabling nm-cloud-setup.service"
        systemctl disable nm-cloud-setup.service --now
        info "Disabled nm-cloud-setup.service"
    fi
}

# --- check whether a time syncing service is installed and being used
check_time_sync() {
    if [ "${SECURITI_SKIP_TIME_SYNC_CHECK}" = "true" ]; then
        warn 'Skipping time sync check'
        return
    fi
    info "Running time sync test"

    # Check with NTP first
    if command_exists "ntpstat"; then
        info "Using NTP for checking time sync"
        if ntpstat >/dev/null; then
            info "Time synced via ntp"
            info "Done checking clock sync"
            return 0
        else
            result=$?
            if [ "$result" -eq 1 ]; then
                # no need to check chrony in this case
                fatal "Clock not synchronized"
            elif [ "$result" -eq 2 ]; then
                # NTP installed but potentially not running, check chrony state
                warn "NTP Clock state indeterminate"
            fi
        fi
    fi

    # Check with chrony in case NTP has issues or is not configured correctly
    if [ -f "/etc/chrony/chrony.conf" ]; then
        info "Using Chrony for checking time sync"
        if systemctl is-active -q chronyd; then
            info "Time synced via chrony"
            info "Done checking clock sync"
            return 0
        fi
        # TODO: Better method to check if time is synced or not, then fatal here
        warn "Chrony is not running"
    else
        warn "Neither NTP nor Chrony is configured."
    fi
}

# --- ensure we meet minimum RAM requirements
check_total_ram() {
    info "Checking RAM amount"
    memory=$(grep -oP '^MemTotal:\s+\K\d+' /proc/meminfo)
    memory_gb=$(numfmt --from=auto --from-unit=1024 --to=iec "$memory")
    min_mem_kb=$((MIN_MEMORY * 1000 * 1000))
    if [ "$memory" -lt "$min_mem_kb" ]; then
        fatal "Available memory $memory_gb is lower than the recommended minimum of ${MIN_MEMORY}G"
    fi
    info "Done checking RAM amount: $memory_gb"
}

# --- ensure we meet minimum CPU requirements
check_total_cpus() {
    info "Checking available CPUs"
    cpus=$(nproc --all)
    if [ "$cpus" -lt "$MIN_CPU" ]; then
        fatal "Available CPUs $cpus is lower than the recommended minimum of $MIN_CPU"
    fi
    info "Done checking CPU amount: $cpus"
}

# --- ensure VM ram, cpu, AVX and architecture requirements
require_compute_prereqs() {
    if [ "${SECURITI_SKIP_COMPUTE_CHECKS}" = "true" ]; then
        return
    fi
    require_64bit_architecture
    check_total_cpus
    check_total_ram
    require_avx_cpu
}
# END validations

# --- check hostname access
check_host_access() {
    URL=$1
    expected_response=$2

    # check URL in DNS
    info "Checking hostname access https://$URL"
    if command_exists "ns_lookup"; then
        dns_lookup=$(nslookup "$URL" | tail -2 | head -1 | grep -i Address)
    elif command_exists "getent"; then
        dns_lookup=$(getent hosts "$URL")
    fi
    if [ -z "$dns_lookup" ]; then
        fatal "Cannot resolve domain name $URL"
        return 1
    fi

    # check http response code
    if command_exists "curl"; then

        http_response=$(curl -ILs -m2 "https://$URL" | head -n 1 | tr -d '\r')
        response_code="${http_response:-"EMPTY"}"
        if ! contains "$response_code" "$expected_response"; then
            fatal "Received response ${response_code}, expected response ${expected_response}"
            return 1
        fi
    fi

    info "Done checking https://$URL"
    return 0
}

# --- check for required hosts to be accessible
check_hosts() {
    HTTP_OK=200
    HTTP_FORBIDDEN=403
    HTTP_FOUND=302

    check_host_access "$host_url" "$HTTP_OK"                     # Securiti app url
    check_host_access "$s3_bucket" "$HTTP_FORBIDDEN"             # AWS s3 bucket
    check_host_access "$package_url" "$HTTP_FORBIDDEN"           # CDN for appliance bundle
    check_host_access "$starport_layer_bucket" "$HTTP_FORBIDDEN" # Pod auto update
    check_host_access "$cloudfront_url" "$HTTP_OK"               # Cloudfront

    check_host_access "manage-support.securiti.ai" "$HTTP_FOUND" # Remote management
}

# --- check for network ports
port_test() {
    info "Checking for port availability"
    # list of ports
    set -- 53 2379 2380 4001 7001 3008 3009 3010 3011 3012 3022 3023 3024 3025 3080 4242 5000 5001 9100 6443 7575 8472 10001 10002 10003 10004 10005 10248 10249 10250 10255 51820 51821 61008 61009 61010 61022 61023 61024
    for port in "$@"; do
        result=$(grep -w "$port/tcp" /etc/services | awk '{print $1}' | head -c-1)
        if [ -n "$result" ]; then
            warn "Port $port mapped to service $result"
        fi
    done

    start_port=30000
    end_port=32767
    while [ $start_port -lt $end_port ]; do
        result=$(grep -w "$start_port/tcp" /etc/services | awk '{print $1}' | head -c-1)
        if [ -n "$result" ]; then
            warn "Port $port mapped to service $result"
        fi
        start_port=$((start_port + 1))
    done

    # Check ports used by customer's applications
    set -- 5000 5001 9100
    for i in "$@"; do
        if command_exists "lsof"; then
            result=$(lsof -i :"$i" | awk 'NR==2 {print $1}' | head -c-1)
        elif command_exists "ss"; then
            result=$(ss -tulpn | grep "$i" | awk '{print $7}' | sed -e 's/.*"\(.*\)".*/\1/' | tr '\n' ' ')
        fi

        if [ -n "$result" ]; then
            warn "Port $port currently being used by service $result"
        fi
    done

    info "Done checking ports"
    return 0
}

check_iptables() {
    info "Checking version of iptables used"
    if command_exists iptables; then
        found_version=$(iptables --version | awk '{print $2}')
        set -- v1.8.0 v1.8.1 v1.8.2 v1.8.3 v1.8.4 # https://docs.k3s.io/known-issues#:~:text=Iptables%20versions%201.8.0%2D1.8.4%20have%20known%20issues%20that%20can%20cause%20K3s%20to%20fail
        for version in "$@"; do
            if [ "$found_version" = "$version" ]; then
                fatal "Unsupported iptables version $version found. Please remove the \"iptables\" and \"nftables\" packages from your system before proceeding with the Securiti Pod install"
            fi
        done
    fi
    info "Done checking iptables version"
}

network_tests() {
    if [ "${SECURITI_SKIP_NETWORK_TESTS}" = "true" ]; then
        return
    fi
    check_hosts
    port_test
    check_iptables
}

# --- helper function, search substring in string
contains() {
    string="$1"
    substring="$2"
    if [ "${string#*"$substring"}" != "$string" ]; then
        return 0 # $substring is in $string
    else
        return 1 # $substring is not in $string
    fi
}

# --- check for weak ssh ciphers
weak_cipher_test() {
    info "Ensuring strong ssh ciphers are used"
    available_ciphers=$(sshd -T | grep "ciphers" | cut -d' ' -f2- | tr -d '\n')
    IFS=","
    strong_cipher_list="chacha20-poly1305@openssh.com aes256-gcm@openssh.com aes128-gcm@openssh.com aes256-ctr aes192-ctr aes128-ctr"
    for cipher in $available_ciphers; do
        if ! contains "$strong_cipher_list" "$cipher"; then
            warn "Weak ssh cipher found: $cipher"
        fi
    done
    unset IFS
    info "Done checking Ciphers"
}

# --- attempt to set all the necessary pre reqs required to install an appliance
set_system_prereqs() {
    if [ "${SECURITI_SKIP_PRE_REQ_CHECKS}" = "true" ]; then
        warn 'Skipping system pre-reqs'
        return
    fi
    info "Setting pre-reqs"
    load_kernel_modules
    set_sysctl_config
    disable_selinux
    set_file_descriptor_limits
    ensure_thp_disabled
    disable_or_config_firewall
    disable_conflicting_services
    info "Done setting pre-reqs"
    list_errors
}

# --- ensure all required pre-reqs are met
ensure_system_prereqs() {
    if [ "${SECURITI_SKIP_PRE_REQ_CHECKS}" = "true" ]; then
        warn 'Skipping system pre-reqs'
        return
    fi
    info "Ensuring pre-reqs"
    require_compute_prereqs
    network_tests
    weak_cipher_test
    validate_sysctl_config
    validate_file_descriptor_limits
    check_selinux_status
    validate_disk_pre_reqs
    check_time_sync
    info "Done ensuring pre-reqs"
    list_errors
}

# Helper function to manage manual confirmations for certain commands
get_confirmation() {
    if [ -n "$1" ] && $1; then
        return 0
    fi
    info "Are you sure you would like to proceed? (y/n)"
    while true; do
        read -r yn
        case $yn in
        [Yy]*)
            return 0
            ;;
        [Nn]*)
            return 1
            ;;
        *) info "Please answer (y)es or (n)o." ;;
        esac
    done
}

list_k8s_pods() {
    if [ -n "$1" ]; then
        case $1 in
        "--job" | "--jobs" | "-j")
            info "Listing all jobs"
            k3s kubectl get job
            ;;
        "-w" | "--watch")
            info "Watching all pods. Press ^C (ctrl+C) to exit"
            k3s kubectl get pod -w -A
            ;;
        "-A" | "--all-namespaces")
            info "Listing all pods across all namespaces"
            k3s kubectl get pods -A -o wide
            ;;
        *)
            warn "Unknown command \"$1\""
            return 1
            ;;
        esac
    # By default list all pods in 'default' NS
    else
        info "Listing all pods"
        k3s kubectl get pods -o wide
    fi
    return 0
}

scale_k8s_pod() {
    if [ "$1" = "-d" ] && [ -n "$2" ]; then
        deploymentName="$2"
        if [ -n "$3" ] && [ "$3" -eq "$3" ] 2>/dev/null && [ "$3" -gt 0 ] && [ "$3" -le 10 ]; then
            replicas="$3"
        else
            fail "Error in value \"$3\", please input a value between 1 and 10 to scale to"
        fi
    else
        printf "\t Deployment name not specified, please use the following argument"
        printf "\n\t\t\t-d\t\t Specify deployment to scale, e.g. troubleshoot pods scale -d <deployment-name> <amount>"
        printf "\n"
        fail "Required option not specified"
    fi

    # check if argument is a number, and within the given range
    k3s kubectl scale deploy "$deploymentName" --replicas="$replicas"
    return 0
}

delete_k8s_pods() {
    if [ -z "$1" ]; then
        printf "Available options:"
        printf "\n\t--securiti\t\t Delete all Securiti Pods"
        printf "\n\t--failed\t\t Delete only failed pods"
        printf "\n\t--completed\t\t Delete only completed pods"
        printf "\n\t--all\t\t Delete all pods across all namespaces"
        printf " \n"
        fail "Required option not specified"
    fi
    while :; do
        if [ -z "$1" ]; then
            break
        fi
        case $1 in
        "--securiti")
            securiti=true
            ;;
        "--failed")
            failed=true
            ;;
        "--completed")
            completed=true
            ;;
        "--all")
            all=true
            ;;
        "-y" | "--assume-yes")
            skip_confirm=true
            ;;
        *)
            warn "Unknown command \"$1\""
            return 1
            ;;
        esac
        shift
    done

    info "The following pods will be restarted/deleted"
    if [ -n "$all" ] && "$all"; then
        k3s kubectl get pods -A
    else
        if [ -n "$securiti" ] && "$securiti"; then
            k3s kubectl get pods
        fi
        if [ -n "$completed" ] && "$completed"; then
            k3s kubectl get pod --field-selector=status.phase==Succeeded
        fi
        if [ -n "$failed" ] && "$failed"; then
            k3s kubectl get pod --field-selector=status.phase==Failed
        fi
    fi
    if ! get_confirmation "$skip_confirm"; then
        return 2
    fi
    if [ -n "$all" ] && "$all"; then
        k3s kubectl delete pod -A --all
        return 0
    fi
    if [ -n "$securiti" ] && "$securiti"; then
        k3s kubectl delete pods --all
    fi
    if [ -n "$completed" ] && "$completed"; then
        k3s kubectl delete pod --field-selector=status.phase==Succeeded
    fi
    if [ -n "$failed" ] && "$failed"; then
        k3s kubectl delete pod --field-selector=status.phase==Failed
    fi
    return 0
}

capture_logs() {
    if [ "$1" = "-d" ] && [ -n "$2" ]; then
        deploymentName="$2"
        if [ -n "$3" ]; then
            if [ "$3" = "-c" ]; then
                if [ -n "$4" ]; then
                    container="$4"
                else
                    fail "Container name not provided"
                fi
            else
                fail "Unknown argument \"$3\""
            fi
        fi
    else
        printf "\t Please use one of the following options:"
        printf "\n\t\t\t-d\t\t Specify deployment to list logs for, e.g. troubleshoot logs -d <deployment-name>"
        printf "\n\t\t\t-c\t\t Optional argument to only list logs for a specific container, e.g. troubleshoot pods logs -d <deployment-name> -c <container-name>"
        printf "\n"
        fail "Required option not specified"
    fi

    if ! k3s kubectl get deployment "$deploymentName"; then
        fail "No deployment found with name $deploymentName"
    fi

    time_stamp=$(date +"%d-%m-%Y")
    logs_path="${time_stamp}"
    mkdir -p "$logs_path"
    cd "$logs_path" || exit

    info "Capturing logs to $logs_path"
    for pod in $(k3s kubectl get pods | grep "$deploymentName" | awk '{print $1}'); do
        info "Capturing logs of $pod"
        if [ -z "$container" ]; then
            container=$(k3s kubectl get pods "$pod" -o jsonpath='{.spec.containers[*].name}')
        fi
        info "$container"
        for cont in $container; do
            info "Capturing logs of container $cont"
            k3s kubectl logs --tail 1000 "$pod" "$cont" >"$pod-$cont.log"
            k3s kubectl logs --tail 1000 "$pod" "$cont" --previous >"$pod-PREV-$cont.log"
        done
        info "Capturing describe pod for: $pod"
        k3s kubectl describe pod "$pod" >"$pod-DESC-Pod"
    done
    info "Capturing completed for: $deploymentName"

    info "Logs generated"
    return 0
}

check_node_health() {
    # TODO: Every node https://securitiai.atlassian.net/browse/PRIV-126674
    info "Hostname"
    printf "=========================================\n"
    hostname -I
    printf "\n"

    info "Disk Status"
    printf "=========================================\n"
    df -hT
    printf "\n"

    info "Memory Status"
    printf "=========================================\n"
    free -h
    printf "\n"

    info "K8s Pods Status"
    printf "=========================================\n"
    k3s kubectl top pods
    printf "\n"

    info "k3s Status"
    printf "=========================================\n"
    k3s status
    printf "\n"

    info "Nodes Status"
    printf "=========================================\n"
    k3s kubectl get node
    printf "\n"

    info "Nodes Describe"
    printf "=========================================\n"
    k3s kubectl describe node
    printf "\n"

    info "List Deployments"
    printf "=========================================\n"
    k3s kubectl get deploy
    printf "\n"

    info "List StateFulSets"
    printf "=========================================\n"
    k3s kubectl get statefulset
    printf "\n"

    info "Pod Images"
    printf "=========================================\n"
    k3s kubectl describe pod | grep Image:
    printf "\n"

    return 0
}

delete_images() {
    if [ -n "$1" ]; then
        version="-v $1"
    fi
    info "Deleting old container images"
    k3s kubectl exec -it deploy/priv-appliance-config-controller -- securitictl deleteimages "$version"
    return 0
}

# Delete local images, temporary files etc
disk_cleanup() {
    if [ -n "$1" ]; then
        while :; do
            if [ -z "$1" ]; then
                break
            fi
            case $1 in
            "--delete-images")
                delete_images=true
                if [ -n "$2" ] && [ "$2" != "-y" ] && [ "$2" != "--assume-yes" ]; then
                    version="$2"
                fi
                ;;
            "-y" | "--assume-yes")
                skip_confirm=true
                ;;
            *)
                warn "Unknown command \"$1\""
                return 1
                ;;
            esac
            shift
        done
    fi
    warn "This command will attempt to cleanup your disk by removing data from /mnt/data and any old downloaded container images"
    if ! get_confirmation "$skip_confirm"; then
        return 2
    fi
    info "Disk Status before cleanup"
    df -hT

    # disk cleanup, delete from /mnt/data
    k3s kubectl exec -it deploy/priv-appliance-config-controller -- securitictl diskcleanup

    if [ -n "$delete_images" ] && "$delete_images"; then
        delete_images "$version"
    fi
    info "Disk Status After cleanup"
    df -hT
    printf "\n\n\n-----------------------------------------------\n\n\n"
    return 0
}

register_pod() {
    if [ -z "$1" ]; then
        fail "No license key provided, aborting."
    fi
    licenseKey="$1"
    k3s kubectl exec -it deploy/priv-appliance-config-controller -- securitictl register -- -l "$licenseKey"
    info "Restarting config-controller pod"
    k3s kubectl rollout restart deploy/priv-appliance-config-controller
    info "Pod registered successfully."
}

deregister_pod() {
    if [ -n "$1" ] && { [ "$1" = "-y" ] || [ "$1" = "--assume-yes" ]; }; then
        skip_confirm=true
    fi
    warn "Attempting to Deregister Pod"
    if ! get_confirmation "$skip_confirm"; then
        return
    fi

    info "Deregistering Pod."
    k3s kubectl exec -it deploy/priv-appliance-config-controller -- securitictl update -- -r disable
    info "Pod deregistered successfully."
    return 0
}

fix_redis_aof() {
    k3s kubectl exec -it deploy/priv-appliance-config-controller -- securitictl redis-fix
}

reduce_redis_aof() {
    k3s kubectl exec -it deploy/priv-appliance-config-controller -- securitictl reduce-redis-aof
}

app_help() {
    printf "Usage: sh poddiagnostics.sh COMMAND [OPTIONS]"
    printf "\nAvailable Commands:"
    printf "\n\tinstall [OPTIONS]\t\t\t Parent command for running pre install diagnostics on your machine"
    printf "\n\tAvailable Options:"
    printf "\n\t\t-c, --check\t\t\t Check to see if the pod meets the required prerequisites"
    printf "\n\t\t-f, --fix\t\t\t Attempt to fix some issues that prevent the pod from being installed"
    printf "\n"
    printf "\ttroubleshoot [OPTIONS] Parent command for troubleshooting pods"
    printf "\n\tAvailable Subcommands/Options:"
    printf "\n\t\treport\t\t\t Creates pod logs report"
    printf "\n\t\tpods\t\t\t Parent command for K8S pods operations. For details and subcommands, run: sh poddiagnostics.sh troubleshoot pods help"
    printf "\n\t\tnode\t\t\t Parent command for K8S node operations. For details and subcommands, run: sh poddiagnostics.sh troubleshoot node help"
    printf "\n\t\tcleanup\t\t\t Clean up disk to recover storage. For details and subcommands, run: sh poddiagnostics.sh troubleshoot cleanup help"
    printf "\n\t\tregistration\t\t Register or deregister the Securiti Pod. For details and subcommands, run: sh poddiagnostics.sh troubleshoot register help"
    printf "\n"
}

# --- list any errors that may have occurred during diagnostics
list_errors() {
    if [ -n "$errors" ]; then
        {
            printf "\nDiagnostics scan complete. The following errors were encountered. Please fix them before proceeding with the Pod installation:\n"
            printf "%s" "$errors"
            printf "\n"
        }
    fi
}

# --- helper function to remove ANSI escape sequences from a given file
remove_escape_sequences() {
    file="$1"
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g" "$file" >./tmp.log
    mv -f ./tmp.log "$file"
    # Fix some permissions that get broken due to root user editing the diagnostics log file
    chmod o+rwx "$file"
}

run_logs_command() {
    command_name="$1"
    file_name="$2"

    if $command_name >"$file_name" 2>&1; then
        info "Command '$command_name' successfully executed. Output saved to '$file_name'."
    else
        warn "Failed to execute command '$command_name'."
    fi

}

bundle_logs() {
    # Get the current timestamp for the tarball filename
    timestamp=$(date +"%Y%m%d%H%M%S")

    # Create a tarball with the current timestamp in the filename
    tar_filename="logs_bundle_${timestamp}.tar.gz"
    if tar -czf "$tar_filename" "$@"; then
        info "Log files bundled successfully. Tarball: $tar_filename"

        rm "$@"

        info "Original log files removed."
    else
        warn "Failed to bundle log files."
    fi
}

diagnostics_file="diagnostics.log"
require_root_user 2>&1 | tee "$diagnostics_file"
# unable to check exit status of require_root_user because "tee" creates a sub shell
if grep -Fq "[FAIL]" "$diagnostics_file"; then
    remove_escape_sequences "$diagnostics_file"
    exit 1
fi

case "$1" in
"install")
    case "$2" in
    "--check" | "-c")
        ensure_system_prereqs 2>&1 | tee -a "$diagnostics_file"
        ;;
    "--fix" | "-f")
        set_system_prereqs 2>&1 | tee -a "$diagnostics_file"
        ;;
    *)
        printf "Install needs the one of the following options to run:"
        printf "\n\t-c, --check\t\t Check to see if the pod meets the required prerequisites"
        printf "\n\t-f, --fix\t\t Attempt to fix some issues that prevent the pod from being installed"
        printf "\n"
        fail "Required option not specified"
        ;;
    esac
    remove_escape_sequences "$diagnostics_file"
    # unable to check exit status of prereqs commands because "tee" creates a sub shell
    if grep -Fq "[ERROR]" "$diagnostics_file"; then
        exit 1
    fi
    ;;
"troubleshoot")
    case "$2" in
    "report")
        info "creating reports"
        run_logs_command "ps aux" "ps_out_running_process"
        run_logs_command "journalctl" "journalctl_logs"
        run_logs_command "free -h" "memory_usage"
        run_logs_command "top -b -n 1" "cpu_usage"
        if command_exists "lsof"; then
            run_logs_command "lsof -i -P -n +c0" "ports"
        elif command_exists "ss"; then
            run_logs_command "ss -tulpn" "ports"
        else
            warn "No command available for checking ports"
        fi
        run_logs_command "systemctl list-units --type=service" "systemctl_services_status"
        bundle_logs "ps_out_running_process" "journalctl_logs" "memory_usage" "cpu_usage" "ports" "systemctl_services_status"
        ;;
    "pods")
        case "$3" in
        "list")
            list_k8s_pods "$4"
            ;;
        "scale")
            shift 3
            scale_k8s_pod "$@"
            ;;
        "delete")
            shift 3
            delete_k8s_pods "$@"
            ;;
        "logs")
            shift 3
            capture_logs "$@"
            ;;
        "help")
            printf "You can use the pod command to perform various operations on k8s pods"
            printf "\nThe following operations are available:"

            printf "\n\tlist\t List pods in the default namespace. Optional views are also available:"
            printf "\n\t\t\t-j, --job, --jobs\t Show only the jobs in the default namespace "
            printf "\n\t\t\t-w, --watch\t\t List and watch all pods in all namespace"
            printf "\n\t\t\t-A, --all-namespaces\t Show all pods across all the namespaces"
            printf "\n"

            printf "\n\tscale\t Scale a deployment to the provided size:"
            printf "\n\t\t\t-d\t\t Specify deployment to scale, e.g. troubleshoot pods scale -d <deployment-name> <amount>"
            printf "\n"

            printf "\n\tdelete\t Delete/restart pods. You need to specify which pods to delete:"
            printf "\n\t\t\t--securiti\t\t Delete all Securiti Pods"
            printf "\n\t\t\t--failed\t\t Delete only failed pods"
            printf "\n\t\t\t--completed\t\t Delete only completed pods"
            printf "\n\t\t\t--all\t\t\t\t Delete all pods across all namespaces"
            printf "\n"

            printf "\n\tlogs\t Show logs for all k8s pods. You can use the following options to filter logs for only the mentioned pods:"
            printf "\n\t\t\t-d\t\t Specify deployment to list logs for, e.g. troubleshoot logs -d <deployment-name>"
            printf "\n\t\t\t-c\t\t Optional argument to only list logs for a specific container, e.g. troubleshoot logs -d <deployment-name> -c <container-name>"
            printf "\n"
            ;;
        *)
            printf "Unknown command \"%s\"\n" "$3"
            ;;

        esac
        ;;
    "node")
        case "$3" in
        "health")
            check_node_health
            ;;
        "help")
            printf "You can use the node command to perform various operations on k8s nodes"
            printf "\nThe following operations are available:"
            printf "\n\thealth\t Show the health and details of the node where the Securiti Pod is running"
            printf "\n"
            ;;
        *)
            printf "Unknown command \"%s\"\n" "$3"
            ;;

        esac
        ;;
    "cleanup")
        case "$3" in
        "disk")
            shift 3
            disk_cleanup "$@"
            ;;
        "images")
            shift 3
            delete_images "$@"
            ;;
        "all")
            shift 3
            disk_cleanup --delete-images "$4"
            ;;
        "help")
            printf "You can use the cleanup command to free up used disk storage"
            printf "\nThe following operations are available:"
            printf "\n\tdisk\t Delete all data in /mnt/data"
            printf "\n\timages\t Delete old container images. If a specific version is provided (format like 1.103.0-03rc), only those images will be deleted"
            printf "\n\tall\t Delete all data in /mnt/data and all old container images"
            printf "\n"
            ;;
        *)
            printf "Unknown command \"%s\"\n" "$3"
            ;;
        esac
        ;;
    "registration")
        case "$3" in
        "deregister")
            deregister_pod "$4"
            ;;
        "help")
            printf "You can use the registration command to register or deregister a Securiti Pod"
            printf "\nTo register, simply provide the license key as such: registration <license-key>"
            printf "\nTo deregister, simply pass the 'deregister' argument as such: registration deregister"
            printf "\n"
            ;;
        *)
            register_pod "$3"
            ;;
        esac
        ;;
    *)
        printf "troubleshoot needs the one of the following options/subcommands to run:"
        printf "\n\treport\t\t\t Creates pod logs report"
        printf "\n\tpods\t\t\t Parent command for K8S pods operations. For details and subcommands, run: sh poddiagnostics.sh troubleshoot pods help"
        printf "\n\tnode\t\t\t Parent command for K8S node operations. For details and subcommands, run: sh poddiagnostics.sh troubleshoot node help"
        printf "\n\tcleanup\t\t\t Clean up disk to recover storage. For details and subcommands, run: sh poddiagnostics.sh troubleshoot cleanup help"
        printf "\n\tregistration\t\t Register or deregister the Securiti Pod. For details and subcommands, run: sh poddiagnostics.sh troubleshoot register help"
        printf "\n"
        fail "Required option not specified"
        ;;
    esac

    ;;
*)
    app_help
    ;;
esac
