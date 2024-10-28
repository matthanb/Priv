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
#   - SECURITI_NODE_KIND
#     One of "server" or "agent". The server runs the k8s control plane. The agent
#     represents a Kubernetes worker node.
#     Default: server
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
#
#   - SECURITI_BIN_DIR
#     Directory for installing executables during installation. This MUST be on system PATH.
#     Default: /usr/bin
#
#   - SECURITI_SKIP_AZURE_MOUNT_CHECK
#     If set to true, will not check for Azure mount related issues
#     Default: false
#

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
SECURITI_BIN_DIR="${SECURITI_BIN_DIR:-"/usr/bin"}"
SECURITI_NODE_KIND="${SECURITI_NODE_KIND:-"server"}"
SECURITI_SKIP_AZURE_MOUNT_CHECK="${SECURITI_SKIP_AZURE_MOUNT_CHECK:-false}"

# --- internal variables
PACKAGE_NAME="securiti-appliance-installer"
INSTALLATION_DIR="$SECURITI_INSTALL_DIR/installation/$PACKAGE_NAME"
TMP_DIR="/tmp"
K8S_CONFIG_DIR="/etc/rancher/k3s"
K8S_CLUSTER_SERVICE_CIDR="10.43.0.0/16"
K8S_CLUSTER_POD_CIDR="10.42.0.0/16"
POD_CIDR_BLOCK=$(echo "$K8S_CLUSTER_POD_CIDR" | awk '{print $1}' | awk -F. '{print $1"."$2}')
SERVICE_CIDR_BLOCK=$(echo "$K8S_CLUSTER_SERVICE_CIDR" | awk '{print $1}' | awk -F. '{print $1"."$2}')
HELM_INSTALLATION_NAME="priv-appliance"
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
MONITORING_MOUNT_PATH=$SECURITI_INSTALL_DIR/securiti-app/monitor/monitoring.log

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
troubleshoot() {
    printf "[TROUBLESHOOT] %s\n" "$1" >&2
    fatal "$2"
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

    warn "File descriptor limits set. Please reboot to apply changes "
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

thp_service_file="/etc/systemd/system/securiti-disable-thp.service"
# --- create thp service
create_thp_service() {
    cat >"$thp_service_file" <<EOF
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
    if [ ! -f "$thp_service_file" ]; then
        create_thp_service
    fi

    systemctl enable securiti-disable-thp.service

    info "Done disabling THP"
}

flannel_fix_service="/etc/systemd/system/securiti-flannel-fix.service"
# --- create flannel fix service
create_flannel_fix_service() {
    flannel_fix_script="${SECURITI_BIN_DIR}/securiti-flannel-fix.sh"
    cat >"$flannel_fix_script" <<EOF
#!/bin/sh
set -e
set -o noglob

# Maximum wait time in seconds (e.g., 300 seconds = 5 minutes)
MAX_WAIT=300
WAIT_INTERVAL=10
ELAPSED_TIME=0

while ! ip link show flannel.1 > /dev/null 2>&1; do
  sleep \$WAIT_INTERVAL
  ELAPSED_TIME=$((ELAPSED_TIME + WAIT_INTERVAL))
  if [ \$ELAPSED_TIME -ge \$MAX_WAIT ]; then
    echo "Timed out waiting for flannel.1 interface to become ready."
    exit 1
  fi
done
echo "Running ethtool command to set tx-checksum-ip-generic off for flannel.1"
# Now that flannel.1 is up, run the ethtool command
ethtool -K flannel.1 tx-checksum-ip-generic off
EOF
    chmod +x "$flannel_fix_script"
    service_name="k3s"
    if [ "$SECURITI_NODE_KIND" = "agent" ]; then
        service_name="${service_name}-agent"
    fi
    cat >"$flannel_fix_service" <<EOF
[Unit]
Description=Run command to fix flannel (vxlan + UDP) once after boot and K3s is up
Requires=${service_name}.service
After=${service_name}.service

[Service]
Type=oneshot
ExecStart=$flannel_fix_script

[Install]
WantedBy=default.target
EOF
}

# --- ensure flannel fix service is enabled
ensure_flannel_fix_service_enabled() {
    info "Enabling flannel fix service"
    # retain the setting after a reboot
    if [ ! -f "$flannel_fix_service" ]; then
        create_flannel_fix_service
    fi
    systemctl enable securiti-flannel-fix.service
    info "Done enabling flannel fix service"
}

# --- validate that flannel fix service is enabled
validate_flannel_fix_service_enabled() {
    service_name="k3s"
    if [ "$SECURITI_NODE_KIND" = "agent" ]; then
        service_name="${service_name}-agent"
    fi
    info "Validating flannel fix service is enabled"
    if systemctl is-enabled -q "$service_name" 2>/dev/null && ! systemctl is-enabled -q securiti-flannel-fix.service 2>/dev/null; then
        fatal "Securiti flannel fix service is not enabled"
    fi
    info "Done validating flannel fix service is enabled"
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

# --- check the conflict of azure mount with waagent
check_azure_mount() {
    if [ "${SECURITI_INSTALL_DIR}" = "/mnt" ]; then
        if [ "${SECURITI_SKIP_AZURE_MOUNT_CHECK}" = "true" ]; then
            warn 'Skipping Azure mount check'
            return
        fi

        info "Checking Azure mount"
        if [ -f /etc/waagent.conf ]; then
            if grep -q "^ResourceDisk\.MountPoint=/mnt$" /etc/waagent.conf; then
                fatal "Mounting Conflict with Linux waagent.
                Either of these options can be used to resolve the conflict:
                1. Change mount point of azure_resource disk from /mnt to /mnt/resource in /etc/fstab (add if entry does not exists)
                Example: <disk name>    /mnt/resource   auto    defaults,nofail,x-systemd.requires=cloud-init.service,_netdev,comment=cloudconfig       0       2
                Use 'chattr +i /etc/fstab' to make fstab immutable
                Change ResourceDisk.MountPoint=/mnt to ResourceDisk.MountPoint=/mnt/resource in /etc/waagent.conf
                2. Update the installation path outside of /mnt to prevent conflicts and ensure proper functionality
                Reboot the vm"
            fi
        fi
        info "Done checking Azure mount"
    else
        info "Skipping Azure mount check as SECURITI_INSTALL_DIR is not set to /mnt"
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

# --- Detect if the machine IP address lies within a specific provided CIDR range
detect_cidr_block() {
    cidr_block=$1

    # detect if file exists, check if cidr conflicts exist there
    override_dir="${K8S_CONFIG_DIR}/config.yaml.d"
    cidr_override="$override_dir/99-securiti-cidr-override.yaml"
    if [ -f $cidr_override ]; then
        service=$(grep -F "service-cidr: " "$cidr_override" | awk '{print $2}' | awk -F. '{print $1"."$2}')
        cluster=$(grep -F "cluster-cidr: " "$cidr_override" | awk '{print $2}' | awk -F. '{print $1"."$2}')
        if [ "$cidr_block" = "$service" ] || [ "$cidr_block" = "$cluster" ]; then
            return 0
        fi
        if grep -q "cluster-cidr:" "$cidr_override"; then
            return 1
        fi
        if grep -q "
        service-cidr:" "$cidr_override"; then
            return 1
        fi
    fi
    machine_cidr_block=$(hostname -I | awk '{print $1}' | awk -F. '{print $1"."$2}')
    if [ "$machine_cidr_block" = "$cidr_block" ]; then
        return 0
    fi
    return 1
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
            fatal "Unexpected HTTP response: ${response_code}"
            return 1
        fi
    fi

    info "Done checking https://$URL"
    return 0
}

# --- check for required hosts to be accessible
check_hosts() {
    HTTP_OK=200
    HTTP_FOUND=302
    HTTP_FORBIDDEN=403
    HTTP_NOT_FOUND=404

    check_host_access "$host_url" "$HTTP_OK"                     # Securiti app url
    check_host_access "$s3_bucket" "$HTTP_FORBIDDEN"             # AWS s3 bucket
    check_host_access "$package_url" "$HTTP_NOT_FOUND"           # CDN for Securiti Pod bundle
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
                fatal "Unsupported iptables version $version found. Please remove the \"iptables\" and \"nftables\" packages using the appropriate package manager for your system before proceeding with the Securiti Pod install (e.g. sudo apt remove iptables / sudo yum remove iptables) "
            fi
        done
    fi
    info "Done checking iptables version"
}

check_pod_ip() {
    info "Checking machine IP for conflicts against internal requirements"
    if detect_cidr_block "$POD_CIDR_BLOCK"; then
        troubleshoot "poddiagnostics.sh troubleshoot network override-cidr --pod-cidr <CIDR>" "Machine IP conflicts with K8S Pod IP. Run the troubleshooting hint to try to resolve this issue"
    fi
    if detect_cidr_block "$SERVICE_CIDR_BLOCK"; then
        troubleshoot "poddiagnostics.sh troubleshoot network override-cidr --service-cidr <CIDR>" "Machine IP conflicts with K8S Service IP. Run the troubleshooting hint to try to resolve this issue"
    fi
    info "Done checking IP conflicts"
}

network_tests() {
    if [ "${SECURITI_SKIP_NETWORK_TESTS}" = "true" ]; then
        return
    fi
    check_hosts
    port_test
    check_iptables
    check_pod_ip
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

# --- attempt to set all the necessary pre reqs required to install a Securiti Pod
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
    ensure_flannel_fix_service_enabled
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
    validate_flannel_fix_service_enabled
    check_azure_mount
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
            k3s kubectl get job -n "$SECURITI_INSTALL_NAMESPACE"
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
        k3s kubectl get pods -o wide -n "$SECURITI_INSTALL_NAMESPACE"
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
    k3s kubectl scale deploy -n "$SECURITI_INSTALL_NAMESPACE" "$deploymentName" --replicas="$replicas"
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
            k3s kubectl get pods -n "$SECURITI_INSTALL_NAMESPACE"
        fi
        if [ -n "$completed" ] && "$completed"; then
            k3s kubectl get pod -n "$SECURITI_INSTALL_NAMESPACE" --field-selector=status.phase==Succeeded
        fi
        if [ -n "$failed" ] && "$failed"; then
            k3s kubectl get pod -n "$SECURITI_INSTALL_NAMESPACE" --field-selector=status.phase==Failed
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
        k3s kubectl delete pods -n "$SECURITI_INSTALL_NAMESPACE" --all
    fi
    if [ -n "$completed" ] && "$completed"; then
        k3s kubectl delete pod -n "$SECURITI_INSTALL_NAMESPACE" --field-selector=status.phase==Succeeded
    fi
    if [ -n "$failed" ] && "$failed"; then
        k3s kubectl delete pod -n "$SECURITI_INSTALL_NAMESPACE" --field-selector=status.phase==Failed
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

    if ! k3s kubectl get deployment -n "$SECURITI_INSTALL_NAMESPACE" "$deploymentName"; then
        fail "No deployment found with name $deploymentName"
    fi

    time_stamp=$(date +"%d-%m-%Y")
    logs_path="${time_stamp}"
    mkdir -p "$logs_path"
    cd "$logs_path" || exit

    info "Capturing logs to $logs_path"
    for pod in $(k3s kubectl get pods -n "$SECURITI_INSTALL_NAMESPACE" | grep "$deploymentName" | awk '{print $1}'); do
        info "Capturing logs of $pod"
        if [ -z "$container" ]; then
            container=$(k3s kubectl get pods -n "$SECURITI_INSTALL_NAMESPACE" "$pod" -o jsonpath='{.spec.containers[*].name}')
        fi
        info "$container"
        for cont in $container; do
            info "Capturing logs of container $cont"
            k3s kubectl logs -n "$SECURITI_INSTALL_NAMESPACE" --tail 1000 "$pod" "$cont" >"$pod-$cont.log"
            k3s kubectl logs -n "$SECURITI_INSTALL_NAMESPACE" --tail 1000 "$pod" "$cont" --previous >"$pod-PREV-$cont.log"
        done
        info "Capturing describe pod for: $pod"
        k3s kubectl describe pod -n "$SECURITI_INSTALL_NAMESPACE" "$pod" >"$pod-DESC-Pod"
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
    k3s kubectl top pods -n "$SECURITI_INSTALL_NAMESPACE"
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
    k3s kubectl get deploy -n "$SECURITI_INSTALL_NAMESPACE"
    printf "\n"

    info "List StateFulSets"
    printf "=========================================\n"
    k3s kubectl get statefulset -n "$SECURITI_INSTALL_NAMESPACE"
    printf "\n"

    info "Pod Images"
    printf "=========================================\n"
    k3s kubectl describe pod -n "$SECURITI_INSTALL_NAMESPACE" | grep Image:
    printf "\n"

    return 0
}

delete_images() {
    if [ -n "$1" ]; then
        version="$1"
    fi
    scans=$(kubectl get pods -n "$SECURITI_INSTALL_NAMESPACE" -o jsonpath='{range .items[*]}{.metadata.name} {.status.phase}{"\n"}{end}' | grep "scanjob" | grep "Running")
    if [ -n "$scans" ]; then
          info "scanjob: $scans already running. cannot perform deletion"
          return 0
    else
          info "No scanjob found."
          # disk cleanup, delete from /mnt/data
          k3s kubectl exec -it deploy/priv-appliance-config-controller -n "$SECURITI_INSTALL_NAMESPACE" -- securitictl diskcleanup
    fi
    info "Deleting old container images"
    k3s kubectl exec -it -n "$SECURITI_INSTALL_NAMESPACE" deploy/priv-appliance-config-controller -- securitictl deleteimages -v "$version"
    return 0
}

# -- Check if k3s is properly installed
k8s_installed() {
    if command_exists k3s && k3s kubectl get pods >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# -- Check if Securiti Pod is installed
securiti_pod_installed() {
    name=$(k3s kubectl get pods -n "$SECURITI_INSTALL_NAMESPACE" -l app=config-controller -o name 2>&1 | grep config-controller)
    phase=$(k3s kubectl get "$name" -n "$SECURITI_INSTALL_NAMESPACE" -o jsonpath="{.status.phase}" 2>&1)
    if [ "$phase" = "Running" ]; then
        return 0
    fi
    return 1
}

# Delete local images, temporary files etc
disk_cleanup() {
    delete_images=false

    images_to_delete=$(k3s kubectl get jobs -o custom-columns=:.metadata.name --no-headers | grep scanjob)  
    if [ -n "$images_to_delete" ]; then
        warn "One or more scanjobs are running. Please wait for them to complete or stop them to proceed with disk cleanup"
        exit 1
    fi 

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

    if [ "$delete_images" ]; then
        warn "This command will attempt to cleanup your disk by removing data from ${SECURITI_INSTALL_DIR}/data and any old downloaded container images"
    else  
        warn "This command will attempt to cleanup your disk by removing data from ${SECURITI_INSTALL_DIR}/data"
    fi

    if ! get_confirmation "$skip_confirm"; then
        return 2
    fi
    info "Disk Status before cleanup"
    df -hT

    # disk cleanup, delete from /mnt/data
    k3s kubectl exec -it deploy/priv-appliance-config-controller -n "$SECURITI_INSTALL_NAMESPACE" -- securitictl diskcleanup

    if [ -n "$delete_images" ] && "$delete_images"; then
        delete_images "$version"
    fi
    info "Disk Status After cleanup"
    df -hT
    printf "\n\n\n-----------------------------------------------\n\n\n"
    return 0
}

replace_key_if_exists() {
    key=$1
    value=$2
    file=$3
    if grep -q "$key" "$file"; then
        sed -i "s|$key.*|${key}${value}|" "$file"
        return 0
    fi
    return 1
}

add_or_replace_key() {
    if ! replace_key_if_exists "$1" "$2" "$3"; then
        cat >>"$3" <<EOF
${1}${2}
EOF
    fi
}

# -- setup proxy on the node
setup_proxy() {
    if [ -z "$1" ]; then
        printf "Please enter an address to set HTTP proxy, e.g. troubleshoot network setup-proxy <hostname>:<port>"
        printf "\nAvailable options:"
        printf "\n\t--cert\t\t In case an intercepting proxy is used, this optional argument can be used to import the relevant certificate into K8S e.g troubleshoot network setup-proxy <hostname>:<port> --cert /path/to/cert-file"
        printf "\n\t--no-proxy\t Add additional custom addresses where proxy won't be applied. This argument can contain multiple, comma separated addresses e.g troubleshoot network setup-proxy <hostname>:<port> --no-proxy <address 1>,<address 2>..."
        printf " \n"
        fail "Missing required proxy address"
    fi

    while :; do
        if [ -z "$1" ]; then
            break
        fi
        case $1 in
        "--cert")
            if [ -z "$2" ]; then
                fail "Required option missing, please mention the path to the certificate"
            fi
            cert=$2
            shift 2
            ;;
        "--no-proxy")
            if [ -z "$2" ]; then
                fail "Required option missing, please list the addresses to exclude from proxy"
            fi
            custom_no_proxy=",$2"
            shift 2
            ;;
        *)
            proxy=$1
            shift
            ;;
        esac
    done

    private_ips=$(hostname -I | tr ' ' ',' | head -c -2)

    # Different files required for agent and server
    env_file="/etc/systemd/system/k3s.service.env"
    if [ "$SECURITI_NODE_KIND" = "agent" ]; then
        env_file="/etc/systemd/system/k3s-agent.service.env"
    fi

    all_no_proxy="0.0.0.0/0,.local,localhost,127.0.0.1,${private_ips}${custom_no_proxy}"

    # K3s installation ensures the existence of the k3s env file
    if k8s_installed; then
        # If keys exists, replacement is required
        # If keys do not exist, we will need to add them manually
        add_or_replace_key "HTTP_PROXY=" "$proxy" "$env_file"
        add_or_replace_key "HTTPS_PROXY=" "$proxy" "$env_file"
        add_or_replace_key "NO_PROXY=" "$all_no_proxy" "$env_file"
        add_or_replace_key "http_proxy=" "$proxy" "$env_file"
        add_or_replace_key "https_proxy=" "$proxy" "$env_file"
        add_or_replace_key "no_proxy=" "$all_no_proxy" "$env_file"
    else
        # in case k3s in not installed yet, we can use the environment variables instead
        cat >>"/etc/environment" <<EOF
HTTP_PROXY=$proxy
HTTPS_PROXY=$proxy
NO_PROXY=$all_no_proxy
http_proxy=$proxy
https_proxy=$proxy
no_proxy=$all_no_proxy
EOF
        warn "System environment variables have been modified, please restart the shell or run \"source /etc/environment\" to apply the proxy changes"
        # create local overrides file with proxy configurations. For custom install this can be required.
        mkdir -p "$INSTALLATION_DIR"
        cat >"$INSTALLATION_DIR/local-override-values.yaml" <<EOF
runtimeenvironment:
  env:
    HTTP_PROXY: $proxy
    HTTPS_PROXY: $proxy
    http_proxy: $proxy
    https_proxy: $proxy
    NO_PROXY: $all_no_proxy
    no_proxy: $all_no_proxy
EOF
    fi

    # Import certificate if provided
    if [ -n "$cert" ]; then
        if [ -f "$cert" ]; then
            cp "$cert" /etc/pki/ca-trust/source/anchors/
            # used during install
            cp "$cert" "$INSTALLATION_DIR"/custom-ca-cert.pem
            update-ca-trust
        else
            fail "Certificate file not found"
        fi
    fi

    # Create secret/configmap on K8S
    if k8s_installed; then
        if [ -n "$cert" ]; then
            cert_arg="--cert"
        fi
        if [ -n "$custom_no_proxy" ]; then
            no_proxy_arg="--no-proxy"
        fi
        install_proxy_k8s "$proxy" "$cert_arg" "$cert" "$no_proxy_arg" "$custom_no_proxy"

        # restart k3s
        warn "A k3s system restart is required to apply the proxy settings. Do you want to restart k3s now?"
        if ! get_confirmation "$skip_confirm"; then
            return
        fi
        systemctl restart k3s

        warn "K8s Pods need to be restarted to apply the proxy settings. Do you want to restart all pods now?"
        if ! get_confirmation "$skip_confirm"; then
            return
        fi
        kubectl get po -n "$SECURITI_INSTALL_NAMESPACE" | grep "priv-app" | awk '{print $1x}' | xargs kubectl delete po -n "$SECURITI_INSTALL_NAMESPACE"
    fi
}

# --- install proxy settings on K8S. Part of proxy setup, and can be used on its own as well
install_proxy_k8s() {
    if [ -z "$1" ]; then
        printf "Please enter an address to use for HTTP proxy, e.g. troubleshoot network install-proxy-k8s <hostname>:<port>"
        printf "\nAvailable options:"
        printf "\n\t--cert\t\t In case an intercepting proxy is used, this optional argument can be used to import the relevant certificate into K8S e.g troubleshoot network install-proxy-k8s <hostname>:<port> --cert /path/to/cert-file"
        printf "\n\t--no-proxy\t Add additional custom addresses where proxy won't be applied. This argument can contain multiple, comma separated addresses e.g troubleshoot network setup-proxy <hostname>:<port> --no-proxy <address 1>,<address 2>..."
        printf " \n"
        fail "Missing required proxy address"
    fi

    while :; do
        if [ -z "$1" ]; then
            break
        fi
        case $1 in
        "--cert")
            if [ -z "$2" ]; then
                fail "Required option missing, please mention the path to the certificate"
            fi
            cert=$2
            shift 2
            ;;
        "--no-proxy")
            if [ -z "$2" ]; then
                fail "Required option missing, please list the addresses to exclude from proxy"
            fi
            custom_no_proxy=",$2"
            shift 2
            ;;
        *)
            proxy=$1
            shift
            ;;
        esac
    done

    if ! k8s_installed && securiti_pod_installed; then
        fail "Securiti Pod is not installed yet, cannot proceed"
    fi

    private_ips=$(hostname -I | tr ' ' ',' | head -c -2)
    all_no_proxy="0.0.0.0/0,.local,localhost,127.0.0.1,${private_ips}${custom_no_proxy}"

    # if file exists, replace vars, else create file. use case: installed with proxy
    if [ -f "$INSTALLATION_DIR/local-override-values.yaml" ]; then
        if grep -Fq "runtimeenvironment:" "$INSTALLATION_DIR/local-override-values.yaml"; then
            #if keys exists, replace
            replace_key_if_exists "HTTP_PROXY: " "$proxy" "$INSTALLATION_DIR/local-override-values.yaml"
            replace_key_if_exists "HTTPS_PROXY: " "$proxy" "$INSTALLATION_DIR/local-override-values.yaml"
            replace_key_if_exists "http_proxy: " "$proxy" "$INSTALLATION_DIR/local-override-values.yaml"
            replace_key_if_exists "https_proxy: " "$proxy" "$INSTALLATION_DIR/local-override-values.yaml"
            replace_key_if_exists "NO_PROXY: " "$all_no_proxy" "$INSTALLATION_DIR/local-override-values.yaml"
            replace_key_if_exists "no_proxy: " "$all_no_proxy" "$INSTALLATION_DIR/local-override-values.yaml"
        else
            # append to file if keys do not exist. use case: installed without proxy
            cat >>"$INSTALLATION_DIR/local-override-values.yaml" <<EOF
runtimeenvironment:
  env:
    HTTP_PROXY: $proxy
    HTTPS_PROXY: $proxy
    http_proxy: $proxy
    https_proxy: $proxy
    NO_PROXY: $all_no_proxy
    no_proxy: $all_no_proxy
EOF
        fi
    else
        # create file if it does not exist. use case: running this before installation
        mkdir -p "$INSTALLATION_DIR"
        cat >"$INSTALLATION_DIR/local-override-values.yaml" <<EOF
runtimeenvironment:
  env:
    HTTP_PROXY: $proxy
    HTTPS_PROXY: $proxy
    http_proxy: $proxy
    https_proxy: $proxy
    NO_PROXY: $all_no_proxy
    no_proxy: $all_no_proxy
EOF
    fi

    if [ -n "$cert" ]; then
        k3s kubectl create configmap ca-pem-config -n "$SECURITI_INSTALL_NAMESPACE" --from-file=custom-ca-cert.pem="$cert"
        kubectl get po -n "$SECURITI_INSTALL_NAMESPACE" | grep "priv-app" | awk '{print $1x}' | xargs kubectl delete po -n "$SECURITI_INSTALL_NAMESPACE"
    fi

    k3s kubectl exec -it -n "$SECURITI_INSTALL_NAMESPACE" deploy/priv-appliance-config-controller -- securitictl perform-upgrade
    return 0

}

override_cidr() {
    if [ -z "$1" ]; then
        printf "Available options:"
        printf "\n\t--pod-cidr\t\t Override default CIDR for K8s pods, e.g. troubleshoot network override-cidr --pod-cidr <CIDR>"
        printf "\n\t--service-cidr\t\t Override default CIDR for K8s services, e.g. troubleshoot network override-cidr --service-cidr <CIDR>"
        printf " \n"
        fail "Required option not specified"
    fi
    while :; do
        if [ -z "$1" ]; then
            break
        fi
        case $1 in
        "--service-cidr")
            if [ -z "$2" ]; then
                fail "Required option missing, please enter an IP block to override service CIDR"
            fi
            service_cidr=$2
            ;;
        "--pod-cidr")
            if [ -z "$2" ]; then
                fail "Required option missing, please enter an IP block to override pod CIDR"
            fi
            pod_cidr=$2
            ;;
        *)
            warn "Unknown command \"$1\""
            return 1
            ;;
        esac
        shift 2
    done

    # if k3s is installed properly, we cannot proceed
    if k8s_installed && securiti_pod_installed; then
        fail "Securiti Pod is already installed, cannot override CIDRs now"
    fi

    override_dir="${K8S_CONFIG_DIR}/config.yaml.d"
    mkdir -p "$override_dir"
    override_file="$override_dir/99-securiti-cidr-override.yaml"

    if [ -n "$pod_cidr" ]; then
        pod_override="cluster-cidr: $pod_cidr"
    fi
    if [ -n "$service_cidr" ]; then
        service_override="service-cidr: $service_cidr"
    fi
    cat >"$override_file" <<EOF
$pod_override
$service_override
EOF
    chmod 600 "$override_file"
}

register_pod() {
    if [ -z "$1" ]; then
        fail "No license key provided, aborting."
    fi
    licenseKey="$1"
    k3s kubectl exec -it -n "$SECURITI_INSTALL_NAMESPACE" deploy/priv-appliance-config-controller -- securitictl register -l "$licenseKey"
    info "Restarting config-controller pod"
    k3s kubectl rollout restart -n "$SECURITI_INSTALL_NAMESPACE" deploy/priv-appliance-config-controller
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
    k3s kubectl exec -it -n "$SECURITI_INSTALL_NAMESPACE" deploy/priv-appliance-config-controller -- securitictl update -r disable
    info "Pod deregistered successfully."
    return 0
}

helm_revision_list() {
  info "Available helm revision list"
  export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

  # Get the history of the release
  HISTORY=$(${INSTALLATION_DIR}/helm history "$HELM_INSTALLATION_NAME" --namespace "$SECURITI_INSTALL_NAMESPACE" --max 1000) || fail "Failed to get release history"

  # Print the release history
  echo "Release History for $HELM_INSTALLATION_NAME:"
  echo "$HISTORY"
}

helm_rollback() {

  if [ -z "$1" ]; then
      troubleshoot "poddiagnostics.sh troubleshoot helm revision-list" "Please provide the rollback revision fetched via troubleshooting command"
      fail "Required option not specified"
  fi

  if [ -n "$2" ] && { [ "$2" = "-y" ] || [ "$2" = "--assume-yes" ]; }; then
      skip_confirm=true
  fi
  warn "Attempting to rollback helm revision"
  if ! get_confirmation "$skip_confirm"; then
      return
  fi


  export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

  ${INSTALLATION_DIR}/helm rollback "$HELM_INSTALLATION_NAME" "$1" --namespace "$SECURITI_INSTALL_NAMESPACE" || fail "Failed to roll back to revision $REVISION"

}

fix_redis_aof() {
    k3s kubectl exec -it -n "$SECURITI_INSTALL_NAMESPACE" deploy/priv-appliance-config-controller -- securitictl redis-fix
}

reduce_redis_aof() {
    k3s kubectl exec -it -n "$SECURITI_INSTALL_NAMESPACE" deploy/priv-appliance-config-controller -- securitictl reduce-redis-aof
}

# --- creating node monitoring script
create_node_monitoring_script() {
    cat <<EOF >/usr/local/bin/monitoringNode.sh
                  #!/bin/bash
                  is_selinux_status_changed(){
                    status=\$(sudo grep "SELINUX=disabled" "/etc/selinux/config")
                    if [ -n "\$status" ]; then
                        if [ "$ENABLE_SELINUX" = true ]; then
                            echo "true"
                        else
                            echo "false"
                        fi
                    else
                        if [ "$ENABLE_SELINUX" = false ]; then
                            echo "true"
                        else
                            echo "false"
                        fi
                    fi
                  }
                  if [ -f "$MONITORING_MOUNT_PATH" ]; then
                    sudo rm -rf "$MONITORING_MOUNT_PATH"
                  fi
                  if [ "\$(sudo sysctl -n kernel.pid_max)" != "4194304" ]; then
                      sudo sysctl -n kernel.pid_max=4194304
                      echo 'pidMax' >> "$MONITORING_MOUNT_PATH"
                  fi

                  if [ "\$(sudo sysctl -n vm.max_map_count)" != "262144" ]; then
                    	sudo sysctl -n vm.max_map_count=262144
                    	echo 'vmMaxMapCount' >> "$MONITORING_MOUNT_PATH"
                  fi

                  if [ "\$(sudo sysctl -n net.ipv4.conf.all.forwarding)" != "1" ]; then
                      echo 'ipForward' >> "$MONITORING_MOUNT_PATH"
                  fi

                  if [ "\$(sudo sysctl -n net.bridge.bridge-nf-call-iptables)" != "1" ]; then
                      echo 'bridgeNf' >> "$MONITORING_MOUNT_PATH"
                  fi

                  if [ "\$(sudo sysctl -n fs.inotify.max_user_watches)" != "1048576" ]; then
                      sudo sysctl -n fs.inotify.max_user_watches=1048576
                      echo 'iNotifyWatch' >> "$MONITORING_MOUNT_PATH"
                  fi

                  if [ "\$(is_selinux_status_changed)" = true ]; then
                      sudo sed -i '/^SELINUX=/c\SELINUX=disabled' /etc/selinux/config
                      echo 'selinux' >> "$MONITORING_MOUNT_PATH"
                  fi

                  if [ ! -f "$MONITORING_MOUNT_PATH" ]; then
                		echo 'no system changes made' >> "$MONITORING_MOUNT_PATH"
                  fi
EOF
}

# --- running monitoring cronjob
node_monitoring_cronjob() {
    #running node monitoring cronjob
    crontab_list=$(crontab -l || info "no crontab for root")
    if echo "$crontab_list" | grep -q "0 \* \* \* \* /usr/local/bin/monitoringNode.sh"; then
        info "cronjob for monitoringNode service is already running..."
    else
        rm -rf /usr/local/bin/monitoringNode.sh
        touch /usr/local/bin/monitoringNode.sh
        create_node_monitoring_script
        info "script created..."
        chmod +x /usr/local/bin/monitoringNode.sh
        echo "0 * * * * /usr/local/bin/monitoringNode.sh" | crontab -
        info "cron job for monitoringNode service running successfully…"
    fi
}

# --- monitor pod utils to monitor the status of the pod utils service
monitor_pod_utils() {
    info "Monitoring the status of the pod utils service"
    cron_script="/usr/local/bin/monitoringPodUtils.sh"
    logrotate_config="/etc/logrotate.d/monitor"
    log_path="/mnt/monitor.log"
    touch $log_path

    cat <<EOF >"$cron_script"
#!/bin/bash

printf "Time:  %s\n" "$(date)" >>"$log_path"
printf "TEST DISK##########\n" >>"$log_path"

df -lh >>"$log_path"

printf "TEST DISK-IO tmp##########\n" >>"$log_path"
dd if=/dev/zero of=/tmp/output conv=fdatasync bs=350k count=1k 2>>"$log_path"

printf "TEST DISK-IO root##########\n" >>"$log_path"
dd if=/dev/zero of=/output conv=fdatasync bs=350k count=1k 2>>"$log_path"

rm /tmp/output
rm /output

printf "TEST USAGE##########\n" >>"$log_path"
top -b | awk 'FNR>=7 && FNR<=15;FNR==15{exit}' >>"$log_path"

printf "TEST KUBERNETES USAGE##########\n" >>"$log_path"
kubectl top nodes >>"$log_path"

printf "TEST KUBERNETES POD USAGE##########\n" >>"$log_path"
kubectl top pods -n "$SECURITI_INSTALL_NAMESPACE" >>"$log_path"

printf "TEST CLUSTER HEALTH##########\n" >>"$log_path"
kubectl get cs >>"$log_path"
EOF

    chmod +x "$cron_script"

    if (crontab -l | grep -Eq "^\*/5 \* \* \* \* $cron_script"); then
        info "Cron job for monitor the status of the pod utils service is already running..."
    else
        (
            crontab -l
            echo "*/5 * * * * $cron_script"
        ) | crontab -
        info "Cron job for monitor the status of the pod utils service running successfully..."
    fi

    # Add logrotate configuration
    cat <<LOGROTATE >"$logrotate_config"
/mnt/monitor.log {
    su root adm
    rotate 5
    size 1M
    compress
    delaycompress
}
LOGROTATE

    # Run logrotate
    logrotate "$logrotate_config"
    info "log rotation for monitor log is done"
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
    printf "\n\t\tnetwork\t\t\t Parent command for any network related operations. For details and subcommands, run: sh poddiagnostics.sh troubleshoot network help"
    printf "\n\t\tmonitor\t\t\t Monitor the pod utils of the Securiti Pod. For details and subcommands, run: sh poddiagnostics.sh troubleshoot monitor help"
    printf "\n\t\tregistration\t\t Register or deregister the Securiti Pod. For details and subcommands, run: sh poddiagnostics.sh troubleshoot registration help"
    printf "\n\t\tcronjobs\t\t Run Cronjobs, For details and subcommands, run: sh poddiagnostics.sh troubleshoot cronjobs help"
    printf "\n\t\thelm\t\t\t Run HelmOperations, For details and subcommands, run: sh poddiagnostics.sh troubleshoot helm help"
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

# Detect if diagnostic script is running on a k3s server or agent
if systemctl -q is-enabled k3s-agent 2>/dev/null && systemctl -q is-active k3s-agent 2>/dev/null; then
    info "Overriding SECURITI_NODE_KIND=agent"
    export SECURITI_NODE_KIND="agent"
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
            printf "\n\tdisk\t Delete all data in: %s/data" "${SECURITI_INSTALL_DIR}"
            printf "\n\timages\t Delete old container images. If a specific version is provided (format like 1.103.0-03rc), only those images will be deleted"
            printf "\n\tall\t Delete all data in %s/data and all old container images" "${SECURITI_INSTALL_DIR}"
            printf "\n"
            ;;
        *)
            printf "Unknown command \"%s\"\n" "$3"
            ;;
        esac
        ;;
    "network")
        case "$3" in
        "override-cidr")
            shift 3
            override_cidr "$@"
            ;;
        "setup-proxy")
            shift 3
            setup_proxy "$@"
            ;;
        "install-proxy-k8s")
            shift 3
            install_proxy_k8s "$@"
            ;;
        "help")
            printf "You can use the network command to perform various network related operations on k8s"
            printf "\n\toverride-cidr\t Override default CIDR for K8S cluster and pods. This command will only work before the Securiti Pod is installed:"
            printf "\n\t\t\t\t--pod-cidr\t\t Override default CIDR for K8s pods, e.g. troubleshoot network override-cidr --pod-cidr <CIDR>"
            printf "\n\t\t\t\t--service-cidr\t\t Override default CIDR for K8s services, e.g. troubleshoot network override-cidr --service-cidr <CIDR>"
            printf "\n\tsetup-proxy\t Add a proxy to use for connecting to the Securiti Pod. A valid proxy endpoint is required to run this command e.g. troubleshoot network setup-proxy <hostname>:<port>:"
            printf "\n\t\t\t\t--cert\t In case an intercepting proxy is used, this optional argument can be used to import the relevant certificate into K8S e.g troubleshoot network setup-proxy <hostname>:<port> --cert /path/to/cert-file"
            printf "\n\t\t\t\t\t--no-proxy\t Add additional custom addresses where proxy won't be applied. This argument can contain multiple, comma separated addresses e.g troubleshoot network setup-proxy <hostname>:<port> --no-proxy <address 1>,<address 2>..."
            printf "\n\tinstall-proxy-k8s\t In case a proxy is set up before installing a Securiti Pod, this command can be used to ensure that k8s is properly set up. A valid proxy endpoint is required to run this command e.g. troubleshoot network install-proxy-k8s <hostname>:<port>:"
            printf "\n\t\t\t\t\t--cert\t In case an intercepting proxy is used, this optional argument can be used to import the relevant certificate into K8S e.g troubleshoot network install-proxy-k8s <hostname>:<port> --cert /path/to/cert-file"
            printf "\n\t\t\t\t\t--no-proxy\t Add additional custom addresses where proxy won't be applied. This argument can contain multiple, comma separated addresses e.g troubleshoot network setup-proxy <hostname>:<port> --no-proxy <address 1>,<address 2>..."

            printf "\n"
            ;;
        *)
            printf "Unknown command \"%s\"\n" "$3"
            ;;
        esac
        ;;
    "monitor")
        case "$3" in
        "pod-utils")
            shift 3
            monitor_pod_utils "$@"
            ;;
        "help")
            printf "You can use the monitor command to monitor the pod utils of the Securiti Pod"
            printf "\nThe following operations are available:"
            printf "\n\tpod-utils\t Monitor the disk i/o, kubernetes pod usage and other pod utils"
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
    "cronjobs")
        case "$3" in
        "node-monitoring")
            node_monitoring_cronjob "$4"
            ;;
        "help")
            printf "\n\tnode-monitoring\t run node_monitoring cronjob"
            printf "\n"
            ;;
        *)
            printf "Unknown command \"%s\"\n" "$3"
            ;;
        esac
        ;;
    "helm")
        case "$3" in
        "rollback")
            shift 3
            helm_rollback $@
            ;;
        "revision-list")
            helm_revision_list
            ;;
        "help")
            printf "You can use the helm command to list and rollback to available revision"
            printf "\nrevision-list\t lists outs all the available revisions"
            printf "\nTo rollback, you have to provide simply provide revision as such: rollback 140"
            printf "\n"
            ;;
        *)
            printf "Unknown command \"%s\"\n" "$3"
            ;;
        esac
        ;;
    *)
        printf "troubleshoot needs the one of the following options/subcommands to run:"
        printf "\n\treport\t\t\t Creates pod logs report"
        printf "\n\tpods\t\t\t Parent command for K8S pods operations. For details and subcommands, run: sh poddiagnostics.sh troubleshoot pods help"
        printf "\n\tnode\t\t\t Parent command for K8S node operations. For details and subcommands, run: sh poddiagnostics.sh troubleshoot node help"
        printf "\n\tcleanup\t\t\t Clean up disk to recover storage. For details and subcommands, run: sh poddiagnostics.sh troubleshoot cleanup help"
        printf "\n\tnetwork\t\t\t Parent command for any network related operations. For details and subcommands, run: sh poddiagnostics.sh troubleshoot network help"
        printf "\n\tmonitor\t\t\t Monitor the pod utils of the Securiti Pod. For details and subcommands, run: sh poddiagnostics.sh troubleshoot monitor help"
        printf "\n\tregistration\t\t Register or deregister the Securiti Pod. For details and subcommands, run: sh poddiagnostics.sh troubleshoot registration help"
        printf "\n\tcronjobs\t\t Run Cronjobs, For details and subcommands, run: sh poddiagnostics.sh troubleshoot cronjobs help"
        printf "\n\thelm\t\t\t Run HelmOperations, For details and subcommands, run: sh poddiagnostics.sh troubleshoot helm help"
        printf "\n"
        fail "Required option not specified"
        ;;
    esac
    ;;
*)
    app_help
    ;;
esac
