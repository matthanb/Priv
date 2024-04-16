#!/usr/bin/bash
#text colors
TXTNORMAL="\e[0m"
TXTBLINKON="\e[5m"
TXTBOLD="\e[1m"
TXTUNDERLINED="\e[4m"
TXTRED="\e[91m"
TXTGREEN="\e[92m"
TXTYELLOW="\e[93m"
TXTCYAN="\e[96m"
TXTBLUE="\e[34m"

show_help() {
echo ""
echo -e "${TXTBOLD}${TXTBLUE}This script will collect the output of some commands for troubleshooting purposes.${TXTNORMAL}"
echo -e "${TXTBOLD}${TXTBLUE}The commands will run and the output will be written to the output.log file.${TXTNORMAL}"
echo ""
echo -e "${TXTBOLD}${TXTBLINKON}${TXTUNDERLINED}${TXTYELLOW}No sensitive/confidential data will be collected.${TXTNORMAL}"
echo ""
}
show_help

echo -e "${TXTGREEN}1/23 Checking K3s/Gravity status${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}K3s status = systemctl status k3s${TXTNORMAL}"; echo "") > output.log
(systemctl status k3s > /dev/null 2>&1 >> output.log)
(echo ""; echo -e "${TXTGREEN}Gravity status = gravity status${TXTNORMAL}"; echo "") >> output.log
(gravity status > /dev/null 2>&1 >> output.log)
echo -e "${TXTGREEN}2/23 Checking Gravity current operations${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Gravity plan = gravity plan${TXTNORMAL}"; echo "") >> output.log
(gravity plan > /dev/null 2>&1 >> output.log)
echo -e "${TXTGREEN}3/23 Checking images${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Check images = crictl images${TXTNORMAL}"; echo "") >> output.log
(crictl images > /dev/null 2>&1 >> output.log)
echo -e "${TXTGREEN}4/23 Checking jobs status${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Check jobs status = kubectl get job${TXTNORMAL}"; echo ""; kubectl get job) >> output.log
echo -e "${TXTGREEN}5/23 Checking pods status${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Check pods status = kubectl get po -Ao wide${TXTNORMAL}"; echo ""; kubectl get po -Ao wide) >> output.log
echo -e "${TXTGREEN}6/23 Checking Deployments${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Check deployments = kubectl get deploy${TXTNORMAL}"; echo ""; kubectl get deploy) >> output.log
echo -e "${TXTGREEN}7/23 Checking Top pods${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Check Top Pods = kubectl top pods${TXTNORMAL}"; echo "") >> output.log
(kubectl top pods > /dev/null 2>&1 >> output.log)
echo -e "${TXTGREEN}8/23 Checking Top nodes${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Check Top Nodes = kubectl top nodes${TXTNORMAL}"; echo "") >> output.log
(kubectl top nodes > /dev/null 2>&1 >> output.log)
echo -e "${TXTGREEN}9/23 Checking nodes${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Check nodes = kubectl get nodes${TXTNORMAL}"; echo ""; kubectl get nodes) >> output.log
echo -e "${TXTGREEN}10/23 Checking Redis settings${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Check Redis settings = kubectl describe po priv-appliance-redis-master-0 | grep memory -A 4${TXTNORMAL}"; echo ""; kubectl describe po priv-appliance-redis-master-0 | grep memory -A 4) >> output.log
echo -e "${TXTGREEN}11/23 Checking common critical events${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Check common events = kubectl get events | egrep -i 'readiness|liveliness|oom'${TXTNORMAL}"; echo ""; kubectl get events | egrep -i 'readiness|liveliness|oom') >> output.log
echo -e "${TXTGREEN}12/23 Checking RAM memory${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Check RAM memory = free -g${TXTNORMAL}"; echo ""; free -g) >> output.log
echo -e "${TXTGREEN}13/23 Checking local disk space${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Check Disk space = df -hT --exclude-type=overlay --exclude-type=tmpfs${TXTNORMAL}"; echo ""; df -hT --exclude-type=overlay --exclude-type=tmpfs) >> output.log
echo -e "${TXTGREEN}14/23 Checking CPU cores${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Check CPU cores = lscpu | grep 'CPU(s)' -A 4${TXTNORMAL}"; echo ""; lscpu | grep 'CPU(s)' -A 4) >> output.log
echo -e "${TXTGREEN}15/23 Checking Redis maxmemory setting${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Check Redis maxmemory setting = kubectl describe cm priv-appliance-redis | grep maxmemory${TXTNORMAL}"; echo ""; kubectl describe cm priv-appliance-redis | grep maxmemory) >> output.log
echo -e "${TXTGREEN}16/23 Checking AOF file size${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Check AOF file size = ls -lhr${TXTNORMAL}"; echo "") >> output.log
(ls -lhr /mnt/hostpath/* > /dev/null 2>&1 >> output.log)
(ls -lhr /var/lib/hostpath/* > /dev/null 2>&1 >> output.log)
(ls -lhr /mnt/rancher/k3s/storage/*redis*/* > /dev/null 2>&1 >> output.log)
(ls -lhr /var/lib/rancher/k3s/storage/*redis*/* > /dev/null 2>&1 >> output.log)
echo -e "${TXTGREEN}17/23 Checking DBs health${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Check Redis health${TXTNORMAL}"; echo ""; kubectl get pod priv-appliance-redis-master-0 --output=jsonpath='{.status.conditions[?(@.type=="Ready")].status}') >> output.log
(echo ""; echo -e "${TXTGREEN}Check Elasticsearch health${TXTNORMAL}"; echo ""; kubectl get pod priv-appliance-elasticsearch-master-0 --output=jsonpath='{.status.conditions[?(@.type=="Ready")].status}') >> output.log
(echo ""; echo -e "${TXTGREEN}Check Postgresql health${TXTNORMAL}"; echo ""; kubectl get pod priv-appliance-postgresql-0 --output=jsonpath='{.status.conditions[?(@.type=="Ready")].status}') >> output.log
echo -e "${TXTGREEN}18/23 Checking Redis DB stats${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Check Redis DB stats = kubectl exec -it deploy/priv-appliance-config-controller -- securitictl getdbinfo 2>&1${TXTNORMAL}"; echo ""; kubectl exec -it deploy/priv-appliance-config-controller -- securitictl getdbinfo 2>&1) >> output.log
echo -e "${TXTGREEN}19/23 Checking Application version${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Check Application version = kubectl exec -it deploy/priv-appliance-config-controller -- cat /home/appuser/CURRENT_RELEASE${TXTNORMAL}"; echo "") >> output.log
(kubectl exec -it deploy/priv-appliance-config-controller -- cat /home/appuser/CURRENT_RELEASE > /dev/null 2>&1 >> output.log)
echo -e "${TXTGREEN}20/23 Checking HPA${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Check HPA = kubectl get hpa${TXTNORMAL}"; echo ""; kubectl get hpa) >> output.log
echo -e "${TXTGREEN}21/23 Checking Operating System${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Check OS = cat /etc/os-release${TXTNORMAL}"; echo ""; cat /etc/os-release) >> output.log
(echo ""; echo -e "${TXTGREEN}Check OS = uname -r${TXTNORMAL}"; echo ""; uname -r) >> output.log
echo -e "${TXTGREEN}22/23 Checking Network Device settings${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Check Flannel = ethtool -k flannel.1 | grep check${TXTNORMAL}"; echo ""; ethtool -k flannel.1 | grep check) >> output.log
echo -e "${TXTGREEN}23/23 Calculating '/mnt/data' subfolders size${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}/mnt/data subfolders size = du -h -d 1 /mnt/data | sort -h${TXTNORMAL}"; echo ""; du -h -d 1 /mnt/data | sort -h) >> output.log

show_help2() {
echo ""
echo -e "${TXTBOLD}${TXTBLUE}The process was completed and the output was written to the file.${TXTNORMAL}"
echo -e "${TXTBOLD}${TXTBLUE}Please attach the output.log file to the support ticket. Thank you.${TXTNORMAL}"
echo ""
}
show_help2