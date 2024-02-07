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

echo -e "${TXTGREEN}1/17 Checking Gravity Status${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Gravity status = gravity status${TXTNORMAL}"; echo ""; gravity status) > output.log
echo -e "${TXTGREEN}2/17 Checking Gravity current operation${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Gravity plan = gravity plan${TXTNORMAL}"; echo ""; gravity plan) >> output.log
echo -e "${TXTGREEN}3/17 Checking jobs status${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Check jobs status = kubectl get job${TXTNORMAL}"; echo ""; kubectl get job) >> output.log
echo -e "${TXTGREEN}4/17 Checking pods status${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Check pods status = kubectl get po -A${TXTNORMAL}"; echo ""; kubectl get po -A) >> output.log
echo -e "${TXTGREEN}5/17 Checking Deployments${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Check deployments = kubectl get deploy${TXTNORMAL}"; echo ""; kubectl get deploy) >> output.log
echo -e "${TXTGREEN}6/17 Checking Top pods${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Check Top Pods = kubectl top pods${TXTNORMAL}"; echo ""; kubectl top pods) >> output.log
echo -e "${TXTGREEN}7/17 Checking Top nodes${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Check Top Nodes = kubectl top nodes${TXTNORMAL}"; echo ""; kubectl top nodes) >> output.log
echo -e "${TXTGREEN}8/17 Describing Nodes${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Describe Nodes = kubectl describe nodes${TXTNORMAL}"; echo ""; kubectl describe nodes) >> output.log
echo -e "${TXTGREEN}9/17 Describing Redis pod${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Describe Redis = kubectl describe po priv-appliance-redis-master-0${TXTNORMAL}"; echo ""; kubectl describe po priv-appliance-redis-master-0) >> output.log
echo -e "${TXTGREEN}10/17 Checking common critical events${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Check common events = kubectl get events | egrep -i 'readiness|liveliness|oom'${TXTNORMAL}"; echo ""; kubectl get events | egrep -i 'readiness|liveliness|oom') >> output.log
echo -e "${TXTGREEN}11/17 Checking RAM memory${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Check RAM memory = free -g${TXTNORMAL}"; echo ""; free -g) >> output.log
echo -e "${TXTGREEN}12/17 Checking local disk space${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Check Disk space = df -ha${TXTNORMAL}"; echo ""; df -ha) >> output.log
echo -e "${TXTGREEN}13/17 Checking CPU cores${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Check CPU cores = lscpu${TXTNORMAL}"; echo ""; lscpu) >> output.log
echo -e "${TXTGREEN}14/17 Calculating '/' subfolders size${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}/ subfolders size = du -h -d 1 /${TXTNORMAL}"; echo ""; du -h -d 1 /) >> output.log
echo -e "${TXTGREEN}15/17 Calculating '/mnt' subfolders size${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}/mnt subfolders size = du -h -d 1 /mnt${TXTNORMAL}"; echo ""; du -h -d 1 /mnt) >> output.log
echo -e "${TXTGREEN}16/17 Calculating '/mnt/data' subfolders size${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}/mnt/data subfolders size = du -h -d 1 /mnt/data${TXTNORMAL}"; echo ""; du -h -d 1 /mnt/data) >> output.log
echo -e "${TXTGREEN}17/17 Describing Redis ConfigMap${TXTNORMAL}"
(echo ""; echo -e "${TXTGREEN}Describe Redis ConfigMap = kubectl describe cm priv-appliance-redis${TXTNORMAL}"; echo ""; kubectl describe cm priv-appliance-redis) >> output.log

show_help2() {
echo ""
echo -e "${TXTBOLD}${TXTBLUE}The process was completed and the output was written to the file.${TXTNORMAL}"
echo -e "${TXTBOLD}${TXTBLUE}Please attach the output.log file to the support ticket. Thank you.${TXTNORMAL}"
echo ""
}
show_help2