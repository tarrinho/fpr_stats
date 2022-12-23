#!/bin/bash
#n_vulns=`xmllint --shell audit.xml <<EOF
#cd *
#cd *[5]
#ls
#EOF`
#echo $n_vulns | tr ' ' '\n' | grep -i vulnerability | wc -l | xargs

n_vulns=`xmllint --xpath "//*/*[local-name()='Vulnerabilities']" audit.xml | grep "<Vulnerability>" | wc -l | xargs`

# We now have the vulnerabilities references
declare -a vulns

for i in $(seq 1 $n_vulns); 
do
  vulns[$i]=`xmllint --xpath "//*/*[local-name()='Vulnerabilities']/*[$i]/*[local-name()='ClassInfo']/*[local-name()='ClassID']/text()" audit.xml`
  echo "${vulns[$i]}"
done


declare -a impact
declare -a probability
declare -a status_vuln

for i in $(seq 1 $n_vulns); 
do
  impact[$i]=`xmllint --xpath "//*/*[local-name()='RuleInfo']/*[name()='Rule' and @id='${vulns[$i]}']" audit.xml | grep -i "\"impact\"" | cut -d '>' -f 2 | cut -d '<' -f 1 `
  probability[$i]=`xmllint --xpath "//*/*[local-name()='RuleInfo']/*[name()='Rule' and @id='${vulns[$i]}']" audit.xml | grep -i "\"probability\"" | cut -d '>' -f 2 | cut -d '<' -f 1 `
  echo "impact ${impact[$i]} and probability ${probability[$i]}"
  
   if [ "$(echo "${impact[$i]} >= 2.5" | bc) " -eq 1 ] && [ "$(echo "${probability[$i]} >= 2.5" | bc)" -eq 1 ] 
   then
     status_vuln[$i]="Critical"
   elif [ "$(echo "${impact[$i]} >= 2.5" | bc) " -eq 1 ] && [ "$(echo "${probability[$i]} <= 2.5" | bc)" -eq 1 ]
   then
     status_vuln[$i]="High"
   elif [ "$(echo "${impact[$i]} <= 2.5" | bc)" -eq 1 ] && [ "$(echo "${probability[$i]} >= 2.5" | bc)" -eq 1 ]
   then
     status_vuln[$i]="Medium"
   else
     status_vuln[$i]="Low"
   fi
   echo ${status_vuln[$i]}
done



