#!/bin/bash
#
# Goal: list all Critical and High vulnerabilities in a FPR
# requires : unzip, bc, xmllint (libxml2-utils) installed

############################################################
# Help                                                     #
############################################################
Help()
{
   # Display Help
   echo "Present the application name and the number of critical and high vulnerabilities."
   echo "found in the Fortify report file .fpr"
   echo
   echo "Syntax:  [h|filename.fpr]"
   echo "options:"
   echo "h     Print this Help."
   echo "f     filename.fpr - file to be analyzed."
   echo
}

############################################################
# Process the input options. Add options as needed.        #
############################################################
# Get the options
while getopts ":hf:" option; do
   case $option in
      h) # display Help
         Help
         exit;;
      f) # Enter a filename
	 filename=$OPTARG;;
      \?) # Invalid option
	 echo "Error: Invalid option"
	 Help
         exit;;
   esac
done
if [ $# -eq 0 ]; then
    echo "No arguments provided, try -h"
    exit 1
fi


if [ ! -f "$filename" ]; then
    echo "The file:$filename does not exist. try -h"
    exit 1;
fi


# Present Application Name
#app=`unzip -p $filename audit.fvdl`

data=$(unzip -p "$filename" audit.fvdl 2>/dev/null)
if [ $? -ne 0 ] || [ -z "$data" ]; then
  echo "Error: Failed to unzip 'audit.fvdl' from '$filename' or file is empty."
  exit 1
fi

app_name=$(xmllint --xpath 'string(//*[local-name()="BuildID"])' - <<< "$data" 2>/dev/null)
#echo "$app_name"

n_vulns=$(xmllint --xpath 'count(//*[local-name()="Vulnerability"])' - <<< "$data" 2>/dev/null)
echo "Found $n_vulns vulnerabilities"

RULES_DATA=$(xmllint --xpath '//*[local-name()="RuleInfo"]' - <<< "$data" 2>/dev/null)

declare -i vuln_critical=0;
declare -i vuln_high=0;
declare -i vuln_medium=0;
declare -i vuln_low=0;
declare -i vuln_unknown=0;

# Get vulnerabilities
readarray -t vulnerabilities < <(xmllint --xpath '//*[local-name()="Vulnerability"]' - <<< "$data" 2>/dev/null)

# Fix array (every tag is in a newline but we want the complete <Vulnerability>...</Vulnerability> in a single array position)
declare -a vulns
declare -i pos=0
for vuln in "${vulnerabilities[@]}"; do
  vulns[pos]+="$vuln"
  if [[ "$vuln" =~ "</Vulnerability>" ]]; then
    pos+=1
  fi
done


# Loop through each vulnerability stored in the array
for vuln in "${vulns[@]}"; do
    class_id=$(echo "$vuln" | xmllint --xpath 'string(//*[local-name()="ClassID"])' - 2>/dev/null)
    if [ -z "$class_id" ]; then
      continue
    fi
    
    confidence=$(echo "$vuln" | xmllint --xpath 'string(//*[local-name()="Confidence"])' - 2>/dev/null)

    # If no ClassID or Confidence, mark as Unknown and continue
    if [ -z "$confidence" ]; then
      vuln_unknown+=1;
      continue
    fi
    
    # Find the corresponding rule using ClassID
    rules=$(echo "$RULES_DATA" | xmllint --xpath "//*[local-name()='Rule'][@id='$class_id']" - 2>/dev/null)

    # If no rule is found, mark as Unknown and continue
    if [ -z "$rules" ]; then
      vuln_unknown+=1;
      continue
    fi
    
    # Extract values from the rule XML
    impact=$(echo "$rules" | xmllint --xpath 'string(//*[local-name()="Group"][@name="Impact"])' - 2>/dev/null)
    accuracy=$(echo "$rules" | xmllint --xpath 'string(//*[local-name()="Group"][@name="Accuracy"])' - 2>/dev/null)
    probability=$(echo "$rules" | xmllint --xpath 'string(//*[local-name()="Group"][@name="Probability"])' - 2>/dev/null)
    
    # Use bc for floating-point calculations
    # Handle empty values by defaulting to 0.0
    impact=${impact:-0.0}
    accuracy=${accuracy:-0.0}
    probability=${probability:-0.0}
    
    # Calculate likelihood
    likelihood=$(echo "scale=1; ($accuracy * $confidence * $probability) / 25" | bc)
    
    # Determine severity based on the Impact/Likelihood matrix    
    if [ $(echo "$impact >= 2.5 && $likelihood >= 2.5" | bc) -eq 1 ]; then
      vuln_critical+=1;
    elif [ $(echo "$impact >= 2.5 && $likelihood < 2.5" | bc) -eq 1 ]; then
      vuln_high+=1;
    elif [ $(echo "$impact < 2.5 && $likelihood >= 2.5" | bc) -eq 1 ]; then
      vuln_medium+=1;
    else
      vuln_low+=1;
    fi
done

#echo "The $app_name has $vuln_critical critical vulns and $vuln_high high, ones!"
echo "Critical: $vuln_critical"
echo "High: $vuln_high"
echo "Medium: $vuln_medium"
echo "Low: $vuln_low"

if [ $vuln_critical -gt 0 ] ||  [ $vuln_high -gt 0 ] 
   then
	   echo "Pipeline should break!"
	   exit 1;
   else
	   echo "Pipeline can go forward!"
	   exit 0;
fi
