# nsx-ingress-packetcapture
This repo is a script to automatically preform packet captures across the NSX infrastructure.
## Usage
`python main.py --srcip [SOURCE IP OF TRAFFIC] --dstVM [DESTINATION VM OF TRAFFIC] --vcenter [VCENTER HOSTNAME/IP] --vcenter_user [VCENTER USER] --esx_user [ESX USER] --vcenter_password [optinal VCENTER PASSWORD] --esx_password [optional ESX PASSWORD] --nsx_password [optional NSX PASSWORD]`

## How it works
The script will find all the componenets and then ssh into esx and the edge nodes to preform packet captures in this order:
1. ESXi vmnics for edge uplinks (hard coded to vmnic0 and vmnic3)
2. ESXi host switchports that the edge vms are connected to
3. Edge T0 SR Uplinks
4. Edge T0 DR Downlinks
5. Edge T1 SR Uplink
6. Edge T1 DR Downlink
7. Destination VM host switchport