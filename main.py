from time import sleep
import json
import sys
import argparse
import getpass
from fabric import Connection
from pyVmomi import vim 
from tools.pchelper import get_obj
from tools.service_instance import connect

class PasswordPromptAction(argparse.Action):
    def __init__(self,
             option_strings,
             dest=None,
             nargs=0,
             default=None,
             required=False,
             type=None,
             metavar=None,
             help=None,
             values=None):
        super(PasswordPromptAction, self).__init__(
             option_strings=option_strings,
             dest=dest,
             nargs=nargs,
             default=default,
             required=required,
             metavar=metavar,
             type=type,
             help=help)

    def __call__(self, parser, args, values, option_string=None):
        print(self)
        print(parser)
        print(args)
        print(values)
        password = values
        if values is None:
            password = getpass.getpass(self.help+":")
        setattr(args, self.dest, password)

class vCenterArgs:
    def __init__(self,
             host=None,
             user=None,
             password=None,
             disable_ssl_verification=True,
             port=443):
             self.host=host
             self.user=user
             self.password=password
             self.disable_ssl_verification=True
             self.port=443

def get_vmk1_ip(host):
    for nic in host.config.network.vnic:
        if nic.device == "vmk1":
            return nic.spec.ip.ipAddress

def host_uplink_capture(host, esxiuser, esxipassword,uplink,srcip,dstip):
    c = None
    print("Connect to {ip}".format(ip=host))
    c = Connection(host=host,user=esxiuser,connect_kwargs={"password":esxipassword})
    #pcktcap-uw --uplink vmnicX --ip IP -c 10
    result = c.run("pktcap-uw --uplink {uplink} --ip {srcip} --ip {dstip} -c 10 --dir 2 -o - | tcpdump-uw -enr-".format(uplink=uplink , srcip=srcip, dstip=dstip),timeout=10,hide=True)
    c.run("kill -9 $(lsof |grep pktcap-uw |awk '{print $1}'| sort -u)", hide=True)
    c.close()
    c= None
    return result

def host_vm_switchport_vdr_capture(host, esxiuser, esxipassword, srcip,dstip):
    c = None
    print("Connect to {ip}".format(ip=host))
    c = Connection(host=host,user=esxiuser,connect_kwargs={"password":esxipassword})
    #result = c.run("nsxdp-cli vswitch instance list | grep vdr",hide=True)
    #switchportid = result.stdout.split()[1]
    #try:
    #    print("Switchport ID: {switchportid}".format(switchportid=switchportid))
    #    result = c.run("pktcap-uw -K --switchport {switchportid} -c 10 --ip {srcip} --ip {dstip} --dir 2 -o - | tcpdump-uw -enr -".format(switchportid=switchportid,srcip=srcip, dstip=dstip),timeout=10, hide=True)
    #    c.run("kill -9 $(lsof |grep pktcap-uw |awk '{print $1}'| sort -u)", hide=True)
    #    print(result.stdout)
    #    result = None
    #except:
    #    print("Timeout")
    try:
        result = c.run("nsxcli -c start capture interface vdrPort direction dual count 10 expression ip {dstip}".format(dstip=dstip),timeout=10)
        print(result.stdout)
    except:
        print("Timeout")
    c.close()
    return 0

def host_vm_switchport_capture(host, esxiuser, esxipassword, evm, srcip,dstip):
    c = None
    print("Connect to {ip}".format(ip=host))
    c = Connection(host=host,user=esxiuser,connect_kwargs={"password":esxipassword})
    result = c.run("esxcli network vm list | grep {vmname} | awk '{{ print $1 }}'".format(vmname=evm.name),hide=True)
    worldid = result.stdout.strip()
    print("World ID: {worldid}".format(worldid=worldid))
    result = c.run("esxcli network vm port list -w {worldid} | grep \ \ Port\ ID:  | awk '{{ print $3 }}'".format(worldid=worldid),hide=True)
    switchportid = result.stdout
    for switchport in switchportid.splitlines():
        try:
            print("Switchport ID: {switchportid}".format(switchportid=switchport.strip()))
            result = c.run("pktcap-uw -K --switchport {switchportid} -c 10 --ip {srcip} --ip {dstip} --dir 2 -o - | tcpdump-uw -enr -".format(switchportid=switchport.strip(),srcip=srcip, dstip=dstip),timeout=10, hide=True)
            print(result.stdout)
            result = None
        except:
            print("Timeout")
    c.close()
    return 0


def edge_interface_catpure_process_perrouter(c,data,srdr,srcip, dstip):
    print("Router Type: {router}".format(router=srdr))
    print("Checking Uplinks")
    for interface in data[srdr]['ports']:
        if interface['type'] == 'lif':
            if "TNT" in interface['name'] and interface['ptype'] == "uplink":
                print("Checking Interface {type}: {name} ifuuid: {ifuuid}".format(type=interface['ptype'],name=interface['name'],ifuuid=interface['ifuuid']))
                sleep(1)
                try:
                    result = c.run("del capture session 0",hide=True)
                except:
                    result = None
                sleep(1)
                c.run("set capture session 0 interface {intid} direction dual".format(intid=interface['ifuuid']),hide=True)
                sleep(1)
                try:
                    result = c.run("set capture session 0 count 10 expression host {srcip} and host {dstip}".format(srcip=srcip,dstip=dstip), timeout=10,hide=True)
                    print(result.stdout)
                except:
                    print("Timeout")
                result= None
                print("-------")
    results = None
    #this does not see any traffic.  should it???
    #print("Checking SR/DR Backplane ports")
    #for interface in data[srdr]['ports']:
    #    if interface['type'] == 'lif':
    #        if interface['ptype'] == "backplane":
    #            print("Checking Interface {type}: {name} ifuuid: {ifuuid}".format(type=interface['ptype'],name=interface['name'],ifuuid=interface['ifuuid']))
    #            sleep(1)
    #            try:
    #                result = c.run("del capture session 0",hide=True)
    #            except:
    #                result = None
    #            sleep(1)
    #            c.run("set capture session 0 interface {intid} direction dual".format(intid=interface['ifuuid']),hide=True)
    #            sleep(1)
    #            try:
    #                result = c.run("set capture session 0 count 10 expression host {srcip} and host {dstip}".format(srcip=srcip,dstip=dstip), timeout=10,hide=True)
    #                print(result.stdout)
    #            except Exception as e:
    #                print("Timeout")
    #                sleep(5)
    #            result= None
    #            print("-------")
    print("Checking Downlinks")
    result = None
    for interface in data[srdr]['ports']:
        if interface['type'] == 'lif':
            if interface['ptype'] == "downlink":
                print("Checking Interface {type}: {name} ifuuid: {ifuuid}".format(type=interface['ptype'],name=interface['name'],ifuuid=interface['ifuuid']))
                sleep(1)
                try:
                    result = c.run("del capture session 0",hide=True)
                except:
                    result = None
                sleep(1)
                c.run("set capture session 0 interface {intid} direction dual".format(intid=interface['ifuuid']),hide=True)
                sleep(1)
                try:
                    result = c.run("set capture session 0 count 10 expression host {srcip} and host {dstip}".format(srcip=srcip,dstip=dstip), timeout=10,hide=True)
                    print(result.stdout)
                except Exception as e:
                    print("Timeout")
                    sleep(5)
                result= None
                print("-------")
    print("-------")

def edge_interface_capture_process(c, data,srcip,dstip):
    for srdr in data:
        if srdr == "SERVICE_ROUTER_TIER0":
            edge_interface_catpure_process_perrouter(c,data,srdr,srcip,  dstip)
    for srdr in data:
        if srdr == "DISTRIBUTED_ROUTER_TIER0":
            edge_interface_catpure_process_perrouter(c,data,srdr,srcip,  dstip)
    for srdr in data:
        if srdr == "SERVICE_ROUTER_TIER1":
            edge_interface_catpure_process_perrouter(c,data,srdr,srcip,  dstip)
    for srdr in data:
        if srdr == "DISTRIBUTED_ROUTER_TIER1":
            edge_interface_catpure_process_perrouter(c,data,srdr,srcip, dstip)
    return 0

def edge_interface_capture(vm, nsxpassword, srcip, dstip):
    c = None
    print("Connect to {ip}".format(ip=vm.summary.guest.ipAddress))
    c = Connection(host=vm.summary.guest.ipAddress,user="admin",connect_kwargs={"password":nsxpassword})
    result = c.run("get logical-routers | json",hide=True)
    routers = json.loads(result.stdout)
    for router in routers:
        if "T0" in router['name'] and "SR" in router['name']:
            print("Checking Logical Router: {router}".format(router=router['name']))
            result = c.run("get logical-router {vrid} interfaces | json".format(vrid=router['uuid']),hide=True)
            data =json.loads(result.stdout)
            edge_interface_capture_process(c, data,srcip, dstip)
    for router in routers:
        if "T1" in router['name'] and "SR" in router['name']:
            print("Checking Logical Router: {router}".format(router=router['name']))
            result = c.run("get logical-router {vrid} interfaces | json".format(vrid=router['uuid']),hide=True)
            data =json.loads(result.stdout)
            edge_interface_capture_process(c, data, srcip, dstip)
    c.close()         
    return result

def edge_t1_firewall_check(vm, nsxpassword, srcip, dstip):
    c = None
    print("Connect to {ip}".format(ip=vm.summary.guest.ipAddress))
    c = Connection(host=vm.summary.guest.ipAddress,user="admin",connect_kwargs={"password":nsxpassword})
    result = c.run("get logical-routers | json",hide=True)
    routers = json.loads(result.stdout)
    for router in routers:
        if "T1" in router['name'] and "DR" in router['name']:
            print("Checking Logical Router: {router}".format(router=router['name']))
            result = c.run("get logical-router {vrid} interfaces | json".format(vrid=router['uuid']),hide=True)
            data =json.loads(result.stdout)
            for srdr in data:
                if srdr == "SERVICE_ROUTER_TIER1":
                    for interface in data[srdr]['ports']:
                        if interface['type'] == 'lif':
                            if "TNT" in interface['name'] and interface['ptype'] == "uplink":
                                print("Checking Interface {type}: {name} ifuuid: {ifuuid}".format(type=interface['ptype'],name=interface['name'],ifuuid=interface['ifuuid']))
                                sleep(1)
                                result = c.run("get logical-router interface {ifuuid} stats | json".format(ifuuid=interface['ifuuid']), hide=True)
                                stats = json.loads(result.stdout)
                                print("RX Firewall Drops: {fwdrops}".format(fwdrops=stats['stats']['rx_drop_firewall']))
                                rx_fw_drops_1 = int(stats['stats']['rx_drop_firewall'])
                                sleep(20)
                                result = c.run("get logical-router interface {ifuuid} stats | json".format(ifuuid=interface['ifuuid']), hide=True)
                                stats = json.loads(result.stdout)
                                print("RX Firewall Drops: {fwdrops}".format(fwdrops=stats['stats']['rx_drop_firewall']))
                                rx_fw_drops_2 = int(stats['stats']['rx_drop_firewall'])
                                if rx_fw_drops_2 > rx_fw_drops_1:
                                    print("!!!rx_fw_drops INCREASING!!!")
                                else:
                                    print("rx_fw_drops not increasing")
    c.close
    c = None
                                

                    
def main():
    parser = argparse.ArgumentParser(description="Command to verify NSX-T ingress packet flow")
    parser.add_argument('--srcip', type=str, help="Source IP address for ingress traffic", required=True)
    parser.add_argument('--dstVM', type=str, help="Destination VM (single interface VM only)", required=True)
    parser.add_argument('--vcenter', type=str, help="vCenter Server Hostname or IP", required=True)
    parser.add_argument('--vcenter_user', type=str, help="vCenter Server Username", required=True)
    #parser.add_argument('--vcenter_password', action=PasswordPromptAction, type=str, help="vCenter Server Password", required=True)
    parser.add_argument('--vcenter_password', type=str, help="vCenter Server Password", required=False)
    parser.add_argument('--esx_user', type=str, help="ESXi Username", required=True)
    #parser.add_argument('--esx_password', action=PasswordPromptAction, type=str, help="ESXi Password", required=True)
    parser.add_argument('--esx_password', type=str, help="ESXi Password", required=False)
    #parser.add_argument('--nsx_password', action=PasswordPromptAction, type=str, help="NSX Admin Password", required=True)
    parser.add_argument('--nsx_password', type=str, help="NSX Admin Password", required=False)
    args = parser.parse_args()
    if args.vcenter_password is None:
        args.vcenter_password = getpass.getpass("vCenter Password: ")
    if args.esx_password is None:
        args.esx_password = getpass.getpass("ESXi Password: ")
    if args.nsx_password is None:
        args.nsx_password = getpass.getpass("NSX Admin Password: ")
    
    vcenter_args = vCenterArgs(host=args.vcenter, user=args.vcenter_user, password=args.vcenter_password)
    si = connect(vcenter_args)
    dstvm = get_obj(si.RetrieveContent(), [vim.VirtualMachine], args.dstVM)
    print("Found VM: "+dstvm.name)
    print("VM IP: "+dstvm.summary.guest.ipAddress)
    dstvmhostip=get_vmk1_ip(dstvm.runtime.host)
    print("DstVM Host IP: "+dstvmhostip)
    mgtVMFolder = get_obj(si.RetrieveContent(),[vim.Folder],"MGMT-VM")
    evms = []
    for vm in mgtVMFolder.childEntity:
        if "EVM01" in vm.name:
            evm01=vm
            evms.append(vm)
        if "EVM02" in vm.name:
            evm02=vm
            evms.append(vm)
    print("Found EVM01: "+evm01.name)
    print("EVM01 IP: "+evm01.summary.guest.ipAddress)
    print("EVM01 Host IP: "+ get_vmk1_ip(evm01.runtime.host))
    print("Found EVM02: "+evm02.name)
    print("EVM02 IP: "+evm02.summary.guest.ipAddress)
    print("EVM02 Host IP: "+ get_vmk1_ip(evm02.runtime.host))
    print("Starting caputre for host uplinks")
    print("-------")
    for vm in evms:
        for uplink in ["vmnic0","vmnic3"]:
            print("Edge VM: {vm} Host: {host} Uplink: {uplink}".format(vm=vm.name, host = get_vmk1_ip(vm.runtime.host), uplink=uplink))
            try:
                result = host_uplink_capture(get_vmk1_ip(vm.runtime.host),args.esx_user, args.esx_password,uplink,args.srcip,dstvm.summary.guest.ipAddress)
                print(result.stdout)
            except:
                print("-------")
            print("-------")
    print("Check Switch Ports")
    print("--------")
    for vm in evms:
        print("Edge VM: {vm} Host: {host}".format(vm=vm.name,host=get_vmk1_ip(vm.runtime.host)))
        try:
            result = host_vm_switchport_capture(get_vmk1_ip(vm.runtime.host),args.esx_user, args.esx_password,vm,args.srcip,dstvm.summary.guest.ipAddress)
            print(result.stdout)
        except:
            print("-------")
        print("--------")
    print("Check Edges")

    for vm in evms:
        print("Edge VM: {vm} Host: {host}".format(vm=vm.name,host=get_vmk1_ip(vm.runtime.host)))
        result = edge_interface_capture(vm,args.nsx_password,args.srcip,dstvm.summary.guest.ipAddress)

    print("--------")
    print("Check T1 Firewall Drops")
    for vm in evms:
        print("Edge VM: {vm} Host: {host}".format(vm=vm.name,host=get_vmk1_ip(vm.runtime.host)))
        result = edge_t1_firewall_check(vm,args.nsx_password,args.srcip,dstvm.summary.guest.ipAddress)

    print("DST VM: {dstvm} Host: {host}".format(dstvm=dstvm.name, host=get_vmk1_ip(vm.runtime.host)))
    try:
        result = host_vm_switchport_capture(get_vmk1_ip(dstvm.runtime.host),args.esx_user, args.esx_password,dstvm,args.srcip,dstvm.summary.guest.ipAddress)
        print(result.stdout)
    except:
        print("-------")
    ###Does not produce expected results
    #print("Check vdrPort")
    #print("DST VM: {dstvm} Host: {host}".format(dstvm=dstvm.name, host=get_vmk1_ip(dstvm.runtime.host)))
    #try:
    #    result = host_vm_switchport_vdr_capture(get_vmk1_ip(dstvm.runtime.host),args.esx_user, args.esx_password,args.srcip,dstvm.summary.guest.ipAddress)
    #    print(result.stdout)
    #except:
    #    print("-------")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())