#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Description:
    Take input of single ip address and analyze the system for IOC's to determine if the given
    IP has hits of IOC's. It is used for Live Response in a domain environment

    This script is designed to run only on WINDOWS

Requirements:

    Python 2.7 with the following modules

    1) win32 module (https://sourceforge.net/projects/pywin32/files/pywin32/Build%20221/pywin32-221.win32-py2.7.exe/download)

    2) wmi module: (http://timgolden.me.uk/python/wmi/index.html)

    3) active directory module: (http://timgolden.me.uk/python/active_directory.html)

    4) EnumerateMutex.exe, handle.exe, md5.exe

Credentials:
    The wmi and remote executions queries are all conducted with current context

Tested:
    Windows 7 / Python 2.7

Usage:
    ir.py <ip_address> [options]

    Options:
      --version    show program's version number and exit
      -h, --help   show this help message and exit
      -q, --quiet  execute the program silently
      -d, --dirs   scan directories

Examples:

    python ir.py 10.10.10.10

"""
from optparse import OptionParser
from datetime import datetime, date
import os, sys, socket, logging, re
import subprocess, active_directory
import win32com.client, win32security, signal
import pythoncom, threading, struct, getpass
import _winreg, wmi, win32wnet, shutil
import requests, json

__author__ = 'Sriram G'
__version__ = '1'
__license__ = 'GPLv3'
__datecreated__ = '01/jul/2013'
__dateupdated__ = '01/sep/2014'

"""
Global variables
"""
logger = logging.getLogger('windows-ir')
logger.setLevel(logging.DEBUG)
logging.basicConfig(format='[%(levelname)-7s] %(asctime)s | %(message)s', datefmt='%I:%M:%S %p') #%m/%d/%Y
remotebaselocation = "c:\\windows\\system32\\"
wmidomain = ""
wmiuser = ""
wmipass = ""
envDomain = os.environ.get("USERDOMAIN")
analyst = os.environ.get("USERNAME")
CaseRef = ""
dirInfo = False
isCopyComplete = False
allThreadsFinished = False
response = {} # store thread outputs
startTime = ""
"""
 Dictionary of Registry entries to be read on remote machine
 %s is used in the below string(s), it will be mapped with SID later on;
 if you add more of HKU, don't forget put %s
"""
HKU_RegistryKeys = {
    # Description:                      Registry Key
    "User specific Shell & User Init": r"HKU\%s\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "User specific Shell Folders": r"HKU\%s\Software\Microsoft\Windows\CurrentVersion\explorer\Shell Folders",
    "User specific Run Key - Persistence": r"HKU\%s\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "User specific RunOnce Key": r"HKU\%s\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "User specific Explorer mountpoints": r"HKU\%s\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\mountpoints2",
    "User Specific 64bit Startup Apps": r"HKU\%s\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "User Specific 64bit Runonce Entries": r"HKU\%s\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Runonce",
    "User Specific 64 Run Entry": r"HKU\%s\SOFTWARE\wow6432node\Microsoft\Windows\\CurrentVersion\Run",
    "User specific Mapped Drives": r"HKU\%s\Software\Microsoft\Windows\CurrentVersion\explorer\Map Network Drive MRU",
    "User specific softwares": r"HKU\%s\SOFTWARE"
}
HKLM_RegistryKeys = {
    # Description:                       Registry Key
    "Shell & User Init": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "Shell Folders": r"HKLM\Software\Microsoft\Windows\CurrentVersion\explorer\Shell Folders",
    "Approved Shell extensions": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
    "Configured EXE File Shell Command": r"HKLM\SOFTWARE\Classes\exefile\shell\open\command",
    "Shell Commands": r"HKLM\SOFTWARE\Classes\HTTP\shell\open\command",
    "HKLM Run Entry": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "RunOnce Entry": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM Services": r"HKLM\SYSTEM\CurrentControlSet\Services",
    "64bit Run Entries": r"HKLM\SOFTWARE\wow6432node\Microsoft\Windows\CurrentVersion\Run",
    "64bit Startup Applications": r"HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "64bit RunOnce": r"HKLM\SOFTWARE\wow6432node\Microsoft\Windows\CurrentVersion\Runonce",
    "LSA packages loaded": r"HKLM\system\currentcontrolset\control\lsa",
    "Firewall Policies": r"HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\AuthorizedApplications\List"
}
other_RegistryKeys = {
    # Description:                      Registry Key
    "Installed Browsers": r"HKLM\SOFTWARE\Clients\StartMenuInternet",
    "Typed URLS": r"HKU\%s\Software\Microsoft\Internet Explorer\TypedUrls",
    "BHO": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
    "64bit BHO": r"HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
    "User specific IE extensions": r"HKU\%s\Software\Microsoft\Internet Explorer\Extensions",
    "IE Extensions": r"HKLM\Software\Microsoft\Internet Explorer\Extensions",
    "64bit IE Extensions": r"HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions",
    "Internet Settings": r"HKU\%s\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
    "Internet Trusted Domains": r"HKU\%s\SOFTWARE\Microsoft\Windows\CurrentVersion\InternetSettings\ZoneMap\EscDomains",
    "UAC Group policy settings": r"HKLM\Software\Microsoft\Windows\CurrentVersion\policies\system",
    "Security center SVC values": r"HKLM\software\microsoft\security center\svc",
    "Programs Executed By Session Manager": r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager",
    "App Path Keys": r"HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths",
    "Active Setup Installs": r"'HKLM\Software\Microsoft\Active Setup\Installed Components",
    "Run MRU Keys": r"HKU\%s\Software\Microsoft\Windows\CurrentVersion\explorer\RunMru",
    "Start Menu": r"HKLM\Software\Microsoft\Windows\CurrentVersion\explorer\Startmenu",
    "USB Devices": r"HKLM\system\currentcontrolset\enum\usbstor"
}

"""
useful misc commands that can be
executed on remote machine
uses: PSEXEC -s
"""
remote_commands = {
    # description:              command
    "Firewall Policy": r"netsh firewall show config",
    "Hosts file": r"cmd /c type c:\windows\system32\drivers\etc\hosts",
    "Users directory": r"cmd /c dir /a c:\users",
    "Audit Policy": r"auditpol /get /category:*"
}

"""
directory requirements
"""
XP_Dirs_Lookup = {
    # descirption           command (%s is mapped with %USERPROFILE%)
    "User Profile Directory": r"cmd /c dir /a %s",
    "User Profile Temp": r"cmd /c dir /a /s %s\local settings\temp",
    "User AppData Directory": r"cmd /c dir /a %s\local settings\application data"
}
SEVENPLUS_Dirs_Lookup = {
    # descirption           command (%s is mapped with %USERPROFILE%)
    "Appdata Roaming": r"cmd /c dir /a %s\appdata\roaming",
    "Windows Program Data": r"cmd /c dir /a c:\programdata",
    "Appdata Local Temp": r"cmd /c dir /a /s %s\appdata\local\temp"
}
WIN_Dirs_Lookup = {
    # description   command (%s is mapped with %WINDIR%)
    "Windows Temp": r"cmd /c dir /a /s %s\temp",
    "Windows Prefetch": r"cmd /c dir /a %s\Prefetch",
    "C:\ Hidden files": "cmd /c dir /a:h c:\\"
}


"""
strRand is a regular expression string to match for
random characters based on min 4 constants found in string
"""
strRandReg = r"(AppData\\Local\\|AppData\\Roaming\\|\%AppData\%\\|\%LOCALAPPDATA\%\\)[0-9zrtypqsdfghjklmwxcvbnZRTYPQSDFGHJKLMWXCVBN]{4,}}"
netstat_regex = "(\\s+TCP\\s+\\d+\\.\\d+\\.\\d+\\.\\d+\\:\\d+\\s+)(\\d+\\.\\d+\\.\\d+\\.\\d+)\\:(\\d+)" # should return 3 groups


def is_valid_ip(ip):
    """
    validates the given IP addresses
    ip v4 or ipv6 can be passed
    returns: True if IP detected or False (bool)
    """
    def is_valid_ipv4(ip):
        """
        validates IPv4 addresses.
        """
        pattern = re.compile(r"""
            ^
            (?:
              # Dotted variants:
              (?:
                # Decimal 1-255 (no leading 0's)
                [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
              |
                0x0*[0-9a-f]{1,2}  # Hexadecimal 0x0 - 0xFF (possible leading 0's)
              |
                0+[1-3]?[0-7]{0,2} # Octal 0 - 0377 (possible leading 0's)
              )
              (?:                  # Repeat 0-3 times, separated by a dot
                \.
                (?:
                  [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
                |
                  0x0*[0-9a-f]{1,2}
                |
                  0+[1-3]?[0-7]{0,2}
                )
              ){0,3}
            |
              0x0*[0-9a-f]{1,8}    # Hexadecimal notation, 0x0 - 0xffffffff
            |
              0+[0-3]?[0-7]{0,10}  # Octal notation, 0 - 037777777777
            |
              # Decimal notation, 1-4294967295:
              429496729[0-5]|42949672[0-8]\d|4294967[01]\d\d|429496[0-6]\d{3}|
              42949[0-5]\d{4}|4294[0-8]\d{5}|429[0-3]\d{6}|42[0-8]\d{7}|
              4[01]\d{8}|[1-3]\d{0,9}|[4-9]\d{0,8}
            )
            $
        """, re.VERBOSE | re.IGNORECASE)
        return pattern.match(ip) is not None

    def is_valid_ipv6(ip):
        """
        validates IPv6 addresses.
        """
        pattern = re.compile(r"""
            ^
            \s*                         # Leading whitespace
            (?!.*::.*::)                # Only a single wildcard allowed
            (?:(?!:)|:(?=:))            # Colon if it would be part of a wildcard
            (?:                         # Repeat 6 times:
                [0-9a-f]{0,4}           #   A group of at most four hexadecimal digits
                (?:(?<=::)|(?<!::):)    #   Colon unless preceded by wildcard
            ){6}                        #
            (?:                         # Either
                [0-9a-f]{0,4}           #   Another group
                (?:(?<=::)|(?<!::):)    #   Colon unless preceded by wildcard
                [0-9a-f]{0,4}           #   Last group
                (?: (?<=::)             #   Colon iff preceded by exactly one colon
                 |  (?<!:)              #
                 |  (?<=:) (?<!::) :    #
                 )                      # OR
             |                          #   A v4 address with NO leading zeros
                (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)
                (?: \.
                    (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)
                ){3}
            )
            \s*                         # Trailing whitespace
            $
        """, re.VERBOSE | re.IGNORECASE | re.DOTALL)
        return pattern.match(ip) is not None


    return is_valid_ipv4(ip) or is_valid_ipv6(ip)

def signed_to_unsigned(signed):
    """
    convert signed to unsigned
    """
    unsigned, = struct.unpack("L", struct.pack("l", signed))
    str_unsigned = str("%08X" % (unsigned))
    return str_unsigned

def of(filename):
    """
    check to see if given file exists, if it does, return
    incremented file name
    returns: as file name format (as string)
    """
    _of = ""
    files = [f for f in os.listdir('.') if re.match(filename,f)]
    if files:
        _of = filename + "_%02d.txt" % (len(files)+1)
    else:
        _of = filename + "_01.txt"

    return _of

def to_wmi_time(year=None, month=None, day=None, hours=None, minutes=None, seconds=None, microseconds=None, timezone=None):
    """
    convert human readable time to WMI time
    """
    def str_or_stars(i, length):
        if i is None:
            return "*" * length
        else:
            return str(i).rjust(length, "0")

    wmi_time = ""
    wmi_time += str_or_stars(year, 4)
    wmi_time += str_or_stars(month, 2)
    wmi_time += str_or_stars(day, 2)
    wmi_time += str_or_stars(hours, 2)
    wmi_time += str_or_stars(minutes, 2)
    wmi_time += str_or_stars(seconds, 2)
    wmi_time += "."
    wmi_time += str_or_stars(microseconds, 6)
    wmi_time += "+"
    wmi_time += str_or_stars(timezone, 3)

    return wmi_time

def from_wmi_time(wmi_time):
    """
    convert WMI time to human readable time
    """
    def int_or_none (s, start, end):
        try:
            return int(s[start:end])
        except ValueError:
            return None

    year = int_or_none(wmi_time, 0, 4)
    month = int_or_none(wmi_time, 4, 6)
    day = int_or_none(wmi_time, 6, 8)
    hours = int_or_none(wmi_time, 8, 10)
    minutes = int_or_none(wmi_time, 10, 12)
    seconds = int_or_none(wmi_time, 12, 14)
    microseconds = int_or_none(wmi_time, 15, 21)
    timezone = wmi_time[22:]
    if timezone == "***":
        timezone = None

    strDt = "%s/%s/%s %s:%s %s" % (year,month,day,hours,minutes,timezone)
    return str(strDt)
    #return year, month, day, hours, minutes, seconds, microseconds, timezone

def bytes2human(n):
    """
    convert bytes to human readable
    """
    symbols = ('K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y')
    prefix = {}
    for i, s in enumerate(symbols):
        prefix[s] = 1 << (i+1)*10
    for s in reversed(symbols):
        if n >= prefix[s]:
            value = float(n) / prefix[s]
            return '%.1f%s' % (value, s)
    return "%sB" % n


def is_ip4_in_net(ip,cdir):
    """
    check to see if a ipv4 address falls in a given network space
    input: ipaddress to check (10.120.10.1), network space (10.0.0.0/8)
    returns: true of false
    """
    ipaddr = struct.unpack('<L', socket.inet_aton(ip))[0]
    net, bits = cdir.split('/')
    netaddr = struct.unpack('<L', socket.inet_aton(net))[0]
    netmask = ((1L << int(bits)) - 1)
    return ipaddr & netmask == netaddr & netmask


def isPrivateIP(ip):
    """
    check if a given IP is in private ip space
    returns: true or false
    """
    is_private = False
    PrivateIPSpace = ["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/24","0.0.0.0/24"]
    for net in PrivateIPSpace:
        is_private = is_ip4_in_net(ip,net)
        if is_private:
            return is_private
        else:
            is_private = False

    return is_private


def ip2loc(ip):
    """
    returns: country/asn/isp data of a given ip
    """
    details = ""
    UA = "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36"
    api_url = "http://www.telize.com/geoip/%s" % ip
    headers = {'User-Agent': UA}
    try:
        response = requests.get(api_url, headers=headers)
        json_data = json.loads(response.text)
    except ValueError:
        details=""

    try: details= "COUNTRY: " + json.dumps(json_data["country"]).replace('"',"").strip()
    except KeyError: details= 'COUNTRY: N/A'
    try: details+= ", ISP: " + json.dumps(json_data["isp"]).replace('"',"").strip()
    except KeyError: details+= ', ISP: N/A'
    try: details+= ", ASN: " + json.dumps(json_data["asn"]).replace('"',"").strip()
    except KeyError: details+= ', ASN: N/A'

    return details


def run_cmd(command):
    logger.debug("cmd: %s" % command)
    clean_output = []
    p = subprocess.Popen(command,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    for line in p.stdout.readlines():
        clean_output.append(line.rstrip(os.linesep))
    return clean_output
    #return iter(p.stdout.readline, b'')


def touch(fn, contents, append=False):
    """
    generic function to write to a file with
    given contents
    returns: none
    """
    mode = ("a" if append else "w")
    f = open(fn, mode)
    f.write(contents)
    f.close()

def rm(fn):
    """
    generic function to remove a file
    returns: none
    """
    os.remove(fn)

def tab_print(content):
    """
    returns tabbed  output.
    """
    tabbed_output = ""
    tabbed_output += (120*'-')
    for row in content:
        row = [str(e) for e in row]
        tabbed_output += ('\t'.join(row))
    tabbed_output += (120*'-')

    return tabbed_output

def readableTimeZone(strDT):
    wmi_dt = str(strDT)
    clock, tz = re.split("[-+]+", wmi_dt)
    #convert the CurrentTimeZone to readable TimeZone format and return it
    a = int(tz)/60
    r = int(tz) % 60
    return "%s%02d:%02d" % ("+" if "+" in wmi_dt else "-", a, r)


def execWQL(wmiObj, wql):
    """
    execute WMI Query language Statement
    returns: result set
    """
    return wmiObj.query(wql)


def copy2(ip, user=None, pwd=None):
    """
    copies specified files to remote host to collect artifacts
    """
    logger.debug("copy2 on %s" % ip)
    def covert_unc(host, path):
        """ Convert a file path on a host to a UNC path."""
        return ''.join(['\\\\', host, '\\', path.replace(':', '$')])

    def _connect2(host, username, password):
        unc = ''.join(['\\\\', host])
        try:
            win32wnet.WNetAddConnection2(0, None, unc, None, username, password)
        except Exception, err:
            if isinstance(err, win32wnet.error):
                # Disconnect previous connections if detected, and reconnect.
                if err[0] == 1219:
                    win32wnet.WNetCancelConnection2(unc, 0, 0)
                    return _connect2(host, username, password)
            raise err

    def _disconnect(host):
        unc = ''.join(['\\\\', host])
        try:
            win32wnet.WNetCancelConnection2(unc, 0, 0)
        except Exception, err:
            logger.error(err)

    cpDone = False

    dest = covert_unc(ip, remotebaselocation)
    if not dest[len(dest) - 1] == '\\': dest = ''.join([dest, '\\'])
    files = ["EnumerateMutex.exe","autorunsc.exe","handle.exe", "md5.exe"]
    _connect2(ip, user, pwd)

    for file in files:
        try:
            shutil.copy(file, dest)
            cpDone = True
        except IOError, err:
            cpDone = False
            logger.error(err)

    logger.debug("copy2 thread finished")
    isCopyComplete = cpDone
    _disconnect(ip)


def netstat(ip):
    """
    execute netstat on remote machine
    returns: netstat output
    """
    o = {}
    cmd = r"psexec -s \\%s netstat -ano" % ip
    output_data = run_cmd(cmd)
    output_data = output_data[5:-2]
    output_data[0] = (120*'-')

    o['netstat'] = output_data

    logger.debug("<   finished netstat thread>")
    return o


def dnscache(ip):
    """
    execute netstat on remote machine
    returns: netstat output
    """
    o = {}
    cmd = r"psexec -s \\%s ipconfig /displaydns" % ip
    output_data = run_cmd(cmd)
    output_data = output_data[5:-2]
    output_data[0] = (120*'-')
    output_data[1] = 'DNS CACHE Information'

    o['dnscache'] = output_data

    logger.debug("<   finished dnscache thread>")
    return o


def mutexes(ip):
    """
    execute EnumerateMutex on remote machine
    returns: mutex output
    """
    o = {}
    output_data = ""
    cmd = r"psexec -s \\%s EnumerateMutex.exe" % ip
    output_data = run_cmd(cmd)
    output_data = output_data[3:-2]
    output_data[0] = (120*'-')
    output_data[1] = "Mutexes present in this system"

    o['mutex'] = output_data

    logger.debug("<   finished mutex thread>")
    return o


def handles(ip):
    """
    execute handle on remote machine
    returns: handle output
    """
    o = {}
    output_data = ""
    cmd = r"psexec -s \\%s handle.exe -u /accepteula" % ip
    output_data = run_cmd(cmd)
    output_data = output_data[9:-2]
    output_data[0] = (120*'-')
    output_data[1] = "Open Handles"

    o['handles'] = output_data

    logger.debug("<   finished handles thread>")
    return o


def autorunsc(ip):
    """
    execute autorunsc on remote machine
    returns: autorunsc output
    """
    o = {}
    output_data = ""
    cmd = r"psexec -s \\%s autorunsc.exe -a /accepteula" % ip
    output_data = run_cmd(cmd)
    output_data = output_data[9:-2]
    output_data[0] = (120*'-')
    output_data[1] = "Autoruns"

    o['autorunsc'] = output_data

    logger.debug("<   finished autorunsc thread>")
    return o


def misc_cmds(ip):
    """
    execute misc remote commands on the workstation
    returns: dict output of the commands
    """
    o = {}
    t = []
    t.append(120*'-')
    output_data = ""
    for desc, cmd in remote_commands.items():
        t.append(30*'-')
        t.append(desc)
        q = r"psexec -s \\%s %s" % (ip,cmd)
        output_data = run_cmd(q)
        output_data = output_data[4:-2]
        t.append('\n'.join(output_data))

    t.pop(1)
    o['misccmds'] = t

    logger.debug("<   finished misc cmds thread>")
    return o


def dirwalk(ip, userprofile, ostype="7", windir=r"c:\windows"):
    """
    get directory contents of the remote workstation
    returns: dict output of directory contents
    """
    o = {}
    t = []
    output_data = ""
    t.append(120*'-')
    """
    1. Get Windows Directory Information
    """
    for desc, cmd in WIN_Dirs_Lookup.items():
        t.append(30*'-')
        t.append(desc)
        try:
            cmd = cmd % str(windir)
        except TypeError:
            cmd = cmd
        q = r"psexec -s \\%s %s" % (ip,cmd)
        output_data = run_cmd(q)
        output_data = output_data[4:-2]
        t.append('\n'.join(output_data))
    """
    2. Get user related specific directories
       check to see if we have XP os or 7+ OS
    """
    if "XP" in str(ostype):
        # XP related dirs
        for desc, cmd in XP_Dirs_Lookup.items():
            t.append(30*'-')
            t.append(desc)
            try:
                cmd = cmd % str(userprofile)
            except TypeError:
                cmd = cmd
            q = r"psexec -s \\%s %s" % (ip,cmd)
            output_data = run_cmd(q)
            output_data = output_data[4:-2]
            t.append('\n'.join(output_data))
    else:
        # 7+ related dirs
        for desc, cmd in SEVENPLUS_Dirs_Lookup.items():
            t.append(30*'-')
            t.append(desc)
            try:
                cmd = cmd % str(userprofile)
            except TypeError:
                cmd = cmd
            q = r"psexec -s \\%s %s" % (ip,cmd)
            output_data = run_cmd(q)
            output_data = output_data[4:-2]
            t.append('\n'.join(output_data))

    t.pop(1)
    o['dirs'] = t

    logger.debug("<   finished dirwalk thread>")
    return o

def show_startup(ip):
    """
    get windows startup information
    returns: windows startup commands
    """
    wmiObj=wmi.WMI(ip)
    o = {}
    output_data = []
    output_data.append((120*'-'))
    output_data.append("Startup items:")
    try:
        for s in wmiObj.Win32_StartupCommand ():
            output_data.append("[%s]\t%s\t<%s>" % (s.Location, s.Caption, s.Command))
    except Exception, err:
        logger.error(err)

    o['startup'] = output_data
    logger.debug("<  startup info thread finished>")
    del wmiObj
    return o


def schtasks(ip):
    """
    get windows scheduled information
    returns: windows scheduled tasks
    """
    wmiObj=win32com.client.Dispatch("WbemScripting.SWbemLocator")
    wmiSvc = wmiObj.ConnectServer(ip,"root\cimv2")
    o = {}
    output_data = []
    output_data.append((120*'-'))
    output_data.append("Scheduled jobs:")
    output_data.append("%10s\t%-20s\t%-30s\t%-50s\t%-50s"%("Job Id","Command","Install Date","Name","Owner"))
    try:
        sctasks =  wmiSvc.ExecQuery("Select * from Win32_ScheduledJob")
        for s in sctasks:
            output_data.append("%10d\t%-20s\t%-30s\t%-50s\t%-50s" % (s.JobId, s.Command, s.InstallDate,s.Name,s.Owner))
    except Exception, err:
        logger.error(err)

    o['schtasks'] = output_data
    logger.debug("<  scheduled tasks info thread finished>")
    del wmiObj
    return o


def getNTlogs(ip,_timeframe=1):
    """
    get Event logs of security, system
    returns: dict of event logs
    """
    import datetime
    o = {}
    t = []
    t.append(120*'-')
    t.append("NT Event Logs - past %d %s"%(_timeframe,('days' if _timeframe>1 else 'day')))
    timeframe = datetime.date.today () - datetime.timedelta (_timeframe)
    wmi_timeframe = wmi.from_time (*timeframe.timetuple ()[:-1])

    """
    NT System Logs
    """
    q = "SELECT * FROM Win32_NTLogEvent \
        WHERE (EventType = 1 OR EventType = 2) AND (Logfile = 'System') \
        AND TimeGenerated >= '%s'" % wmi_timeframe
    t.append("%-10s\t%20s\t%-50s\t%-30s\t%-20s\t%s" %("Event","Time","Message","Source","Event ID","Type"))
    wmiObj = wmi.WMI (ip)
    for event in wmiObj.query (q):
        t.append(30*'-')
        t.append("%-10s\t%20s\t%-50s\t%-30s\t%-20s\t%s" %
                     (str(event.LogFile), str(from_wmi_time(event.TimeGenerated)),str(event.Message),
                     str(event.SourceName),str(event.EventCode), str(event.Type))
            )
    """
    NT Security Log files
    """
    q = "SELECT * FROM Win32_NTLogEvent \
        WHERE (EventType = 5) AND (Logfile = 'Security') \
        AND TimeGenerated >= '%s'" % wmi_timeframe
    wmiObj = wmi.WMI (ip)
    for event in wmiObj.query (q):
        t.append(30*'-')
        t.append("%-10s\t%20s\t%-50s\t%-30s\t%-20s\t%s" %
                     (str(event.LogFile), str(from_wmi_time(event.TimeGenerated)),str(event.Message),
                     str(event.SourceName),str(event.EventCode), str(event.Type))
            )

    o['ntlogs'] = t
    logger.debug("<    getting of NT Event Logs thread finished>")
    return o


def getUserInfo(username):
        userEmail = ""
        userCountry = ""
        userDept = ""
        userFullName = ""
        userJobTitle = ""
        userManager = ""
        userMobNo = ""
        userTelNo= ""
        userDept = ""
        userTZ = ""
        userLocation = ""
        user_details = {}
        try:
            for user in active_directory.search ("objectCategory='Person'","sAMAccountName='"+username+"'"):
                userFullName = user.displayName
                userEmail = user.mail
                try:
                    userManager = user.manager
                    if "CN=" in userManager:
                        userManager = userManager.split(",OU=",1)[0][3:].replace('\\','')
                        #userManager = re.search('(CN=\S+\\\,\s+\S+)',userManager).group(0)
                except ValueError:
                    break
                try:
                    userJobTitle = user.title
                except ValueError:
                    break
                try:
                    userDept = user.department
                except ValueError:
                    break
                try:
                    userTelNo = user.telephoneNumber
                except ValueError:
                    break
                try:
                    userMobNo = user.mobile
                except ValueError:
                    break
                try:
                    userCountry = user.co
                    if (userCountry=="None"):
                        userCountry = user.c
                except ValueError:
                    break
                try:
                    userLocation = user.physicalDeliveryOfficeName
                except ValueError:
                    break
        finally:
            o = []
            o.append(120*'-')
            o.append("User Details:")
            o.append(14*'=')
            o.append("User:%s\\%s" % (envDomain,username))
            o.append("Name: %s\t\tReports to: %s" % (userFullName,userManager))
            o.append("Job Title: %s\tDept: %s" % (userJobTitle,userDept))
            o.append("Phone(s): %s / %s\tEmail: %s" % (userTelNo,userMobNo, userEmail))
            o.append("Location: %s\tCountry: %s" % (userLocation,userCountry))
            o.append("Time Zone: %s" % userTZ)
            user_details['userinfo'] = o
            logger.debug("< finished collecting user information>")

        return user_details


def services(ip):
    """
    get list of services in the workstation
    returns: dict of services
    """
    wmiObj = wmi.WMI(ip)
    r = []
    s = []
    services = {}
    r.append(120*'-')
    r.append("All Services")
    r.append("%7s\t%50s\t%-80s\t%-15s"%("PID","Name","Path","State"))
    for svcs in wmiObj.Win32_Service():
        if svcs.State in "Running":
            r.append("%7d\t%50s\t%-80s\t%-15s" % (svcs.ProcessId,svcs.DisplayName,svcs.PathName,svcs.State))
        else:
            s.append("%7d\t%50s\t%-80s\t%-15s" % (svcs.ProcessId,svcs.DisplayName,svcs.PathName,svcs.State))
    r += s
    services['services'] = r
    logger.debug("<   finished getting services information>")
    return services


def get_reg_entries(ip, sid):
    """
    query for HKLM/HKU registry entries
    registry entry keys to be queried are stored in global variables
    fiddle with them to add/modify/remove
    returns: dict of reg entries values
    """
    reg_vals = {}
    o = []
    o.append(120*'-')
    q = ""

    """
    1. Query HKU Registry items
    """
    for desc, regkey in HKU_RegistryKeys.items():
        o.append(30*'-')
        o.append(desc)
        result = run_cmd(r'reg query "\\%s\%s"' % (ip,regkey%sid))
        o.append('\n'.join(result))
    """
    2. Query HKLM Registry items
    """
    for desc, regkey in HKLM_RegistryKeys.items():
        o.append(30*'-')
        o.append(desc)
        result = run_cmd(r'reg query "\\%s\%s"' % (ip,regkey))
        o.append('\n'.join(result))
    """
    3. Query Misc Registry items
    """
    for desc, regkey in other_RegistryKeys.items():
        o.append(30*'-')
        o.append(desc)
        # check to see if we have a HKU Key
        if regkey.lower().startswith('hku',0):
            # HKU Key, lets put the SID too with the key
            q = regkey % sid
            q = r'reg query "\\%s\%s"' %(ip, q) # regkey%sid
        else:
            # HKLM Key
            q = r'reg query "\\%s\%s"' % (ip,regkey)

        result = run_cmd(q)
        o.append('\n'.join(result))

    o.pop(1) # cleaning extra dashes
    reg_vals['regs'] = o
    logger.debug("<   finished getting registry entries>")
    return reg_vals

def tasklist(ip):
    """
    get the tasklist info (running processes) of remote machine
    reutrns: dict of running processes
    """
    wmiObj = wmi.WMI(ip)
    o = []
    proc = {}
    o.append(120*'-')
    o.append("%-5s\t%-5s\t%-24s\t%-20s\t%-30s\t%s" % ("PID","Parent","Owner", "Start Date","Image name","Executable Path"))
    processTree = {}
    for procs in wmiObj.Win32_Process():
        if procs.ParentProcessId not in processTree.keys():
            #new parent process id
            processTree.update({ procs.ParentProcessId : [procs.ProcessId] })
        else:
            #parent process id is already in there
            processTree[procs.ParentProcessId].append(procs.ProcessId)
        owner = ""
        try:
            owner = procs.GetOwner()
            if owner[0] != None:
                owner = "%s\\%s" %(owner[0],owner[2])
            else:
                owner = 'None'
        except Exception, err:
            logger.error("exception at determinig owner in tasklist process: %s"%err)
        o.append("%-5d\t%-5d\t%-24s\t%-20s\t%-30s\t%s" % (procs.ProcessId, procs.ParentProcessId,owner,
                        from_wmi_time(procs.CreationDate) if procs.CreationDate else "None", procs.Name, procs.ExecutablePath))

    proc['tasklist'] = o
    logger.debug("<   finished getting tasklist info>")
    return proc


def getDisks(ip):
    """
    Get Disk partitions & disk shares
    returns: dict of diskparts and shares
    """
    wmiObj = wmi.WMI(ip)
    disks = {}
    o = []
    #try:
        #get disk partitions
    o.append(120*'-')
    o.append("Disk partitions:")
    try:
        for phyDisk in wmiObj.Win32_DiskDrive():
            for parted in phyDisk.associators("Win32_DiskDriveToDiskPartition"):
                for logicalDisk in parted.associators("Win32_LogicalDiskToPartition"):
                        o.append("%s(%s, Vol SN:%s) on %s with %s free out of %s total space." %
                            (logicalDisk.Caption,logicalDisk.FileSystem,logicalDisk.VolumeSerialNumber,phyDisk.Caption,
                             bytes2human(long(logicalDisk.FreeSpace)),bytes2human(long(logicalDisk.Size))))
    except AttributeError, err:
        logger.error("AttributeError: %s" % err)

    o.append("Disk shares:")
    for share in wmiObj.Win32_Share ():
        o.append("%s\t\t<%s>" % (share.Name, share.Path))

    disks['diskpart'] = o
    #except AttributeError, err:
    #    logger.error("__%s" % err)
    #finally:
    #    logger.debug("<    getting disk info finished>")
    del wmiObj
    return disks


def getUserProfileDir(strUsername,strSID,_ip):
    userProfileDir = ""
    regEntry = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\%s" % strSID
    c = wmi.WMI(_ip, namespace="DEFAULT").StdRegProv
    result,names,type = c.EnumValues(
             hDefKey = _winreg.HKEY_LOCAL_MACHINE,
            sSubKeyName = regEntry,
    )
    for n in range(0,len(names)):
        res,val = c.GetStringValue(
                hDefKey = _winreg.HKEY_LOCAL_MACHINE,
                sSubKeyName = regEntry,
                sValueName = "ProfileImagePath"
        )
        if strUsername in val: userProfileDir=val

    return userProfileDir


def getSysuptime(wmiObj):
    LastBootUpTime = ""
    CurrentTime = ""

    for u in wmiObj.Win32_OperatingSystem():
        LastBootUpTime = u.LastBootUpTime
        CurrentTime = u.LocalDateTime

    cT = wmi.to_time(CurrentTime)
    cTobj= datetime(*cT[0:6])
    Lt = wmi.to_time(LastBootUpTime)
    Ltobj =  datetime(*Lt[0:6])
    secs_up = (cTobj - Ltobj).total_seconds()

    #secs_up = int([uptime.SystemUpTime for uptime in c.Win32_PerfFormattedData_PerfOS_System()][0])
    mins, secs = divmod(secs_up,60)
    hours, mins = divmod(mins,60)
    days, hours = divmod(hours,24)
    uptime = "%.0fdays and %.0fhours, %.0fminutes, %.0fseconds" % (days,hours,mins,secs)
    return uptime

class _tworker(threading.Thread):
    """
    threading class for certain functions that
    returns value. can be used with functions that don't return value as well
    """
    def __init__(self, *args, **kwargs):
        super(_tworker, self).__init__(*args, **kwargs)

        self._return = None

    def run(self):
        pythoncom.CoInitialize()
        if self._Thread__target is not None:
            self._return = self._Thread__target(*self._Thread__args, **self._Thread__kwargs)
        pythoncom.CoUninitialize()

    def join(self, *args, **kwargs):
        super(_tworker, self).join(*args, **kwargs)

        return self._return

def main():
    """
    main function
    """
    threads = []
    global response
    wmiObj = ""
    dstHost = ""
    userprofile_dir = ""
    basicinfo = []
    log_timeframe = 1
    fo = [] # list to store output which will finally get written to file
    parser = OptionParser(usage="usage: %prog <ip_address|file> [options] ", version="%prog v1")
    parser.add_option("-q","--quiet",action="store_true",dest="quiet_mode",help="execute the program silently",default=False)
    parser.add_option("-d","--dirs",action="store_true",dest="dirInfo",help="get dir contents",default=False)
    parser.add_option("-t","--timeframe", dest="log_timeframe",help="how long ago you need Event logs (days)", metavar="1",default=1)

    (options, args) = parser.parse_args()
    quiet_mode = options.quiet_mode
    dirInfo = options.dirInfo
    log_timeframe = int(options.log_timeframe)

    wmiuser = analyst
    wmidomain = envDomain
    if "\\" not in wmidomain and (wmidomain != "" or wmidomain==None): wmidomain += "\\"
    outfile = ""

    # check to see if we have an ip address argument
    if len(args) != 1:
        print("incorrect number of arguments")
        parser.print_help()
        sys.exit(1)
    else:
        """
        check to see if we have a ip address
        """
        try:
            if is_valid_ip(args[0]):
                socket.inet_aton(args[0])
            dstHost = args[0]
        except socket.error as e:
            logger.error(e.message)
            sys.exit(1)

    # set logging level
    if quiet_mode: logger.setLevel(logging.INFO)

    # connect to the remote host
    logger.info("Connecting to host %s" % dstHost)

    try:
        if envDomain == "" or "None" in envDomain:
            #couldn't detect Environment string, perhaps
            logger.error("couldn't get environment variables")

        #connecting to the remote host
        logger.debug("Connecting to= %s" % dstHost)
        wmiObj = wmi.WMI(dstHost)
    except wmi.x_access_denied:
        logger.error("Access is denied to %s." % (dstHost))
        sys.exit(0)
    except wmi.x_wmi_authentication:
        logger.error("Invalid credentials")
        sys.exit(0)
    except wmi.x_wmi:
        logger.error("The RPC server is unavailable to %s." % (dstHost))
        sys.exit(0)


    logger.info("Connected; collecting IR data")
    if dirInfo:
        logger.info("Getting directory information is enabled, Script may run a little more longer than excepted.")

    # Thread-1: collect netstat information
    thread = _tworker(name="netstat", target=netstat, args=(dstHost,))
    thread.start()
    threads += [thread]

    # Thread-2: copy files to remote host
    thread = _tworker(name="copy2", target=copy2, args=(dstHost,))
    thread.start()
    threads += [thread]

    # Thread-3: dnscache of remote host
    thread = _tworker(name="dnscache", target=dnscache, args=(dstHost,))
    thread.start()
    threads += [thread]

    # Thread-4: executes misc commands on remote host
    thread = _tworker(name="misccmds", target=misc_cmds, args=(dstHost,))
    thread.start()
    threads += [thread]

    # Thread-5: get event logs
    thread = _tworker(name="eventlogs", target=getNTlogs, args=(dstHost,log_timeframe,))
    thread.start()
    threads += [thread]

    rManufacturer = rOS = rHostname = rOSName = rOSArch = rCountry = ""
    rServicePack = rCurrentTimeZone = rWinDir = userTZ = rDomain = ""
    rLoggedIn = rPhyRam = rMachineType = ""
    # get basic OS details
    for Os in wmiObj.Win32_OperatingSystem():
        rOS = re.search('\S+\s+(\S+\s+\S+).*',Os.Caption).group(1)
        rHostname = Os.CSName
        rOSName = Os.Caption, Os.BuildType
        if not "XP" in rOS: rOSArch = Os.OSArchitecture
        rCountry = Os.CountryCode
        rServicePack = Os.CSDVersion
        rCurrentTimeZone = readableTimeZone(Os.LocalDateTime)
        rWinDir = Os.WindowsDirectory
    rUpTime = getSysuptime(wmiObj)
    userTZ = rCurrentTimeZone
    logger.info("%s running on %s" % (rOS,dstHost))

    for Cs in wmiObj.Win32_ComputerSystem():
        rDomain = re.search(r'\S+\.(\S+)\.\S+',Cs.Domain).group(1)
        if not "8" in rOS:
            # if user is not loggedin the Cs.UserName is empty & causes an error
            # --todo--
            # take care if there is no username
            try:
                rLoggedIn = re.search(r'\S+\\(\S+)',Cs.UserName).group(1)
            except TypeError:
                # if Cs.username is empty, then look into LogonSession
                for us in wmiObj.Win32_LogonSession():
                    try:
                        for user in us.references("Win32_LoggedOnUser"):
                            if user.Antecedent.Name not in analyst:
                                rLoggedIn = user.Antecedent.Name
                    except:
                        pass

        rPhyRam = bytes2human(long(Cs.TotalPhysicalMemory))
        rManufacturer = Cs.Manufacturer + " (" + Cs.Model + ")"

    if "8" in rOS:
        # get user logged in information if windows 8
        for ul in wmiObj.Win32_LoggedOnUser():
            rDomain = ul.Antecedent.Domain
            rLoggedIn = ul.Antecedent.Name

    if "Virtual" in rManufacturer:
        rMachineType = "Virtual Machine"
    else:
        rMachineType = "Physical Machine"

    logger.debug("Logged in user: %s" % rLoggedIn)

    outfile = of("%s_%s_%s_%s_artifacts" % (str(dstHost).replace('.','-'),rLoggedIn,rHostname,date.today().strftime("%d%b%Y").upper()))

    basicinfo.append(120*'-')
    basicinfo.append("Basic Info:")
    basicinfo.append("Hostname: %s\tOS: %s (%s) %s" %(rHostname, rOS, rServicePack, "Arch: "+ rOSArch if not "XP" in rOSArch else ""))
    basicinfo.append("Type:%s\tManufacturer: %s" % (rMachineType,rManufacturer))
    basicinfo.append("Physical Ram: %s\t\tSystem uptime: %s" % (rPhyRam,rUpTime))
    basicinfo.append("Default Windows Directory: %s" % (rWinDir))

    # get SID of the logged in user
    w32sid = win32security.LookupAccountName(None, rLoggedIn)[0]
    rSID = win32security.ConvertSidToStringSid(w32sid)
    userprofile_dir = getUserProfileDir(rLoggedIn, rSID, dstHost)

    # start worker threads
    logger.debug("Creating threads")

    if dirInfo:
        """
        Thread-6 (if enabled)
        if dirInfo flag is enabled, then get contents of directories that are
        requested in the global dictionary dir variables.
        """
        thread = _tworker(name="dirinfo", target=dirwalk, args=(dstHost,userprofile_dir,rOS,rWinDir,))
        thread.start()
        threads += [thread]

    # Thread-6: collect user information from active directory
    thread = _tworker(name="aduserinfo",target=getUserInfo, args=(rLoggedIn,))
    thread.start()
    threads += [thread]

    # Thread-7: collect disk partitions information
    thread = _tworker(name="dskparts",target=getDisks, args=(dstHost,))
    thread.start()
    threads += [thread]

    # Thread-8: collect mutex information
    thread = _tworker(name="mutex", target=mutexes, args=(dstHost,))
    thread.start()
    threads += [thread]

    # Thread-9: collect open handles information
    thread = _tworker(name="handle", target=handles, args=(dstHost,))
    thread.start()
    threads += [thread]

    # Thread-10: collect autoruns information
    thread = _tworker(name="autorunsc", target=autorunsc, args=(dstHost,))
    thread.start()
    threads += [thread]

    # Thread-11: collect windows startup information
    thread = _tworker(name="startup", target=show_startup, args=(dstHost,))
    thread.start()
    threads += [thread]

    # Thread-12: collect process/tasklist information
    thread = _tworker(name="tasklist", target=tasklist, args=(dstHost,))
    thread.start()
    threads += [thread]

    # Thread-13: collect process/tasklist information
    thread = _tworker(name="services", target=services, args=(dstHost,))
    thread.start()
    threads += [thread]

    # Thread-14: collect scheduled jobs information
    thread = _tworker(name="schtasks", target=schtasks, args=(dstHost,))
    thread.start()
    threads += [thread]

    # Thread-15: collect registry information
    thread = _tworker(name="regs", target=get_reg_entries, args=(dstHost,rSID,))
    thread.start()
    threads += [thread]

    logger.debug("threads created: %d" % len(threads))
    # end of creating threads

    """
    Yield for the threads to complete
    The return vales are stored in response which is a dict
    response is a globally declared dict
    """
    for t in threads:
        try:
            response.update(t.join())
        except TypeError:
            logger.info("__%s: No return value" % str(t))

    allThreadsFinished = True
    del threads, thread
    """
    All threads have finished and we have collected the following Live Response date:
    Basic User information from AD, Basic System information
    Autoruns, Mutexes, Handles, Processes, Services, Network Connections, Disk Partitions
    NT Event Logs, dir information, etc
    Output:
    autorunsc,schtasks,netstat,misccmds,startup,regs,handles,tasklist,mutex,ntlogs
    services,dnscache,diskpart, userinfo,dirs
    """
    summary = [] # Summary section for analytics
    summary.append(120*'-')
    summary.append("Summary")
    summary.append(50*'-')
    logger.debug("performing data analytics...")
    """
    do some analytics/predictions to provide a summary section
    """
    RegsFound = []
    # regex summary
    summary.append("Potiential random characters in registry found:")
    for l in response["regs"]:
        srch = re.search(strRandReg, l)
        if srch:
            RegsFound.append(l)
            RegsFound.append("(Still look into reg section for details, I might have missed something)")
    if len(RegsFound) == 0:
        summary.append("None (Still look into reg section for details, I might have missed something)")
    else:
        summary += RegsFound
    summary.append(30*'-')
    # netstat summary

    nets=[]
    summary.append("Connections to external")
    for l in response['netstat']:
        srch= re.findall(netstat_regex,l)
        if srch:
            for a in srch:
                if not isPrivateIP(a[1]):
                    nets.append(a[1] + " on port " + a[2] + ", " + ip2loc(a[1]))
    if len(nets) == 0:
        summary.append("None")
    else:
        summary += nets
    summary.append(30*'-')

    summary.append(120*'-')

    # summary section end
    logger.debug("writing IR data file...")
    touch(outfile,"Analysis for: %s (%s) | Analysis Started @ %s \n" % (dstHost,rHostname,str(startTime)))
    try:
        touch(outfile,'\n'.join(summary),True)
    except Exception:
        touch(outfile,"\nNO SUMMARY AVAILABLE. Try another run, perhaps something happened",True)
    try:
        touch(outfile,'\n'.join(response['userinfo']),True)
    except Exception:
        touch(outfile,"\nUser details unavailable. Try another run, perhaps something happened",True)
    try:
        touch(outfile,'\n' + '\n'.join(basicinfo),True)
    except Exception:
        touch(outfile,"\nBasic Info unavailable. Try another run, perhaps something happened",True)
    try:
        touch(outfile,'\n' + '\n'.join(response['diskpart']),True)
    except Exception:
        touch(outfile,"\nDisk Partition info unavailable. Try another run, perhaps something happened",True)
    try:
        touch(outfile,'\n' + '\n'.join(response['startup']),True)
    except Exception:
        touch(outfile,"\nStartup Entries unavailable. Try another run, perhaps something happened",True)
    try:
        touch(outfile,'\n' + '\n'.join(response['regs']),True)
    except Exception:
        touch(outfile,"\nRegistry Entries unavailable. Try another run, perhaps something happened",True)
    try:
        touch(outfile,'\n' + '\n'.join(response['mutex']),True)
    except Exception:
        touch(outfile,"\nMutex information unavailable. Try another run, perhaps something happened",True)
    try:
        touch(outfile,'\n' + '\n'.join(response['tasklist']),True)
    except Exception:
        touch(outfile,"\nTasklist information unavailable. Try another run, perhaps something happened",True)
    try:
        touch(outfile,'\n' + '\n'.join(response['handles']),True)
    except Exception:
        touch(outfile,"\nOpen handles info unavailable. Try another run, perhaps something happened",True)
    try:
        touch(outfile,'\n' + '\n'.join(response['netstat']),True)
    except Exception:
        touch(outfile,"\nNetStat info unavailable. Try another run, perhaps something happened",True)
    try:
        touch(outfile,'\n' + '\n'.join(response['schtasks']),True)
    except Exception:
        touch(outfile,"\nScheduled tasks info unavailable. Try another run, perhaps something happened",True)
    try:
        touch(outfile,'\n' + '\n'.join(response['services']),True)
    except Exception:
        touch(outfile,"\nServices info unavailable. Try another run, perhaps something happened",True)
    try:
        touch(outfile,'\n' + '\n'.join(response['dnscache']),True)
    except Exception:
        touch(outfile,"\nDNS Cache ifo unavailable. Try another run, perhaps something happened",True)
    try:
        touch(outfile,'\n' + '\n'.join(response['misccmds']),True)
    except Exception:
        touch(outfile,"\nMisc commands execution unavailable. Try another run, perhaps something happened",True)
    try:
        if dirInfo: touch(outfile,'\n' + '\n'.join(response['dirs']),True)
    except Exception:
        touch(outfile,"\nDirectory contents unavailable. Try another run, perhaps something happened",True)
    try:
        touch(outfile,'\n' + '\n'.join(response['autorunsc']),True)
    except Exception:
        touch(outfile,"\nAutoruns info unavailable. Try another run, perhaps something happened",True)
    try:
        touch(outfile,'\n' + '\n'.join(response['ntlogs']),True)
    except Exception:
        touch(outfile,"\nNT Logs unavailable. Try another run, perhaps something happened",True)

    logger.info("IR data: %s" % outfile)


def signal_handler(signum, frame):
    """
    register signal handler to catch CTRL+C
    """
    logger.info("Ctrl+C detected, exiting gracefully")
    sys.exit(0)


if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    startTime = datetime.now()
    main()
    runtime = datetime.now()-startTime
    logger.info("script runtime: %s" % str(runtime))




"""
<<< EOF
"""
