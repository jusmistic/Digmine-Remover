import glob
import os, sys
import winshell
import winreg
import logging as log
log_setting = log.DEBUG
log.basicConfig(format='[%(levelname)s] - %(message)s', level=log_setting)


def chrome_check_arg():
    """
        Check Chrome Shortcut Malware arguments  

        malicious = --enable-automation --disable-infobars --load-extension=C:\\Users\\IEUser\\AppData\\Roaming\\IEUse

        tmp_path = [(path, attrib)]

        if return [] == Not infected
        else Infected
    """
    log.info("Start Scanning Chrome Shortcut arguments...")
    path_list = glob.iglob("C:/**/*.lnk", recursive=True)
    mal_attr = "--enable-automation --disable-infobars --load-extension".split(" ")[:2]
    tmp_path = []
    for path in path_list:
        try:
            with winshell.shortcut(path) as link:
                if 'chrome.exe' in link.path and mal_attr[0] in link.arguments and mal_attr[1] in link.arguments:
                    log.debug("Found Malicious arguments at %s" % path)
                    tmp_path.append((path, link.arguments))
        except:
            if "chrome.exe" in winshell.shortcut(path).path:
                log.error("Fail To Access At %s" %path)
    log.info("Chrome Extension Scanning Complete")

    return tmp_path
# chrome_check_arg()

def read_reg(reg,sub, key):
    """
        reg = HKEY_LOCAL_MACHINE
        sub = SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run
        key = 'Google Updater'
    """
    log.info("Checking Startup registry...")
    try:
        aReg = winreg.ConnectRegistry(None, reg)
        regKey = winreg.OpenKey(aReg, sub, 0, winreg.KEY_READ)
        value = winreg.QueryValueEx(regKey, key)
        return value
    except:
        log.error("Fail to read startup registry")

def check_registry():
    """
        Check Digmine Startup registry
        reg = HKEY_LOCAL_MACHINE
        sub = SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run
        key = 'Google Updater'
    """
    val= ""
    val = read_reg(winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", 'Google Updater')
    log.debug("Startup Registry Value - "+str(val))
    return val

def check_appdata():
    """
        Check digmine file in %appdata%/user
    """
    log.info("Checking APPDATA...")
    digmine_list = ["update-x64.exe", "update-x86.exe", "background.js", "app.exe", "manifest.json"]
    tmp_list = []
    appdata = os.getenv('APPDATA')
    user = appdata.split("\\")[2] #IEUSer
    file_list = glob.iglob(appdata+"\\"+user+"\\*")
    for file in file_list:
        if file[len(appdata)+len(user)+2:] in digmine_list:
            log.debug("Found a malicious file : %s" % file)
            tmp_list.append(file)
    return tmp_list

# check_appdata()

def digmine_check_infected():
    """
        4 Step to detect this PC is Infected
        1. Check Chrome Shortcuts arguments
        2. Check file in %appdata%/user
        3. Check Registry 
    """

    log.info("Step 1 Check Chrome Shortcuts arguments.")
    arg_list = chrome_check_arg()
    found = 0
    infected = False
    for arg in arg_list:
        if arg[1] != "":
            found += 1
            infected = True
    if found > 0:
        log.warning("Found a malicious Chrome shortcuts!!")
        infected = True
    else:
        log.info("A malicious Chrome shortcut not found.")

    log.info("Step 2 Check file in APPDATA.")
    file_appdata = check_appdata() 
    if len(file_appdata) > 0:
        log.warning("Found a malicious files in APPDATA")
        infected = True
    else:
        log.info("A malicious files in APPDATA not found.")

    log.info("Step 3 Check Registry.")
    if check_registry()[0] != "":
        log.warning("Found a malicious Registry!!")
        infected = True
    else:
        log.info("A malicious Registry not found.")
    if(infected):
        log.warning("Still infected please remove manually.")
    else:
        log.info("Digmine Removed")

# digmine_check_infected()

    
def chrome_remove_arg(path_list):
    """
        Remove All Chrome Malware Shortcut arg
    """
    log.info("Start Removing Chrome shortcut attributes...")
    mal_attr = "--enable-automation --disable-infobars --load-extension".split(" ")[:2]
    path_list = [i[0] for i in path_list]
    for path in path_list:
        try:
            with winshell.shortcut(path) as link:
                if 'chrome.exe' in link.path and mal_attr[0] in link.arguments and mal_attr[1] in link.arguments:
                    log.debug("Removing arguments at %s", path)
                    link.arguments = ""
        except:
            if "chrome.exe" in winshell.shortcut(path).path:
                log.error("Fail To Access At %s" %path)
    log.info("Chrome shortcut arguments removed!")

# chrome_check_attrib()
      

def set_reg(reg, sub, key, value):
    try:
        winreg.CreateKey(reg, sub)
        registry_key = winreg.OpenKey(reg, sub, 0, winreg.KEY_WRITE)
        winreg.SetValueEx(registry_key, key, 0, winreg.REG_SZ, value)
        winreg.CloseKey(registry_key)
        return True
    except WindowsError:
        return False

def regedit():
    """
    HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
    """
    # val = read_reg(winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", 'Google Updater')
    set_reg(winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", 'Google Updater', "")
# regedit()
def delete_appdata():
    """
        Delete digmine file in %appdata%/user
    """
    log.info("Deleting APPDATA...")
    appdata = os.getenv('APPDATA')
    user = appdata.split("\\")[2] #IEUSer
    file_list = glob.iglob(appdata+"\\"+user+"\\*")
    for file in file_list:
        log.warning("Deleting %s" % file)
        os.remove(file)



def digmine_remove():
    """
        Remove step
        step 1 Remove chrome shortcuts 
        step 2 remove Startup registry -> ""
        step 3 Change Low file type -> ""
        step 4 Change Enable LUA -> 1
        step 5 Remove file at %appdata%
    """
    log.info("Step 1 Remove chrome shortcuts.")
    log.basicConfig(format='[%(levelname)s] - %(message)s', level=log.WARNING)
    chrome_remove_arg(chrome_check_arg())
    log.basicConfig(format='[%(levelname)s] - %(message)s', level=log_setting)
    log.info("Step 2 Remove Startup Registry")
    set_reg(winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", 'Google Updater', "")
    log.info("Step 3 Change LowRiskFileType")
    set_reg(winreg.HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations", 'LowRiskFileTypes', "")
    set_reg(winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations", 'LowRiskFileTypes', "")
    log.info("Step 4 Change EnableLUA")
    set_reg(winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 'EnableLUA', "1")
    log.info("Step 5 Delete File in APPDATA")
    delete_appdata()

    log.info("Recheck Digmine...")
    digmine_check_infected()
    

def main():
    print(" -------------------- Digmine Remover --------------------")
    print("Mode:")
    print("1. Check\t\t2.Remove")
    print("Input:> ", end="")
    mode = int(input())
    if mode == 1:
        digmine_check_infected()
    elif mode == 2:
        digmine_remove()
    else:
        print("Error Try again")
        main() 
main()