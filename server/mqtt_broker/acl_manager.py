import argparse 
import os 
import re 
import sys 
import subprocess 
from pathlib import Path 


ROOT =Path (__file__ ).resolve ().parents [2 ]
if str (ROOT )not in sys .path :
    sys .path .insert (0 ,str (ROOT ))

from server .utils import FileLock 

DEVICE_BLOCK ="""# BEGIN DEVICE {device_id}
user {device_id}
topic read ics/control/{device_id}
topic write ics/telemetry/{device_id}
topic write ics/alerts/{device_id}
# END DEVICE {device_id}
"""


def load_acl (path :Path )->str :
    return path .read_text (encoding ="utf-8")if path .exists ()else ""


def write_acl (path :Path ,content :str )->None :
    path .parent .mkdir (parents =True ,exist_ok =True )
    path .write_text (content .rstrip ()+"\n",encoding ="utf-8")


def validate_device_id (device_id :str )->bool :

    return bool (re .match (r"^[a-zA-Z0-9_-]+$",device_id ))


def add_device (path :Path ,device_id :str )->None :
    if not validate_device_id (device_id ):
        raise ValueError (f"Invalid device_id '{device_id }'. Only alphanumeric, underscores, and dashes are allowed.")

    with FileLock (str (path ))as _ :
        content =load_acl (path )
        block_pattern =re .compile (rf"# BEGIN DEVICE {re .escape (device_id )}.*?# END DEVICE {re .escape (device_id )}\n?",re .S )
        content =block_pattern .sub ("",content )
        if content and not content .endswith ("\n"):
            content +="\n"
        content +=DEVICE_BLOCK .format (device_id =device_id )
        write_acl (path ,content )


def remove_device (path :Path ,device_id :str )->None :
    if not validate_device_id (device_id ):
        raise ValueError (f"Invalid device_id '{device_id }'. Only alphanumeric, underscores, and dashes are allowed.")

    with FileLock (str (path ))as _ :
        content =load_acl (path )
        block_pattern =re .compile (rf"\n?# BEGIN DEVICE {re .escape (device_id )}.*?# END DEVICE {re .escape (device_id )}\n?",re .S )
        content =block_pattern .sub ("\n",content )
        write_acl (path ,content )


def reload_broker ()->None :
    commands =(["systemctl","reload","mosquitto"],["service","mosquitto","reload"])
    for command in commands :
        try :
            subprocess .run (command ,check =True ,stdout =subprocess .DEVNULL ,stderr =subprocess .DEVNULL )
            return 
        except Exception :
            continue 
    if os .name =="posix":
        subprocess .run (["pkill","-HUP","mosquitto"],check =False )


def parse_args ()->argparse .Namespace :
    parser =argparse .ArgumentParser (description ="Update Mosquitto ACLs for zero-trust isolation")
    parser .add_argument ("action",choices =["add","remove"])
    parser .add_argument ("device_id")
    parser .add_argument ("--acl-file",default ="acl.conf")
    parser .add_argument ("--reload",action ="store_true")
    return parser .parse_args ()


def main ()->int :
    args =parse_args ()
    acl_path =Path (args .acl_file )

    if args .action =="add":
        add_device (acl_path ,args .device_id )
    else :
        remove_device (acl_path ,args .device_id )

    if args .reload :
        reload_broker ()
    return 0 


if __name__ =="__main__":
    raise SystemExit (main ())
