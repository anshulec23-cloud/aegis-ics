from __future__ import annotations 

import json 
import sys 
from dataclasses import dataclass ,field 
from pathlib import Path 


ROOT =Path (__file__ ).resolve ().parents [2 ]
if str (ROOT )not in sys .path :
    sys .path .insert (0 ,str (ROOT ))

from server .utils import FileLock 


@dataclass 
class MicroSegmentationStore :
    path :Path 
    isolated_devices :set [str ]=field (default_factory =set )

    def load (self )->None :
        with FileLock (str (self .path ))as _ :
            if self .path .exists ():
                try :
                    data =json .loads (self .path .read_text (encoding ="utf-8"))
                    self .isolated_devices =set (data .get ("isolated_devices",[]))
                except (json .JSONDecodeError ,TypeError ,KeyError )as e :

                    print (f"[Microseg] File read error/corruption detected: {e }. Starting fresh.")
                    self .isolated_devices =set ()

    def save (self )->None :
        with FileLock (str (self .path ))as _ :
            self .path .parent .mkdir (parents =True ,exist_ok =True )
            payload ={"isolated_devices":sorted (self .isolated_devices )}
            self .path .write_text (json .dumps (payload ,indent =2 )+"\n",encoding ="utf-8")

    def isolate (self ,device_id :str )->None :
        self .load ()
        self .isolated_devices .add (device_id )
        self .save ()

    def rejoin (self ,device_id :str )->None :
        self .load ()
        self .isolated_devices .discard (device_id )
        self .save ()

    def list_isolated (self )->list [str ]:
        self .load ()
        return sorted (self .isolated_devices )

