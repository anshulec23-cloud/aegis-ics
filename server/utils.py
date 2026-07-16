import os 
import time 
import sys 
from typing import Any 


try :
    import fcntl 
except ImportError :
    fcntl =None 

try :
    import msvcrt 
except ImportError :
    msvcrt =None 


class FileLock :
    """
    A cross-platform file locking utility that supports Windows (msvcrt)
    and Linux/macOS (fcntl) to coordinate file writes across processes/threads.
    """
    def __init__ (self ,file_path :str )->None :
        self .lock_file_path =f"{file_path }.lock"
        self .fd =None 

    def __enter__ (self )->"FileLock":

        self .fd =open (self .lock_file_path ,"w")
        if fcntl :
            try :
                fcntl .flock (self .fd ,fcntl .LOCK_EX )
            except IOError :

                time .sleep (0.1 )
                fcntl .flock (self .fd ,fcntl .LOCK_EX )
        elif msvcrt :


            locked =False 
            for _ in range (50 ):
                try :
                    self .fd .seek (0 )
                    msvcrt .locking (self .fd .fileno (),msvcrt .LK_LOCK ,1 )
                    locked =True 
                    break 
                except IOError :
                    time .sleep (0.1 )
            if not locked :
                raise IOError ("Could not acquire file lock on Windows.")
        return self 

    def __exit__ (self ,exc_type :Any ,exc_val :Any ,exc_tb :Any )->None :
        if self .fd :
            try :
                if fcntl :
                    fcntl .flock (self .fd ,fcntl .LOCK_UN )
                elif msvcrt :
                    self .fd .seek (0 )
                    msvcrt .locking (self .fd .fileno (),msvcrt .LK_UNLCK ,1 )
            except IOError :
                pass 
            self .fd .close ()
            try :
                os .remove (self .lock_file_path )
            except OSError :
                pass 


def canonicalize_payload (payload :dict [str ,Any ])->dict [str ,Any ]:
    """
    Standard canonicalization format for device telemetry signatures.
    """
    canonical ={}
    for k ,v in payload .items ():
        if k in ("temperature","pressure","humidity","rssi"):
            canonical [k ]=f"{float (v ):.2f}"
        elif k =="timestamp":
            canonical [k ]=f"{float (v ):.3f}"
        else :
            canonical [k ]=v 
    return canonical 
