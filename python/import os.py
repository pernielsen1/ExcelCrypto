import os
import shutil
from datetime import datetime
status_file_name = "status.txt"
log_file_name = "log.txt"
#-------------------------------------------------------------
# do the file swap today to yesterday
#-------------------------------------------------------------

#-------------------------------------------------------------
# get_status - read status from status_file_name
#-------------------------------------------------------------
def get_status():
    if os.path.isfile(status_file_name) == False:
        set_status("00", " new status file created")  # will create the file
    f = open(status_file_name,   "r")
    res = f.readline()
    f.close()
    return res[0: 2]   # don't include the "\n" - you never know if it was inserted or not by humans
#-------------------------------------------------------------
# set_status - set status in status_file_name
#-------------------------------------------------------------
def set_status(status, message):
    msg =  status + datetime.now().strftime(" %Y%m%d_%H%M%S " + message + "\n")
    status_file = open(status_file_name,   "w")
    status_file.write(msg)    
    status_file.close()
    log_file = open(log_file_name, "a")
    log_file.write(msg)
    log_file.close()
#-------------------------------------------------------------
# send the file and swap today to yesterday
#-------------------------------------------------------------
def send_and_today_to_yesterday(today_file_name, yesterday_file_name, new_today_file_name, backup_dir, send_dir):
    # take a copy of the old yesterday
    shutil.copy(yesterday_file_name, backup_dir + "/" + yesterday_file_name + datetime.now().strftime("_%Y%m%d_%H%M%S"))
    # entering critical phase
    set_status("80", "send i.e. copying " + new_today_file_name + " to " + send_dir)   #critical 
    shutil.copy(new_today_file_name, send_dir + "/" + new_today_file_name + datetime.now().strftime("_%Y%m%d_%H%M%S"))
    set_status("81", "removing old yesterday:" + yesterday_file_name) 
    os.remove(yesterday_file_name)
    set_status("82", "moving today:" + today_file_name + " to yesterday:" + yesterday_file_name) 
    shutil.move(today_file_name, yesterday_file_name) 
    set_status("00", "All done we are not critical anymore")  # all done we are not critical any more 
    return
#---------------------------------------------------------------------------------------
# main_example  - create a yesterday and today file ... and swap in a safe way
#----------------------------------------------------------------------------------------
def main_example_init(today_file_name, yesterday_file_name, patch_file_name, backup_dir, send_dir):
    f = open(today_file_name,   "w")
    f.write("Today" + "\n")
    f.close()
    f = open(yesterday_file_name, "w")
    f.write("Yesterday" + "\n")
    f.close()
    f = open(patch_file_name, "w")
    f.write("patch" + "\n")
    f.close()

    if not os.path.exists(backup_dir):
        os.mkdir(backup_dir)
    if not os.path.exists(send_dir):
        os.mkdir(send_dir)

#--------------------------------------------------------------------------------------------------------------
# do_patch: add patch to today_file_name - creating new_today_file_name
#--------------------------------------------------------------------------------------------------------------
def do_patch(today_file_name, patch_file_name, new_today_file_name):
    set_status("10", "doing the patch adding " + patch_file_name + " to " + today_file_name )  # processing no danger in restarting 
    in_file = open(today_file_name, "r")
    out_file = open(new_today_file_name, "w")
    for line in in_file:
        out_file.write(line)
    patch_file = open(patch_file_name, "r")
    for line in patch_file:
        out_file.write(line)
    return
def main():
    today_file_name = "today.txt"
    new_today_file_name = "new_today.txt"
    yesterday_file_name = "yesterday.txt"
    patch_file_name = "patch.txt"
    backup_dir = "backup"
    send_dir = "send"
    main_example_init(today_file_name, yesterday_file_name, patch_file_name, backup_dir, send_dir)
    if (get_status() >  "79"):
        print("status is criticcal - can't start")
        exit(1)

    print("status is 00 let's get started")
    do_patch(today_file_name, patch_file_name, new_today_file_name)
    send_and_today_to_yesterday(today_file_name, yesterday_file_name, new_today_file_name, backup_dir, send_dir)
    print("All done")
#-----------------------
# here we go 
#--------------------------------------------------------------------
main()
exit()
