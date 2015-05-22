#!/usr/bin/python
# Query global machine state, as well as 'very busy' PIDs
# glenn@sensepost.com
import psutil
import time
import datetime
import logging

cpu_threshold = 30 # pid using more than x% of the CPU
mem_threshold = 30 # pid using more than y% of memory
network_interface = 'ppp0'

def query_system_status():
    """Query global mem, CPU, disk, and network (if present)"""
    uptime = int(time.time() - psutil.BOOT_TIME)
    uptime = str(datetime.timedelta(seconds=uptime))
    try:
        used_mem = psutil.virtmem_usage().percent
        used_cpu = psutil.cpu_percent(percpu=False) #N.B Only looking at one CPU
        used_disk = psutil.disk_usage('/').percent
        total_network = psutil.network_io_counters(pernic=True)
        network_sent,network_rcvd=-1,-1
        if network_interface in total_network:
            network_sent = round(total_network[network_interface].bytes_sent/1024.0/1024.0,2)
            network_rcvd = round(total_network[network_interface].bytes_recv/1024.0/1024.0,2)
    except psutil.AccessDenied:
            loggging.error("Access denied when trying to query PID %d" %p)
            return None
    return {'used_mem':used_mem, 'used_cpu':used_cpu, 'used_disk':used_disk, 'network_sent':network_sent, 'network_rcvd':network_rcvd, 'uptime':uptime}

def fetch_busy_processes():
    """Query all PIDs for memory and CPU usage."""
    now = int(time.time())
    busy_pids = []
#
    for p in psutil.get_pid_list():
        try:
            pid = psutil.Process(p)
            p_cpu = pid.get_cpu_percent()
            p_mem = pid.get_memory_percent()
            p_name = pid.name
#           logging.debug( "Name: %s, CPU: %s, MEM: %s" %(p_name, p_cpu, p_mem))
            if p_cpu >= cpu_threshold or p_mem >= mem_threshold:
                busy_pid = {'name': p_name, 'pid':p, 'cpu' : p_cpu, 'mem' : p_mem} 
                busy_pids.append( busy_pid )
        except psutil.NoSuchProcess:
             pass
        except psutil.AccessDenied:
            loggging.error("Access denied when trying to query PID %d" %p)
        except psutil.TimeoutExpired:
            logging.error("Timed out when trying to query PID %d" %p)
    return busy_pids

if __name__ == "__main__":
    from pprint import pprint as pp
    print "Global stats:"
    pp(query_system_status())
    print "Very busy processes:"
    pp(fetch_busy_processes())
