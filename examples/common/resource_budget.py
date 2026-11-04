# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Bound native HTTP workers; measure resources without inferring authorization."""
import http.server
import os
import platform
import resource
import socketserver
import subprocess
import threading
import time

class BoundedServer(socketserver.ThreadingMixIn,http.server.HTTPServer):
    daemon_threads=True
    allow_reuse_address=True
    request_queue_size=8
    max_workers=32
    def __init__(self,*args,**kwargs):
        self.slots=threading.BoundedSemaphore(self.max_workers)
        super().__init__(*args,**kwargs)
    def process_request(self,request,client_address):
        if not self.slots.acquire(blocking=False):
            try:
                request.settimeout(.2)
                request.sendall(b'HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 12\r\n\r\nWORKER_LIMIT')
            finally:self.shutdown_request(request)
            return
        request.settimeout(10)
        try:super().process_request(request,client_address)
        except Exception:
            self.slots.release();raise
    def process_request_thread(self,request,client_address):
        try:super().process_request_thread(request,client_address)
        finally:self.slots.release()

class NativeSample:
    def __init__(self):self.last=(time.monotonic(),time.process_time())
    def read(self):
        now,cpu=time.monotonic(),time.process_time();old,cpu_old=self.last;self.last=(now,cpu)
        result={'pid':os.getpid(),'monotonic':now,'cpu_seconds':cpu,'cpu_cores_used':(cpu-cpu_old)/(now-old) if now>old else None,
                'python_threads':threading.active_count(),'rss_bytes':None,'status':'UNMEASURED'}
        try:
            p=subprocess.run(['ps','-o','rss=','-p',str(os.getpid())],capture_output=True,text=True,timeout=2,check=True)
            rss=int(p.stdout.strip())*1024
            if rss<=0:raise ValueError('rss')
            result.update(rss_bytes=rss,status='MEASURED',rss_basis='ps_rss_kib',cpu_basis='process_time_delta')
        except (OSError,ValueError,subprocess.SubprocessError):pass
        return result

def container_sample(container_id):
    """Read cgroup v2 inside one explicitly owned container; missing data stays missing."""
    result={'container_id':container_id,'status':'UNMEASURED','monotonic':time.monotonic()}
    script='for f in cpu.max cpu.stat memory.max memory.current memory.peak memory.events; do echo "$f"; cat "/sys/fs/cgroup/$f" 2>/dev/null || exit 3; done'
    try:
        p=subprocess.run(['docker','exec',container_id,'sh','-c',script],capture_output=True,text=True,timeout=5,check=True)
        names=('cpu.max','cpu.stat','memory.max','memory.current','memory.peak','memory.events');section=None;data={}
        for line in p.stdout.splitlines():
            if line in names:section=line;data[section]=[]
            elif section:data[section].append(line)
        if set(data)!=set(names):return result
        cpu=dict(line.split() for line in data['cpu.stat']);mem=dict(line.split() for line in data['memory.events'])
        result.update(status='MEASURED',cpu_max=' '.join(data['cpu.max']),memory_max=' '.join(data['memory.max']),
                      memory_current=int(data['memory.current'][0]),memory_peak=int(data['memory.peak'][0]),
                      cpu_usage_usec=int(cpu['usage_usec']),nr_periods=int(cpu['nr_periods']),nr_throttled=int(cpu['nr_throttled']),
                      throttled_usec=int(cpu['throttled_usec']),oom=int(mem['oom']),oom_kill=int(mem['oom_kill']))
    except (OSError,ValueError,KeyError,IndexError,subprocess.SubprocessError):pass
    return result
