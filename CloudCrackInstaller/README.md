# CloudCrackInstaller

Script which installs Crunch, Pyrit and Cowpatty on a running Amazon EC2 Cluster GPU Instance to crack WPA and WPA2 keys.


## Amazon EC2 Cluster GPU Instance Details

* AMI ID: ami-aa30c7c3
* Manifest: amazon/EC2 CentOS 5.5 GPU HVM AMI
* Platform: Cent OS
* Instance Type: Cluster GPU(cg1.4xlarge, 22 GiB) !!Important

## Git Installation on CentOS 5.5

### i386  
wget http://packages.sw.be/rpmforge-release/rpmforge-release-0.5.2-2.el5.rf.i386.rpm

### OR x86_64  
wget http://packages.sw.be/rpmforge-release/rpmforge-release-0.5.2-2.el5.rf.x86_64.rpm


### Install DAG's GPG key  
rpm --import http://apt.sw.be/RPM-GPG-KEY.dag.txt


### Verify download  
rpm -K rpmforge-release-0.5.2-2.el5.rf.*.rpm


### Install package  
rpm -i rpmforge-release-0.5.2-2.el5.rf.*.rpm


### Install Git  
yum install git

## Benchmark results
Pyrit 0.4.0 (C) 2008-2011 Lukas Lueg http://pyrit.googlecode.com  
This code is distributed under the GNU General Public License v3+  
  
Running benchmark (**43321.5 PMKs/s**)... -  

Computed 43321.47 PMKs/s total.  
1: 'CUDA-Device #1 'Tesla M2050'': 21232.7 PMKs/s (RTT 2.9)  
2: 'CUDA-Device #2 'Tesla M2050'': 19437.0 PMKs/s (RTT 2.9)  
3: 'CPU-Core (SSE2)': 437.7 PMKs/s (RTT 3.0)  
4: 'CPU-Core (SSE2)': 442.2 PMKs/s (RTT 3.0)  
5: 'CPU-Core (SSE2)': 446.1 PMKs/s (RTT 3.0)  
6: 'CPU-Core (SSE2)': 453.5 PMKs/s (RTT 2.9)  
7: 'CPU-Core (SSE2)': 456.7 PMKs/s (RTT 3.0)  
8: 'CPU-Core (SSE2)': 445.7 PMKs/s (RTT 3.0)  
9: 'CPU-Core (SSE2)': 454.0 PMKs/s (RTT 3.0)  
10: 'CPU-Core (SSE2)': 467.1 PMKs/s (RTT 3.0)  
11: 'CPU-Core (SSE2)': 452.9 PMKs/s (RTT 2.9)  
12: 'CPU-Core (SSE2)': 457.9 PMKs/s (RTT 3.0)  
13: 'CPU-Core (SSE2)': 446.6 PMKs/s (RTT 2.9)  
14: 'CPU-Core (SSE2)': 456.9 PMKs/s (RTT 3.0)  
15: 'CPU-Core (SSE2)': 454.1 PMKs/s (RTT 2.9)  
16: 'CPU-Core (SSE2)': 453.6 PMKs/s (RTT 2.9)