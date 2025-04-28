# eTran: Extensible Kernel Transport with eBPF

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

eTran (extensible kernel Transport) is a system for agilely customizing kernel transports. 

eTran achieves agile customizability and kernel safety by (1) leveraging existing eBPF infrastructure such as built-in data structures (eBPF maps), BPF timer, and XDP for fast packet IO, and (2) extending it with new eBPF hooks and maps to support complex transport functionalities while conforming to the strict eBPF verifier for safety. 

eTran allows safely offloading full trans-port states and performance-critical operations into the kernel, achieving strong protection. For example, it supports packet acknowledging, flow pacing, fast retransmission, and more in eBPF. We implement TCP (with DCTCP congestion control) and Homa under eTran, and achieve up to 4.8×/1.8× higher throughput with 3.7×/7.5× lower latency compared to existing kernel implementation.

## Transport protocols supported
- [x] Homa
- [x] TCP

## Getting Started

### Build eTran-linux

```bash
git clone https://github.com/eTran-NSDI25/eTran-linux

# Install dependencies
sudo apt update && sudo apt-get install git fakeroot build-essential ncurses-dev xz-utils libssl-dev bc flex libelf-dev bison clang llvm libclang-dev libbpf-dev libelf-dev dwarves libmnl-dev libc6-dev-i386 libcap-dev libgoogle-perftools-dev libdwarf-dev cpufrequtils libpcap-dev automake libtool pkg-config -y

cd ~/linux

make menuconfig

scripts/config --disable SYSTEM_TRUSTED_KEYS
scripts/config --disable SYSTEM_REVOCATION_KEYS

# Compile kernel
make -j`nproc`

# Install kernel modules and kernel
sudo make modules_install -j`nproc` && sudo make install -j`nproc`

# Install kernel headers
sudo make headers_install INSTALL_HDR_PATH=/usr

# One-shot command to compile, install kernel and reboot
make -j`nproc` && sudo make modules_install -j`nproc` && sudo make install -j`nproc` && sudo make headers_install INSTALL_HDR_PATH=/usr && sudo shutdown -r now
```

### Build eTran
```bash
cd ~/eTran
# Install bpftool and llvm
sudo bash install.sh
# Compile eTran
./configure && make -C eTran
```

### Run application examples
1. Warm up systems to make sure routing tables are set up correctly in kernel. E.g., ping between servers and clients.

2. Launch microkernel:
```bash
cd eTran/micro_kernel
sudo ./micro_kernel
```
3. Run application:
```bash
# Homa server
ETRAN_PROTO=homa ./cp_node server
# Homa client
ETRAN_PROTO=homa ./cp_node client --first-server 0 --workload 100 --client-max 1 --one-way
# TCP server
ETRAN_PROTO=tcp ETRAN_NR_APP_THREADS=1 ETRAN_NR_NIC_QUEUES=1 LD_PRELOAD=../shared_lib/libetran.so ./epoll_server -i 192.168.6.1 -l 100000 -b 100000
# TCP client
ETRAN_PROTO=tcp ETRAN_NR_APP_THREADS=1 ETRAN_NR_NIC_QUEUES=1 LD_PRELOAD=../shared_lib/libetran.so ./epoll_client -i 192.168.6.1 -l 100000 -b 100000
```

### Reference

```
@inproceedings{etran,
  title={{eTran: Extensible Kernel Transport with eBPF}},
  author={Chen, Zhongjie and Meng, Qingkai and Lao, ChonLam and Liu, Yifan and Ren, Fengyuan and Yu, Minlan and Zhou, Yang},
  booktitle={22nd USENIX Symposium on Networked Systems Design and Implementation (NSDI 25)},
  year={2025}
}
```

### Contact

Feel free to raise issues or contact us if you have any questions or suggestions. 
You can reach us at: Zhongjie Chen (chenzhjthu@gmail.com), Yang Zhou (yangzhou.rpc@gmail.com).