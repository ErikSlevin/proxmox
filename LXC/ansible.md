```
sudo pct create 100 \
    dsm-template:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst \
    --hostname ansible-mgmt \
    --cores 2 \
    --memory 2048 \
    --swap 512 \
    --rootfs local-lvm:20 \
    --net0 name=eth0,bridge=MGMT,tag=10,ip=10.10.0.200/24,gw=10.10.0.1 \
    --nameserver 10.0.0.1 \
    --searchdomain home.intern \
    --ostype debian \
    --unprivileged 1 \
    --onboot 1 \
    --features nesting=1,keyctl=1 \
    --timezone Europe/Berlin \
    --tags mgmt \
    --description "# 🤖 Ansible Management Server

    ## 💻 Hardware
    - **CPU:** 2 Cores
    - **RAM:** 2048 MB
    - **Swap:** 512 MB
    - **Storage:** 20 GB (local-lvm)
    
    ## 🌐 Netzwerk
    - **Bridge:** MGMT
    - **VLAN:** 10
    - **IP:** 10.10.0.200/24
    - **Gateway:** 10.10.0.1
    - **DNS:** 10.0.0.1
    - **Domain:** home.intern" \
    --password
```
