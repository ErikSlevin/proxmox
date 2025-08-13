sudo pct create 100 synology:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst \
  -hostname ansible \
  -storage local-lvm \
  -cores 2 \
  -memory 2048 \
  -rootfs local-lvm:10 \
  -net0 name=mgmt,bridge=vmbr0,tag=10,ip=10.10.0.2/24,gw=10.10.0.1 \
  -unprivileged 1 \
&& sudo pct set 100 -tags mgmt
