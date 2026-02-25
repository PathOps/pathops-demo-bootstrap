# Repository Export

---

## 📄 .gitignore

```gitignore
pathops-demo-bootstrap.zip
repo_dump.txt

# Local secrets
.env

# Ansible vault files
*.vault.yml
.secrets/

# OS
.DS_Store

############################
# VAGRANT
############################

# Estado local de Vagrant
**/.vagrant/

# Archivos temporales de Vagrant
*.box
*.log

############################
# VIRTUALBOX
############################

# Logs que a veces quedan en el repo
VBox.log
VBox.log.*
*.vdi
*.vmdk

############################
# ANSIBLE
############################

# Archivos generados por ejecución
*.retry

# Vault si usás uno local (opcional)
# group_vars/*/vault.yml

############################
# KUBERNETES / KUBECONFIG
############################

# Configs locales
.kube/
kubeconfig
admin.conf

############################
# DOCKER
############################

# Contextos locales
.docker/

############################
# TERRAFORM (por si lo agregás luego)
############################

.terraform/
*.tfstate
*.tfstate.*
crash.log

############################
# OS
############################

# Linux
*~
*.swp

# Mac
.DS_Store

############################
# IDE
############################

.vscode/
.idea/

############################
# LOGS
############################

*.out
*.err
*.pid

############################
# TEMP / CACHE
############################

tmp/
.cache/

### Vim ###
# Swap
[._]*.s[a-v][a-z]
!*.svg  # comment out if you don't need vector files
[._]*.sw[a-p]
[._]s[a-rt-v][a-z]
[._]ss[a-gi-z]
[._]sw[a-p]

# Session
Session.vim
Sessionx.vim

# Temporary
.netrwhist
*~
# Auto-generated tag files
tags
# Persistent undo
[._]*.un~

```

---

## 📄 Makefile

```Makefile
# make repo-zip
REPO_ZIP=pathops-demo-bootstrap.zip

repo-zip:
	@echo "📦 Creating repository zip..."
	@rm -f $(REPO_ZIP)
	@find . -type f -not -path '*/.*' -print | zip -@ $(REPO_ZIP)
	@echo "✅ Created $(REPO_ZIP)"
	@echo ""

export-chatgpt:
	./scripts/export_repo_for_chatgpt.sh

suspend:
	vagrant suspend

resume:
	vagrant resume

up:
	vagrant up

halt:
	vagrant halt

destroy:
	vagrant destroy -f

provision:
	ansible-playbook -i ansible/inventories/demo/hosts.ini ansible/playbooks/site.yml

upgrade:
	ansible-playbook -i ansible/inventories/demo/hosts.ini ansible/playbooks/90-maintenance-upgrade.yml

apt-fix:
	ansible-playbook -i ansible/inventories/demo/hosts.ini ansible/playbooks/91-maintenance-apt-fix.yml
# -------------------------
# Public Edge Gateway (DO)
# -------------------------

EDGE_DIR=infra/edge-gateway
EDGE_INV=$(EDGE_DIR)/inventories/prod/hosts.ini
EDGE_PLAY=$(EDGE_DIR)/playbooks/00-bootstrap.yml
VAGRANT_BRIDGE_IF=wlxb019218015aa
provision-edge:
	@echo "🌍 Provisioning public edge gateway..."
	@test -f $(EDGE_DIR)/.env || (echo "ERROR: missing $(EDGE_DIR)/.env (copy from .env.template)"; exit 1)
	@set -a; . $(EDGE_DIR)/.env; set +a; \
	test -n "$$EDGE_GATEWAY_IP" || (echo "ERROR: EDGE_GATEWAY_IP missing in .env"; exit 1); \
	test -n "$$LE_EMAIL" || (echo "ERROR: LE_EMAIL missing in .env"; exit 1); \
	EDGE_GATEWAY_IP="$$EDGE_GATEWAY_IP" \
	LE_EMAIL="$$LE_EMAIL" \
	VAGRANT_BRIDGE_IF="$$VAGRANT_BRIDGE_IF" \
	ansible-playbook -i $(EDGE_INV) $(EDGE_PLAY)
	@echo "✅ Done"

```

---

## 📄 README.md

```md
# PathOps Demo Bootstrap

## Multi-tenancy (demo only)

This demo uses virtual clusters (vcluster) to simulate
per-user Kubernetes clusters.

Each user gets:
- one vcluster
- three namespaces: agents, preflight, production

In the real PathOps product, users bring their own clusters.

## Requirements
- VirtualBox
- Vagrant
- Ansible

## Quick Start

cd vagrant
vagrant up

cd ../ansible
ansible-playbook -i inventories/demo/hosts.ini playbooks/site.yml

## Architecture
<!-- TODO: diagram -->

(diagrama simple)

```

---

## 📄 Vagrantfile

```Vagrantfile
# Vagrantfile
require "yaml"

CFG_PATH = File.join(__dir__, "vagrant", "config", "vms.yml")
cfg = YAML.load_file(CFG_PATH)

Vagrant.configure("2") do |config|
  config.ssh.insert_key = false
  config.vm.box = cfg.dig("project", "ubuntu_box") || "bento/ubuntu-24.04"

  cfg["vms"].each do |vm|
    config.vm.define vm["name"] do |node|
      node.vm.hostname = vm["hostname"]

      node.vm.network "private_network",
        ip: vm["ip"],
        virtualbox__intnet: false

      # Bridged/Public SOLO para la VM edge (para que el router la vea)
      if vm["name"] == "vm01-edge"
        bridge_if = ENV["VAGRANT_BRIDGE_IF"] # opcional, recomendado
        if bridge_if && !bridge_if.empty?
          node.vm.network "public_network", bridge: bridge_if, ip: vm["lan_ip"]
        else
          # Si no pasás interfaz, Vagrant te va a preguntar cuál bridge usar
          node.vm.network "public_network", ip: vm["lan_ip"]
        end
      end

      node.vm.provider "virtualbox" do |vb|
        vb.name = vm["name"]
        vb.cpus = vm["cpus"] || 2
        vb.memory = vm["memory"] || 2048
      end

      node.vm.provision "shell", inline: <<-SHELL
        set -euxo pipefail
        sudo apt-get update -y
        sudo apt-get install -y python3 python3-apt ca-certificates curl
        echo "#{vm["hostname"]}" | sudo tee /etc/hostname
      SHELL
    end
  end
end

```

---

## 📄 ansible.cfg

```cfg
[defaults]
vault_password_file = ~/.ansible/pathops_vault_pass

```

---

## 📄 ansible/group_vars/all.yml

```yml
# WireGuard - comunes a todos los peers (VMs)
wg_iface: wg0
wg_network_cidr: "10.10.0.0/24"

# Hub (droplet)
wg_hub_ip: "10.10.0.1"
wg_hub_endpoint: "24.144.86.214:51820"   # <- cambias solo aca cuando migres (Hetzner etc.)
wg_hub_public_key: "exe6sCWMoC8ncqstAuUh8DhKFD7ePInNJKMzNWCjdyY="


```

---

## 📄 ansible/host_vars/vm01-edge.yml

```yml
wg_address: "10.10.0.2/32"

```

---

## 📄 ansible/host_vars/vm01-edge_vault.yml

```yml
$ANSIBLE_VAULT;1.1;AES256
62313062376565316438663663633262623630623332363163656664383764633036636334633237
3438336434633566346235626537353065663231616437610a633566656238613338643064643334
62323637316435393565376561373264373966333830383461306362663963623232386465633333
3366633566356537630a336161316639633139313261643961396238323362623662343338353930
64663439333439366162326262356636343237353834366166316339383366646465656439353035
32343266663337396139316161373934333264373263333739323566373931343263653537346333
643761383163653631363331626337376333

```

---

## 📄 ansible/host_vars/vm02-gitlab.yml

```yml
wg_address: "10.10.0.3/32"

# GitLab CE (Open Source) - PathOps demo
gitlab_host: "gitlab.demo.pathops.io"
gitlab_external_url: "https://gitlab.demo.pathops.io"
gitlab_ssh_host: "gitlab.demo.pathops.io"
gitlab_ssh_port: 22  

```

---

## 📄 ansible/host_vars/vm02-gitlab_vault.yml

```yml
$ANSIBLE_VAULT;1.1;AES256
37376632633339623961656565316236623431316161393363666235373966633630633737636139
3265346434653433316564623966636664333935306332300a346264386666666335653035633631
38313135613433613935623131313965343538383338626239333661393439653438656232646566
3161393166363561660a646636383963613462633636656432356237393762343735303138633536
65386136616366383735663432383937376133623334363631323938303334626337323538316632
39333037643561663930376230366137656638306634623865326333636635373563373734356337
643439666335333632666666373330373364

```

---

## 📄 ansible/host_vars/vm03-jenkins.yml

```yml
wg_address: "10.10.0.4/32"

jenkins_http_port: 8080

```

---

## 📄 ansible/host_vars/vm03-jenkins_vault.yml

```yml
$ANSIBLE_VAULT;1.1;AES256
32613562626138373733363730616162633831613165643065613037623934356334636138626261
3164656463366438666636653061306131383539663530370a616237636135323238633436306635
38633962336361396339623661396432656439613533313561326165393238386434613135623266
3738633362386436380a666436363636373566376466326666623735653061663832663439653330
34343033376232343262313263323338336532313662316565326337386130663762373637616237
35346662396436376362643734376233353039373037376334626334323835316366633035616638
643131626364306138393965333039616261

```

---

## 📄 ansible/host_vars/vm04-k8s-shared.yml

```yml
wg_address: "10.10.0.5/32"

```

---

## 📄 ansible/host_vars/vm04-k8s-shared_vault.yml

```yml
$ANSIBLE_VAULT;1.1;AES256
36303936303861613336316430616631313938363938383864613962646262316531643762353964
3235376536663039653433303962316364303163653738350a353562663433363165333962303535
61363733356539353965303836326539616361366434643637323061663130346537333938343631
3163396664346133310a616531623563653966623133663861353938656230643136373639333431
38346531383561373132663039313330326638636639633839653961646131373439646435356333
63366563393864386632633166366534643366653134636365636663343639613430383537636330
656634633764373363333066383334313464

```

---

## 📄 ansible/host_vars/vm05-k8s-control-plane.yml

```yml
wg_address: "10.10.0.6/32"

```

---

## 📄 ansible/host_vars/vm05-k8s-control-plane_vault.yml

```yml
$ANSIBLE_VAULT;1.1;AES256
37616235393531633135626133383062636562323634363765376131343437383865343336666430
6230663033623031376536616361373366623061396264350a343134666237326132356338306661
36326331313730613634643064653335306131653133636165663764376438343138646564613130
3764313965636262390a653064366234363563366135303661666562333566333139353965306231
61623564366164613761633262653662326666353365333438633163656533353362313534303734
61323539333437633663326530643531366561306233353938643166343963656433343965353030
30353433373636373364393262376461356431353762316665343635353861323266353639653063
32353661396330656266

```

---

## 📄 ansible/host_vars/vm06-k8s-apps.yml

```yml
wg_address: "10.10.0.7/32"

```

---

## 📄 ansible/host_vars/vm06-k8s-apps_vault.yml

```yml
$ANSIBLE_VAULT;1.1;AES256
32613737633666636462323563356239313035653831653161326336313663653336663965346661
3461316534646334663736363461663039313637366361390a393639346539393932666230616161
33623262336336613035313337363266353532623130383735383234386338643838643961356662
6533313830646632300a353037616561346534346436366539643235623337663164666235376438
36383832316335643262373038303562356331306461386266626363643033316135633034373633
63623762643235633037316266666336643237323864333766353637326264396264363833643833
663639633432353637366231616236353734

```

---

## 📄 ansible/inventories/demo/hosts.ini

```ini
[all:vars]
ansible_user=vagrant
ansible_ssh_private_key_file={{ lookup('env','VAGRANT_HOME') }}/insecure_private_key
ansible_python_interpreter=/usr/bin/python3
ansible_ssh_common_args=-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null

[edge]
vm01-edge ansible_host=192.168.56.11

[gitlab]
vm02-gitlab ansible_host=192.168.56.12

[jenkins]
vm03-jenkins ansible_host=192.168.56.13

[k8s_shared]
vm04-k8s-shared ansible_host=192.168.56.14

[k8s_cp]
vm05-k8s-control-plane ansible_host=192.168.56.15

[k8s_apps]
vm06-k8s-apps ansible_host=192.168.56.16

[microk8s:children]
k8s_shared
k8s_cp
k8s_apps

```

---

## 📄 ansible/playbooks/00-base.yml

```yml
---
- name: PathOps - Base System Setup
  hosts: all
  become: true

  vars:
    base_packages:
      - curl
      - wget
      - git
      - unzip
      - htop
      - ca-certificates
      - gnupg
      - lsb-release
      - software-properties-common
      - apt-transport-https

  tasks:

    - name: Update apt cache
      apt:
        update_cache: yes
        cache_valid_time: 3600

    - name: Install base packages
      apt:
        name: "{{ base_packages }}"
        state: present

    - name: Set timezone to UTC
      timezone:
        name: UTC

    - name: Ensure sudo is installed
      apt:
        name: sudo
        state: present

    - name: Create pathops group
      group:
        name: pathops
        state: present

    - name: Create pathops user
      user:
        name: pathops
        group: pathops
        shell: /bin/bash
        create_home: yes

    - name: Add pathops user to sudoers (passwordless)
      copy:
        dest: /etc/sudoers.d/pathops
        content: "pathops ALL=(ALL) NOPASSWD:ALL"
        mode: '0440'

    - name: Disable unattended-upgrades if installed (for demo stability)
      block:
        - name: Check if unattended-upgrades service exists
          command: systemctl list-unit-files unattended-upgrades.service
          register: uu
          changed_when: false
          failed_when: false

        - name: Stop and disable unattended-upgrades
          systemd:
            name: unattended-upgrades
            state: stopped
            enabled: no
          when: uu.rc == 0

    - name: Ensure SSH is enabled
      service:
        name: ssh
        state: started
        enabled: yes

```

---

## 📄 ansible/playbooks/05-edge-routing.yml

```yml
---
- name: PathOps - Edge routing fix (eth2 for WAN replies)
  hosts: edge
  become: true

  vars:
    lan_ip: "192.168.1.90"
    lan_gw: "192.168.1.1"
    lan_dev: "eth2"
    table_id: "100"

  tasks:
    - name: Ensure iproute2 is installed
      apt:
        name: iproute2
        state: present
        update_cache: yes

    - name: Set rp_filter to loose (multi-NIC safe)
      copy:
        dest: /etc/sysctl.d/99-pathops-edge-routing.conf
        content: |
          net.ipv4.conf.all.rp_filter=2
          net.ipv4.conf.default.rp_filter=2
          net.ipv4.conf.{{ lan_dev }}.rp_filter=2
        mode: "0644"

    - name: Apply sysctl
      command: sysctl --system
      changed_when: false

    - name: Install systemd unit to enforce routing on boot
      copy:
        dest: /etc/systemd/system/pathops-edge-routing.service
        mode: "0644"
        content: |
          [Unit]
          Description=PathOps Edge Routing Fix (policy routing for WAN)
          After=network-online.target
          Wants=network-online.target

          [Service]
          Type=oneshot
          RemainAfterExit=yes
          ExecStart=/bin/sh -lc '\
            set -e; \
            ip rule del from {{ lan_ip }}/32 table {{ table_id }} 2>/dev/null || true; \
            ip route flush table {{ table_id }} 2>/dev/null || true; \
            ip rule add from {{ lan_ip }}/32 table {{ table_id }}; \
            ip route add default via {{ lan_gw }} dev {{ lan_dev }} table {{ table_id }}; \
            ip route replace default via {{ lan_gw }} dev {{ lan_dev }} metric 10; \
            ip route replace default via 10.0.2.2 dev eth0 metric 200 2>/dev/null || true; \
            ip route; ip rule; \
          '

          [Install]
          WantedBy=multi-user.target

    - name: Enable and run routing service now
      systemd:
        name: pathops-edge-routing.service
        enabled: yes
        state: started
        daemon_reload: yes

```

---

## 📄 ansible/playbooks/10-edge-nginx.yml

```yml
---
- name: PathOps Demo - Edge Nginx Reverse Proxy (one vhost per file)
  hosts: edge
  become: true

  vars:
    demo_domain: "demo.pathops.io"

    ssl_dir: "/etc/nginx/ssl"
    ssl_key: "{{ ssl_dir }}/{{ demo_domain }}.key"
    ssl_crt: "{{ ssl_dir }}/{{ demo_domain }}.crt"
    ssl_days: 3650  # ~10 años

    health_root: "/var/www/health"

    # Upstreams (host-only IPs)
    upstream_gitlab: "192.168.56.12"
    upstream_jenkins: "192.168.56.13"
    upstream_shared: "192.168.56.14"
    upstream_control_plane: "192.168.56.15"
    upstream_apps: "192.168.56.16"

    nginx_site_dir: "/etc/nginx/sites-available/pathops-demo"
    nginx_enabled_dir: "/etc/nginx/sites-enabled"

  tasks:
    - name: Install nginx and openssl
      apt:
        name:
          - nginx
          - openssl
        state: present
        update_cache: yes

    - name: Ensure directories exist
      file:
        path: "{{ item }}"
        state: directory
        owner: root
        group: root
        mode: "0755"
      loop:
        - "{{ ssl_dir }}"
        - "{{ nginx_site_dir }}"
        - "{{ nginx_enabled_dir }}"
        - "{{ health_root }}"

    - name: Generate self-signed certificate (only if missing)
      command: >
        openssl req -x509 -nodes -newkey rsa:4096
        -keyout {{ ssl_key }}
        -out {{ ssl_crt }}
        -days {{ ssl_days }}
        -subj "/CN={{ demo_domain }}"
        -addext "subjectAltName=DNS:{{ demo_domain }},DNS:*.{{ demo_domain }}"
      args:
        creates: "{{ ssl_crt }}"

    - name: Restrict key permissions
      file:
        path: "{{ ssl_key }}"
        owner: root
        group: root
        mode: "0600"

    - name: Write health page
      copy:
        dest: "{{ health_root }}/index.html"
        owner: root
        group: root
        mode: "0644"
        content: |
          <!doctype html>
          <html>
            <head><meta charset="utf-8"><title>PathOps Demo Edge</title></head>
            <body style="font-family: sans-serif;">
              <h1>✅ PathOps Demo Edge OK</h1>
              <p>You reached <b>health.{{ demo_domain }}</b></p>
              <p>Host: {{ inventory_hostname }}</p>
            </body>
          </html>

    - name: Global tuning (timeouts, buffers, upload size, websocket map)
      copy:
        dest: /etc/nginx/conf.d/00-pathops-tuning.conf
        owner: root
        group: root
        mode: "0644"
        content: |
          # PathOps Demo - global proxy tuning

          # Timeouts
          proxy_connect_timeout 60s;
          proxy_send_timeout    300s;
          proxy_read_timeout    300s;
          send_timeout          300s;

          # Buffers
          proxy_buffering   on;
          proxy_buffers     16 64k;
          proxy_buffer_size 128k;

          # Uploads (default). Override per vhost if needed.
          client_max_body_size 2g;

          # Keep original host/proto/ip
          proxy_set_header Host               $host;
          proxy_set_header X-Real-IP          $remote_addr;
          proxy_set_header X-Forwarded-For    $proxy_add_x_forwarded_for;
          proxy_set_header X-Forwarded-Proto  https;

          # Websockets helper
          map $http_upgrade $connection_upgrade {
            default upgrade;
            ''      close;
          }
      notify: Restart nginx

    - name: 00 - HTTP -> HTTPS redirect (keeps port 80 only for redirect)
      copy:
        dest: "{{ nginx_site_dir }}/00-redirect-http.conf"
        owner: root
        group: root
        mode: "0644"
        content: |
          server {
            listen 80;
            server_name .{{ demo_domain }};
            return 301 https://$host$request_uri;
          }
      notify: Restart nginx

    - name: 10 - Health vhost
      copy:
        dest: "{{ nginx_site_dir }}/10-health.conf"
        owner: root
        group: root
        mode: "0644"
        content: |
          server {
            listen 443 ssl;
            server_name health.{{ demo_domain }};

            ssl_certificate     {{ ssl_crt }};
            ssl_certificate_key {{ ssl_key }};

            location / {
              root {{ health_root }};
              index index.html;
            }
          }
      notify: Restart nginx

    - name: 20 - GitLab vhost
      copy:
        dest: "{{ nginx_site_dir }}/20-gitlab.conf"
        owner: root
        group: root
        mode: "0644"
        content: |
          server {
            listen 443 ssl;
            server_name gitlab.{{ demo_domain }};

            ssl_certificate     {{ ssl_crt }};
            ssl_certificate_key {{ ssl_key }};

            # GitLab can upload big artifacts/LFS/imports
            client_max_body_size 2g;

            # Important proxy headers for GitLab behind reverse proxies
            proxy_set_header Host              $host;
            proxy_set_header X-Real-IP         $remote_addr;
            proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-Forwarded-Ssl   on;

            # Websocket support (GitLab uses it for some features)
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";

            location / {
              proxy_pass http://{{ upstream_gitlab }};
              proxy_request_buffering off;
              proxy_read_timeout 600s;
              proxy_send_timeout 600s;
            }
          }
      notify: Restart nginx

    - name: 30 - Jenkins vhost
      copy:
        dest: "{{ nginx_site_dir }}/30-jenkins.conf"
        owner: root
        group: root
        mode: "0644"
        content: |
          server {
            listen 443 ssl;
            server_name jenkins.{{ demo_domain }};

            ssl_certificate     {{ ssl_crt }};
            ssl_certificate_key {{ ssl_key }};

            client_max_body_size 512m;

            location / {
              proxy_pass http://{{ upstream_jenkins }}:8080;
              proxy_http_version 1.1;
              proxy_set_header Connection "";
              proxy_read_timeout 600s;
              proxy_send_timeout 600s;
            }
          }
      notify: Restart nginx

    - name: 40 - Shared vhosts (keycloak/harbor/minio/loki/grafana/argocd)
      copy:
        dest: "{{ nginx_site_dir }}/40-shared.conf"
        owner: root
        group: root
        mode: "0644"
        content: |
          # Shared services hosted on VM4
          server {
            listen 443 ssl;
            server_name
              keycloak.{{ demo_domain }}
              harbor.{{ demo_domain }}
              minio.{{ demo_domain }}
              loki.{{ demo_domain }}
              grafana.{{ demo_domain }}
              argocd.{{ demo_domain }};

            ssl_certificate     {{ ssl_crt }};
            ssl_certificate_key {{ ssl_key }};

            # Harbor/MinIO often need huge uploads. Use unlimited for demo.
            # If you prefer limits: set e.g. 20g instead of 0.
            client_max_body_size 0;

            location / {
              proxy_pass http://{{ upstream_shared }};
              proxy_http_version 1.1;

              # Websockets (Grafana/Argo)
              proxy_set_header Upgrade $http_upgrade;
              proxy_set_header Connection $connection_upgrade;

              # Large uploads
              proxy_request_buffering off;

              proxy_read_timeout 900s;
              proxy_send_timeout 900s;
            }
          }
      notify: Restart nginx

    - name: 50 - Control Plane vhost
      copy:
        dest: "{{ nginx_site_dir }}/50-control-plane.conf"
        owner: root
        group: root
        mode: "0644"
        content: |
          server {
            listen 443 ssl;
            server_name control-plane.{{ demo_domain }};

            ssl_certificate     {{ ssl_crt }};
            ssl_certificate_key {{ ssl_key }};

            client_max_body_size 128m;

            location / {
              proxy_pass http://{{ upstream_control_plane }};
              proxy_read_timeout 300s;
              proxy_send_timeout 300s;
            }
          }
      notify: Restart nginx

    - name: 99 - Wildcard apps vhost (keep last)
      copy:
        dest: "{{ nginx_site_dir }}/99-wildcard-apps.conf"
        owner: root
        group: root
        mode: "0644"
        content: |
          server {
            listen 443 ssl;
            server_name *.{{ demo_domain }};

            ssl_certificate     {{ ssl_crt }};
            ssl_certificate_key {{ ssl_key }};

            client_max_body_size 256m;

            location / {
              proxy_pass http://{{ upstream_apps }};
              proxy_read_timeout 300s;
              proxy_send_timeout 300s;
            }
          }
      notify: Restart nginx

    - name: Enable vhosts (symlink all)
      file:
        src: "{{ nginx_site_dir }}/{{ item }}"
        dest: "{{ nginx_enabled_dir }}/{{ item }}"       
        state: link
        force: true
      loop:
        - 00-redirect-http.conf
        - 10-health.conf
        - 20-gitlab.conf
        - 30-jenkins.conf
        - 40-shared.conf
        - 50-control-plane.conf
        - 99-wildcard-apps.conf

    - name: Disable default site if present
      file:
        path: /etc/nginx/sites-enabled/default
        state: absent
      ignore_errors: yes

    - name: Validate nginx config
      command: nginx -t
      changed_when: false

  handlers:
    - name: Restart nginx
      service:
        name: nginx
        state: restarted
        enabled: yes


```

---

## 📄 ansible/playbooks/20-wireguard.yml

```yml
---
- name: Configure WireGuard peers (LAN VMs)
  hosts: all
  become: true

  vars_files:
    - ../group_vars/all.yml
    - ../host_vars/{{ inventory_hostname }}.yml
    - ../host_vars/{{ inventory_hostname }}_vault.yml

  roles:
    - wireguard

```

---

## 📄 ansible/playbooks/25-gitlab.yml

```yml
---
- name: Install and configure GitLab CE (Open Source)
  hosts: gitlab
  become: true

  vars_files:
    - ../group_vars/all.yml
    - ../host_vars/{{ inventory_hostname }}.yml
    - ../host_vars/{{ inventory_hostname }}_vault.yml

  roles:
    - gitlab

```

---

## 📄 ansible/playbooks/90-maintenance-upgrade.yml

```yml
---
- name: Maintenance - OS upgrade (dist-upgrade) + reboot if needed
  hosts: all
  become: true
  gather_facts: true

  vars:
    maintenance_reboot_if_required: true

  tasks:
    - name: Wait for any unattended/dpkg locks to clear (best effort)
      shell: |
        set -e
        for i in $(seq 1 30); do
          if fuser /var/lib/dpkg/lock >/dev/null 2>&1; then
            sleep 2
            continue
          fi
          if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then
            sleep 2
            continue
          fi
          exit 0
        done
        exit 0
      args:
        executable: /bin/bash
      changed_when: false

    - name: Update apt cache
      apt:
        update_cache: yes
      register: apt_update
      retries: 6
      delay: 10
      until: apt_update is succeeded

    - name: Dist-upgrade packages
      apt:
        upgrade: dist
      register: apt_upgrade
      retries: 3
      delay: 20
      until: apt_upgrade is succeeded

    - name: Autoremove unused packages
      apt:
        autoremove: yes

    - name: Check if reboot is required
      stat:
        path: /var/run/reboot-required
      register: reboot_required

    - name: Reboot if required (maintenance mode)
      reboot:
        msg: "Reboot initiated by PathOps maintenance upgrade playbook"
        reboot_timeout: 900
      when: maintenance_reboot_if_required and reboot_required.stat.exists

    - name: Verify system is back
      wait_for_connection:
        timeout: 300
```

---

## 📄 ansible/playbooks/91-maintenance-apt-fix.yml

```yml
---
- name: Maintenance - Fix apt/dpkg broken state
  hosts: all
  become: true
  gather_facts: false

  tasks:
    - name: Stop unattended-upgrades (if running)
      systemd:
        name: unattended-upgrades
        state: stopped
        enabled: no
      failed_when: false

    - name: Kill stuck apt/dpkg processes (best effort)
      shell: |
        pkill -9 apt || true
        pkill -9 apt-get || true
        pkill -9 dpkg || true
      changed_when: false

    - name: Remove apt/dpkg locks (best effort)
      file:
        path: "{{ item }}"
        state: absent
      loop:
        - /var/lib/dpkg/lock-frontend
        - /var/lib/dpkg/lock
        - /var/cache/apt/archives/lock
      failed_when: false

    - name: Reconfigure dpkg
      command: dpkg --configure -a
      register: dpkg_reconf
      failed_when: false

    - name: Fix broken dependencies
      apt:
        update_cache: yes
        force_apt_get: yes
        state: present
      failed_when: false

    - name: Apt autoremove
      apt:
        autoremove: yes
      failed_when: false

    - name: Verify apt works
      command: apt-get update
      register: apt_verify
      retries: 3
      delay: 10
      until: apt_verify is succeeded
```

---

## 📄 ansible/playbooks/roles/gitlab/handlers/main.yml

```yml
---
- name: Reconfigure GitLab
  ansible.builtin.command: gitlab-ctl reconfigure

```

---

## 📄 ansible/playbooks/roles/gitlab/tasks/main.yml

```yml
---
- name: Ensure base dependencies are installed
  ansible.builtin.apt:
    name:
      - curl
      - openssh-server
      - ca-certificates
      - tzdata
      - perl
    state: present
    update_cache: true

- name: Add GitLab package repository (packagecloud script)
  ansible.builtin.shell: |
    set -euo pipefail
    curl -fsSL https://packages.gitlab.com/install/repositories/gitlab/gitlab-ce/script.deb.sh | bash
  args:
    executable: /bin/bash
    creates: /etc/apt/sources.list.d/gitlab_gitlab-ce.list

- name: Install GitLab CE
  ansible.builtin.apt:
    name: gitlab-ce
    state: present
    update_cache: true
  environment:
    EXTERNAL_URL: "{{ gitlab_external_url }}"

- name: Render /etc/gitlab/gitlab.rb
  ansible.builtin.template:
    src: gitlab.rb.j2
    dest: /etc/gitlab/gitlab.rb
    owner: root
    group: root
    mode: "0644"
  notify: Reconfigure GitLab

- name: Ensure GitLab is running
  ansible.builtin.command: gitlab-ctl status
  register: gitlab_status
  changed_when: false
  failed_when: gitlab_status.rc != 0

- name: Print how to retrieve initial root password (if needed)
  ansible.builtin.debug:
    msg:
      - "If this is the first install, GitLab writes the initial root password to:"
      - "  sudo cat /etc/gitlab/initial_root_password"

```

---

## 📄 ansible/playbooks/roles/gitlab/templates/gitlab.rb.j2

```j2
## Managed by Ansible (PathOps)
external_url '{{ gitlab_external_url }}'

# Keep resource usage reasonable for demo VMs.
puma['worker_processes'] = {{ gitlab_puma_worker_processes | default(0) }}
sidekiq['max_concurrency'] = {{ gitlab_sidekiq_max_concurrency | default(10) }}

# Optional: If you are fronting GitLab with a reverse proxy (edge/haproxy/nginx),
# you may want to set these so clone URLs render correctly.
gitlab_rails['gitlab_host'] = '{{ gitlab_host }}'
gitlab_rails['gitlab_ssh_host'] = '{{ gitlab_ssh_host }}'
gitlab_rails['gitlab_shell_ssh_port'] = {{ gitlab_ssh_port }}

# Disable Registry by default (can enable later for PathOps artifacts/images).
registry['enable'] = {{ gitlab_registry_enable | default(false) | lower }}

# NGINX inside GitLab (disable only if you terminate HTTP elsewhere)
nginx['listen_port'] = {{ gitlab_http_listen_port | default(80) }}
nginx['listen_https'] = {{ gitlab_https_enable | default(false) | lower }}

```

---

## 📄 ansible/playbooks/roles/wireguard/tasks/main.yml

```yml
---
- name: Install WireGuard
  apt:
    name: wireguard
    state: present
    update_cache: yes

- name: Ensure wireguard directory exists
  file:
    path: /etc/wireguard
    state: directory
    mode: "0700"

- name: Deploy wg0.conf
  template:
    src: wg0.conf.j2
    dest: /etc/wireguard/wg0.conf
    mode: "0600"

- name: Enable and start WireGuard
  systemd:
    name: wg-quick@wg0
    enabled: yes
    state: restarted
```

---

## 📄 ansible/playbooks/roles/wireguard/templates/wg0.conf.j2

```j2
[Interface]
PrivateKey = {{ wg_private_key }}
Address = {{ wg_address }}

[Peer]
PublicKey = {{ wg_hub_public_key }}
Endpoint = {{ wg_hub_endpoint }}
AllowedIPs = 10.10.0.0/24
PersistentKeepalive = 25
```

---

## 📄 ansible/playbooks/site.yml

```yml
# ansible/playbooks/site.yml
- import_playbook: 00-base.yml
- import_playbook: 05-edge-routing.yml
- import_playbook: 10-edge-nginx.yml
- import_playbook: 25-gitlab.yml
- import_playbook: 30-jenkins-docker.yml
#- import_playbook: 40-microk8s.yml
#- import_playbook: 50-k8s-shared.yml
#- import_playbook: 60-k8s-controlplane.yml
#- import_playbook: 70-k8s-apps.yml
#- import_playbook: 99-verify.yml

```

---

## 📄 infra/edge-gateway/.env.template

```template
# Public Edge Gateway (DigitalOcean) - local env (TEMPLATE)
# Copy to .env and fill real values.

EDGE_GATEWAY_IP=203.0.113.10
LE_EMAIL=you@example.com
DDNS_HOSTNAME="example.ddns.net" 

```

---

## 📄 infra/edge-gateway/group_vars/edge_gateway.yml

```yml
domain_apex: "demo.pathops.io"
domain_wildcard: "*.demo.pathops.io"

# Edge Backend
backend_host: "10.10.0.2"
backend_scheme: "https"
backend_port: 443
backend_tls_insecure: true

# Email Let's Encrypt
letsencrypt_email: "{{ lookup('env','LE_EMAIL') }}"

# Firewall
ufw_allowed_ports:
  - 2222
  - 22
  - 80
  - 443

# WireGroup    
wg_iface: wg0
wg_port: 51820
wg_hub_address: "10.10.0.1/24"

# Peers (solo public keys + allowed IPs)
wg_peers:
  - name: vm01-edge
    public_key: "wlGQuL2mGcpIKt9aZDJLPHNqwg9Ds2xjV2x2y2nR7wM="
    allowed_ip: "10.10.0.2/32"
  - name: vm02-gitlab
    public_key: "+N1VqZRv/Hhy0MbQJyuVlWWWYZ5EWFrcB055p0RKR2s="
    allowed_ip: "10.10.0.3/32"
  - name: vm03-jenkins
    public_key: "b32lFqvKJ6vQSyjS2GjPf8+Vyov4xqBs1nPggG+KjXU="
    allowed_ip: "10.10.0.4/32"
  - name: vm04-k8s-shared
    public_key: "apDVG064QnstHqRe+w4IOUZrAwugkvBivqwEo6y1CD0="
    allowed_ip: "10.10.0.5/32"
  - name: vm05-k8s-control-plane
    public_key: "jAIZigbZj+Uje+qR2xAynU8ghaPfS6UPrMIkzFYmtBw="
    allowed_ip: "10.10.0.6/32"
  - name: vm06-k8s-apps
    public_key: "6OSaB/f0jgrtGQkFYzp7VxtvngcqdRLUiLbJp4Sw9Tc="
    allowed_ip: "10.10.0.7/32"

```

---

## 📄 infra/edge-gateway/group_vars/edge_gateway_vault.yml

```yml
$ANSIBLE_VAULT;1.1;AES256
61386336376263653664333864376434343561346262303039353334316164613033303333396131
3466386139313766633135643632663534656665306234370a633232393831636166383630343739
34386437636432646232386530346139633134373362663431396633336537366630306130373330
3234383061343166640a306234316332663161363530353662656236346665633734376663323036
62623130656366643766363631303635613734663936323836326138613464386330623034653134
32316632336363613831303466396438613436646433616337666531373865396366376635386463
32386533383732626433336339363164383733616136663864623337626636343764353366653031
62346331646666343430613862373034386131356362353533343365393233646265653361353939
33386531613431376662636665643735333935343764356436373235666139633236343565313332
33343838623737316261633335343231623432386234376330366438303539366562633062653930
30353864383464623435643666646633373962363661373235616630313633333031643465396136
66333037613063363731

```

---

## 📄 infra/edge-gateway/inventories/prod/hosts.ini

```ini
[edge_gateway]
pathops-edge

[edge_gateway:vars]
ansible_port=2222
ansible_user=pathops
ansible_python_interpreter=/usr/bin/python3

```

---

## 📄 infra/edge-gateway/playbooks/00-bootstrap.yml

```yml
---
- import_playbook: 10-ssh.yml
- import_playbook: 20-wireguard.yml
- import_playbook: 30-base.yml
- import_playbook: 31-certbot.yml
- import_playbook: 32-nginx.yml
- import_playbook: 40-haproxy-gitlab-ssh.yml
- import_playbook: 99-verify.yml
```

---

## 📄 infra/edge-gateway/playbooks/10-ssh.yml

```yml
- name: Droplet - enable SSH on 2222 ONLY (free 22 for GitLab SSH passthrough)
  hosts: edge_gateway
  become: true
  gather_facts: true
  serial: 1

  vars:
    admin_ssh_port: 2222

  tasks:
    - name: Ensure sshd_config.d exists
      file:
        path: /etc/ssh/sshd_config.d
        state: directory
        mode: "0755"

    - name: Configure SSH to listen only on admin port (2222)
      copy:
        dest: /etc/ssh/sshd_config.d/20-pathops-admin-port.conf
        mode: "0644"
        content: |
          Port {{ admin_ssh_port }}
      notify: Restart SSH

    - name: Validate sshd config
      command: sshd -t
      changed_when: false

    - name: Allow admin SSH port in UFW (if ufw installed)
      command: ufw allow {{ admin_ssh_port }}/tcp
      register: ufw_allow
      failed_when: false
      changed_when: "'Rules updated' in ufw_allow.stdout or 'Rule added' in ufw_allow.stdout"

  handlers:
    - name: Restart SSH
      service:
        name: ssh
        state: restarted
```

---

## 📄 infra/edge-gateway/playbooks/20-wireguard.yml

```yml
---
- name: Configure WireGuard hub (droplet)
  hosts: edge_gateway
  become: true
  
  vars_files:
    - ../group_vars/edge_gateway.yml
    - ../group_vars/edge_gateway_vault.yml
  
  vars:
    wg_port: 51820

  tasks:
    - name: Install WireGuard
      apt:
        name: wireguard
        state: present
        update_cache: yes

    - name: Ensure wireguard directory exists
      file:
        path: /etc/wireguard
        state: directory
        mode: "0700"

    - name: Deploy hub wg0.conf
      copy:
        dest: /etc/wireguard/wg0.conf
        mode: "0600"
        content: |
          [Interface]
          PrivateKey = {{ wg_private_key }}
          Address = 10.10.0.1/24
          ListenPort = {{ wg_port }}

          {% for peer in wg_peers %}
          [Peer]
          PublicKey = {{ peer.public_key }}
          AllowedIPs = {{ peer.allowed_ip }}
          {% endfor %}

    - name: Enable IP forwarding
      sysctl:
        name: net.ipv4.ip_forward
        value: 1
        state: present
        reload: yes

    - name: Allow WireGuard UDP port in UFW
      ufw:
        rule: allow
        port: "{{ wg_port }}"
        proto: udp

    - name: Enable and start WireGuard
      systemd:
        name: wg-quick@wg0
        enabled: yes
        state: started
```

---

## 📄 infra/edge-gateway/playbooks/30-base.yml

```yml
---
- name: Edge Gateway - Base (packages + ufw)
  hosts: edge_gateway
  become: true

  vars_files:
    - ../group_vars/edge_gateway.yml
    - ../group_vars/edge_gateway_vault.yml

  tasks:
    - name: Ensure apt cache updated
      apt:
        update_cache: yes
        cache_valid_time: 3600

    - name: Install required packages
      apt:
        name:
          - nginx
          - ufw
          - certbot
          - python3-certbot-dns-digitalocean
          - haproxy
        state: present

    - name: Enable UFW (default deny)
      ufw:
        state: enabled
        policy: deny

    - name: Allow required ports
      ufw:
        rule: allow
        port: "{{ item }}"
      loop: "{{ ufw_allowed_ports }}"
```

---

## 📄 infra/edge-gateway/playbooks/30-haproxy-gitlab-ssh.yml

```yml
---
- name: Droplet - HAProxy TCP passthrough for GitLab SSH (22 -> vm02-gitlab:22 over WireGuard)
  hosts: edge_gateway
  become: true

  vars_files:
    - ../group_vars/edge_gateway.yml
    - ../group_vars/edge_gateway_vault.yml

  vars:
    gitlab_wg_ip: "10.10.0.3"
    gitlab_ssh_port: 22

  tasks:
    - name: Install HAProxy
      apt:
        name: haproxy
        state: present
        update_cache: yes

    - name: Write HAProxy config (TCP 22 -> GitLab over WG)
      copy:
        dest: /etc/haproxy/haproxy.cfg
        mode: "0644"
        content: |
          global
            log /dev/log local0
            log /dev/log local1 notice
            daemon
            maxconn 2048

          defaults
            log global
            mode tcp
            option tcplog
            timeout connect 10s
            timeout client  1h
            timeout server  1h

          frontend ssh_gitlab_in
            bind *:22
            default_backend ssh_gitlab_out

          backend ssh_gitlab_out
            server gitlab {{ gitlab_wg_ip }}:{{ gitlab_ssh_port }} check
      notify: Restart haproxy

    - name: Ensure HAProxy enabled and started
      systemd:
        name: haproxy
        enabled: yes
        state: started

  handlers:
    - name: Restart haproxy
      service:
        name: haproxy
        state: restarted
```

---

## 📄 infra/edge-gateway/playbooks/31-certbot.yml

```yml
---
- name: Edge Gateway - Certbot wildcard (DNS-01)
  hosts: edge_gateway
  become: true

  vars_files:
    - ../group_vars/edge_gateway.yml
    - ../group_vars/edge_gateway_vault.yml

  vars:
    cert_name: "{{ domain_apex }}"
    le_live_dir: "/etc/letsencrypt/live/{{ cert_name }}"
    do_creds_path: "/root/.secrets/certbot/digitalocean.ini"

  tasks:
    - name: Create certbot secrets dir
      file:
        path: "{{ do_creds_path | dirname }}"
        state: directory
        mode: "0700"

    - name: Write DigitalOcean DNS token for certbot
      copy:
        dest: "{{ do_creds_path }}"
        mode: "0600"
        content: |
          dns_digitalocean_token = {{ do_dns_token }}

    - name: Obtain or renew wildcard certificate (keep until expiring)
      command: >
        certbot certonly
        --cert-name {{ domain_apex }}
        --non-interactive --agree-tos
        --email {{ letsencrypt_email }}
        --dns-digitalocean
        --dns-digitalocean-credentials {{ do_creds_path }}
        -d {{ domain_apex }}
        -d {{ domain_wildcard }}
        --keep-until-expiring
      register: certbot_out
      changed_when: "'Congratulations' in certbot_out.stdout"
      failed_when: certbot_out.rc != 0

    - name: Ensure certbot auto-renew timer enabled
      systemd:
        name: certbot.timer
        enabled: yes
        state: started

    - name: Add renewal hook to reload nginx
      copy:
        dest: /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
        mode: "0755"
        content: |
          #!/bin/bash
          systemctl reload nginx
```

---

## 📄 infra/edge-gateway/playbooks/32-nginx.yml

```yml
---
- name: Edge Gateway - NGINX (TLS + reverse proxy)
  hosts: edge_gateway
  become: true

  vars_files:
    - ../group_vars/edge_gateway.yml
    - ../group_vars/edge_gateway_vault.yml

  vars:
    cert_name: "{{ domain_apex }}"
    le_live_dir: "/etc/letsencrypt/live/{{ cert_name }}"

  tasks:
    - name: Install nginx gateway config
      copy:
        dest: /etc/nginx/sites-available/pathops-edge.conf
        mode: "0644"
        content: |
          server {
            listen 80;
            server_name {{ domain_apex }} *.{{ domain_apex }};
            return 301 https://$host$request_uri;
          }

          server {
              listen 443 ssl http2;
              server_name edge.{{ domain_apex }};

              ssl_certificate     {{ le_live_dir }}/fullchain.pem;
              ssl_certificate_key {{ le_live_dir }}/privkey.pem;

              ssl_protocols TLSv1.2 TLSv1.3;

              location / {
                  default_type text/plain;
                  return 200 "PathOps Public Edge Gateway OK\n";
              }
          }

          server {
            listen 443 ssl http2;
            server_name {{ domain_apex }} *.{{ domain_apex }};

            ssl_certificate     {{ le_live_dir }}/fullchain.pem;
            ssl_certificate_key {{ le_live_dir }}/privkey.pem;

            ssl_protocols TLSv1.2 TLSv1.3;

            add_header Strict-Transport-Security "max-age=31536000" always;

            client_max_body_size 0;

            proxy_set_header Host              $host;
            proxy_set_header X-Real-IP         $remote_addr;
            proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;

            proxy_connect_timeout 60s;
            proxy_read_timeout    600s;
            proxy_send_timeout    600s;

            proxy_http_version 1.1;
            proxy_set_header Upgrade    $http_upgrade;
            proxy_set_header Connection "upgrade";

            location / {
              set $backend "{{ backend_host }}";
              proxy_pass {{ backend_scheme }}://$backend:{{ backend_port }};
              
              {% if backend_tls_insecure %}
              proxy_ssl_server_name on;
              proxy_ssl_verify off;
              {% endif %}
            }
          }
      notify: Reload nginx

    - name: Enable nginx site
      file:
        src: /etc/nginx/sites-available/pathops-edge.conf
        dest: /etc/nginx/sites-enabled/pathops-edge.conf
        state: link
        force: yes

    - name: Disable default nginx site
      file:
        path: /etc/nginx/sites-enabled/default
        state: absent
      ignore_errors: yes

    - name: Validate nginx config
      command: nginx -t
      changed_when: false

    - name: Ensure nginx enabled and started
      systemd:
        name: nginx
        enabled: yes
        state: started

  handlers:
    - name: Reload nginx
      service:
        name: nginx
        state: reloaded
```

---

## 📄 infra/edge-gateway/playbooks/40-haproxy-gitlab-ssh.yml

```yml
---
- name: Edge Gateway - HAProxy TCP passthrough for GitLab SSH (22 -> vm02-gitlab:22 over WireGuard)
  hosts: edge_gateway
  become: true

  vars_files:
    - ../group_vars/edge_gateway.yml
    - ../group_vars/edge_gateway_vault.yml

  vars:
    gitlab_wg_ip: "10.10.0.3"
    gitlab_ssh_port: 22

  tasks:
    - name: Configure HAProxy (TCP 22 -> GitLab over WG)
      copy:
        dest: /etc/haproxy/haproxy.cfg
        mode: "0644"
        content: |
          global
            log /dev/log local0
            log /dev/log local1 notice
            daemon
            maxconn 2048

          defaults
            log global
            mode tcp
            option tcplog
            timeout connect 10s
            timeout client  1h
            timeout server  1h

          frontend ssh_gitlab_in
            bind *:22
            default_backend ssh_gitlab_out

          backend ssh_gitlab_out
            server gitlab {{ gitlab_wg_ip }}:{{ gitlab_ssh_port }} check
      notify: Restart haproxy

    - name: Ensure HAProxy enabled and started
      systemd:
        name: haproxy
        enabled: yes
        state: started

  handlers:
    - name: Restart haproxy
      service:
        name: haproxy
        state: restarted
```

---

## 📄 infra/edge-gateway/playbooks/99-verify.yml

```yml
---
- name: Verify - Edge Gateway (on droplet)
  hosts: edge_gateway
  become: true

  vars_files:
    - ../group_vars/edge_gateway.yml
    - ../group_vars/edge_gateway_vault.yml

  vars:
    gitlab_wg_ip: "10.10.0.3"
    public_gitlab_host: "gitlab.{{ domain_apex }}"

  tasks:
    - name: Services running (nginx, haproxy)
      command: systemctl is-active {{ item }}
      loop:
        - nginx
        - haproxy
      register: svc
      changed_when: false
      failed_when: svc.rc != 0

    - name: Ports listening on droplet (22, 2222, 80, 443)
      shell: |
        ss -lnt | awk '{print $4}' | egrep ':(22|2222|80|443)$' >/dev/null
      args:
        executable: /bin/bash
      changed_when: false

    - name: WireGuard up
      command: wg show
      changed_when: false

    - name: GitLab reachable via WireGuard TCP/22
      wait_for:
        host: "{{ gitlab_wg_ip }}"
        port: 22
        timeout: 5

    - name: HTTPS endpoint responds (TLS ok) from droplet
      shell: |
        curl -skI https://{{ public_gitlab_host }} | head -n 1 | egrep 'HTTP/(1.1|2) (200|301|302|401|403)'
      args:
        executable: /bin/bash
      changed_when: false

- name: Verify - External (from controller)
  hosts: edge_gateway
  gather_facts: false

  vars_files:
    - ../group_vars/edge_gateway.yml

  vars:
    public_gitlab_host: "gitlab.{{ domain_apex }}"

  tasks:
    - name: Public HTTPS reachable from controller
      wait_for:
        host: "{{ public_gitlab_host }}"
        port: 443
        timeout: 10
      delegate_to: localhost

    - name: Public SSH reachable from controller
      wait_for:
        host: "{{ public_gitlab_host }}"
        port: 22
        timeout: 10
      delegate_to: localhost
```

---

## 📄 vagrant/config/vms.yml

```yml
# vagrant/config/vms.yml
project:
  name: pathops-demo
  ubuntu_box: "bento/ubuntu-24.04"   # podés cambiarlo por ubuntu/jammy64 si preferís
  hostonly_network: "vboxnet0"
  ip_cidr: "192.168.56.0/21"
  gateway: "192.168.56.1"   # opcional: no es necesario si no seteás ruta default en las VMs
  nameservers: ["1.1.1.1", "8.8.8.8"]

vms:
  - name: vm01-edge
    hostname: edge
    ip: 192.168.56.11
    lan_ip: 192.168.1.90
    cpus: 1
    memory: 1024
    disk_gb: 20 
    roles: ["edge"]

  - name: vm02-gitlab
    hostname: gitlab
    ip: 192.168.56.12
    cpus: 2
    memory: 4096
    disk_gb: 80
    roles: ["gitlab"]

  - name: vm03-jenkins
    hostname: jenkins
    ip: 192.168.56.13
    cpus: 2
    memory: 4096
    disk_gb: 60
    roles: ["jenkins", "docker"]

  - name: vm04-k8s-shared
    hostname: k8s-shared
    ip: 192.168.56.14
    cpus: 4
    memory: 16384
    disk_gb: 200
    roles: ["k8s_shared", "microk8s"]

  - name: vm05-k8s-control-plane
    hostname: k8s-cp
    ip: 192.168.56.15
    cpus: 2
    memory: 4096
    disk_gb: 60
    roles: ["k8s_cp", "microk8s"]

  - name: vm06-k8s-apps
    hostname: k8s-apps
    ip: 192.168.56.16
    cpus: 4
    memory: 16384
    disk_gb: 100
    roles: ["k8s_apps", "microk8s", "observability"]

```

