# make repo-zip
REPO_ZIP=pathops-demo-bootstrap.zip

repo-zip:
	@echo "📦 Creating repository zip..."
	@rm -f $(REPO_ZIP)
	@find . -type f -not -path '*/.*' -print | zip -@ $(REPO_ZIP)
	@echo "✅ Created $(REPO_ZIP)"
	@echo ""

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
