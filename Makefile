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
	cd ansible && ansible-playbook -i inventories/demo/hosts.ini playbooks/site.yml
