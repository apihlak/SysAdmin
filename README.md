Ansible Version :shipit:

```
sudo apt-get remove ansible
sudo pip install -I ansible==2.3.1.0
sudo pip install simplejson
sudo pip3 install -I container-transform
sudo ln -s -v /usr/local/bin/ansible-playbook /usr/bin/ansible-playbook
./do_common.yml -i inventory.bc -l bc-bitcasino-sitemap-server --tags taskdef -e update_service=1 -vv
```

Essential

```
apt install git awscli docker-compose jq build-essential python-pip python-netaddr python-boto python-boto3 python-dns
```

Querying CloudWatch logs

```
pip install awslogs
```
