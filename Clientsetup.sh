#!/bin/bash

apt-get update

apt-get install -y openvpn

curl -k -X GET -H 'Content-Type: application/json' -d '{"name":"100_127_255_193","format":"conf"}' https://api:vnscubed@10.10.10.5:8000/api/clientpack -o clientpack.conf

mv clientpack.conf /etc/openvpn

systemctl start openvpn@clientpack.service
