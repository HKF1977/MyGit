#!/bin/bash

apt-get update

apt-get install -y openvpn

wait_for_api () {
   while :
     do
     apistatus=`curl -k -X GET -u api:vnscubed https://10.10.10.10:8000/api/config 2>&1`
        echo $apistatus | grep "refused"
          if [ $? != 0 ] ; then
            break
          fi
         sleep 2
     done
 }

wait_for_api

curl -k -X GET -H 'Content-Type: application/json' -d '{"name":"100_127_255_193","format":"conf"}' https://api:vnscubed@10.10.10.10:8000/api/clientpack -o clientpack.conf

mv clientpack.conf /etc/openvpn

systemctl start openvpn@clientpack.service
