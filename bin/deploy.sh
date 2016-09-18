#!/bin/bash

set -ex

cd $(dirname $0)/..

git pull

sudo cp etc/nginx.conf /etc/nginx/nginx.conf
cd ruby
bundle install

sudo /bin/sh -c '> /var/log/nginx/access.log'
sudo systemctl restart nginx
sudo systemctl restart isuda.ruby
sudo systemctl restart isutar.ruby
