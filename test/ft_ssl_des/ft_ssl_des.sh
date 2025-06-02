#!/bin/bash

declare -g files=( "0B" "1B" "56B" "57B" "63B" "64B" "65B" "100B" "128B" "10MB" )

> ./ft_ssl_des/ft_ssl_des.bats

cat ./ft_ssl_des/setup.bats >> ./ft_ssl_des/ft_ssl_des.bats
echo >> ./ft_ssl_des/ft_ssl_des.bats

echo -n "declare -g files=( " >> ./ft_ssl_des/ft_ssl_des.bats
for file in "${files[@]}"; do
    echo -n "\"$file\" " >> ./ft_ssl_des/ft_ssl_des.bats
done
echo ")" >> ./ft_ssl_des/ft_ssl_des.bats
echo >> ./ft_ssl_des/ft_ssl_des.bats

cat ./ft_ssl_des/base64.bats >> ./ft_ssl_des/ft_ssl_des.bats
echo >> ./ft_ssl_des/ft_ssl_des.bats

for file in "${files[@]}"; do
    echo >> ./ft_ssl_des/ft_ssl_des.bats
    export FILE="$file"
    envsubst '${FILE}' < ./ft_ssl_des/base64_encode_test.template >> ./ft_ssl_des/ft_ssl_des.bats
done
