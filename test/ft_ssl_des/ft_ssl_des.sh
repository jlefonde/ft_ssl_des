#!/bin/bash

declare -g files=( "0B" "1B" "2B" "3B" "4B" "5B" "15B" "16B" "17B" "32B" "64B" "1KB" "4KB" "64KB" "1MB" "10MB" )

> ./ft_ssl_des/ft_ssl_des.bats

cat ./ft_ssl_des/setup.bats >> ./ft_ssl_des/ft_ssl_des.bats
echo >> ./ft_ssl_des/ft_ssl_des.bats

echo -n "declare -g files=( " >> ./ft_ssl_des/ft_ssl_des.bats
for file in "${files[@]}"; do
    echo -n "\"$file\" " >> ./ft_ssl_des/ft_ssl_des.bats
done
echo ")" >> ./ft_ssl_des/ft_ssl_des.bats
echo >> ./ft_ssl_des/ft_ssl_des.bats

echo "# bats file_tags=base64,encode" >> ./ft_ssl_des/ft_ssl_des.bats
for file in "${files[@]}"; do
    echo >> ./ft_ssl_des/ft_ssl_des.bats
    export FILE="$file"
    export FT_SSL_OUT="ft_ssl_base64_${file}_enc"
    export BASE64_OUT="base64_${file}_enc"
    envsubst '${FILE} ${FT_SSL_OUT} ${BASE64_OUT}' < ./ft_ssl_des/base64_encode_test.template >> ./ft_ssl_des/ft_ssl_des.bats
done
echo >> ./ft_ssl_des/ft_ssl_des.bats
echo "# bats file_tags=base64,decode" >> ./ft_ssl_des/ft_ssl_des.bats
for file in "${files[@]}"; do
    echo >> ./ft_ssl_des/ft_ssl_des.bats
    export FILE="$file"
    export FT_SSL_OUT="ft_ssl_base64_${file}_dec"
    export BASE64_OUT="base64_${file}_dec"
    envsubst '${FILE} ${FT_SSL_OUT} ${BASE64_OUT}' < ./ft_ssl_des/base64_decode_test.template >> ./ft_ssl_des/ft_ssl_des.bats
done
echo >> ./ft_ssl_des/ft_ssl_des.bats

cat ./ft_ssl_des/base64_decode.bats >> ./ft_ssl_des/ft_ssl_des.bats
