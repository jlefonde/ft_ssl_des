#!/bin/bash

key=5C21918AC1BBEC44
key2=AABBCCDDEEFF
salt=86A2185F6B1DE243
iv=A4B7397EACE23C39
pass=verysecure

declare -g files=( "0B" "1B" "2B" "3B" "4B" "32B" "64B" "1KB" "4KB" "64KB" "1MB" )
declare -g commands=( "des-ecb" "des-cbc" )

ft_ssl_flags=(
    "-p $pass -s $salt"
    "-k $key -v $iv"
    "-p $pass -s $salt -v $iv"
)

openssl_flags=()
for flag in "${ft_ssl_flags[@]}"; do
    openssl_flag="$flag"
    openssl_flag="${openssl_flag//-p /-pass pass:}"
    openssl_flag="${openssl_flag//-s /-S }"
    openssl_flag="${openssl_flag//-k /-K }"
    openssl_flag="${openssl_flag//-v /-iv }"
    openssl_flags+=("$openssl_flag")
done

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
    export FT_SSL_OUT="out/ft_ssl_base64_${file}_enc"
    export BASE64_OUT="out/base64_${file}_enc"
    envsubst '${FILE} ${FT_SSL_OUT} ${BASE64_OUT}' < ./ft_ssl_des/base64_encode_test.template >> ./ft_ssl_des/ft_ssl_des.bats
done
echo >> ./ft_ssl_des/ft_ssl_des.bats

echo "# bats file_tags=base64,decode" >> ./ft_ssl_des/ft_ssl_des.bats
for file in "${files[@]}"; do
    echo >> ./ft_ssl_des/ft_ssl_des.bats
    export FILE="$file"
    export FT_SSL_OUT="out/ft_ssl_base64_${file}_dec"
    export BASE64_OUT="out/base64_${file}_dec"
    envsubst '${FILE} ${FT_SSL_OUT} ${BASE64_OUT}' < ./ft_ssl_des/base64_decode_test.template >> ./ft_ssl_des/ft_ssl_des.bats
done
echo >> ./ft_ssl_des/ft_ssl_des.bats

echo "# bats file_tags=base64,decode,subject" >> ./ft_ssl_des/ft_ssl_des.bats
cat ./ft_ssl_des/base64_decode.bats >> ./ft_ssl_des/ft_ssl_des.bats
echo >> ./ft_ssl_des/ft_ssl_des.bats

for command in "${commands[@]}"; do
    echo "# bats file_tags=$command,encrypt" >> ./ft_ssl_des/ft_ssl_des.bats
    for file in "${files[@]}"; do
        echo >> ./ft_ssl_des/ft_ssl_des.bats
        export CMD="$command"
        export FILE="$file"
        export FT_SSL_FLAGS="-k $key2"
        export OPENSSL_FLAGS="-K $key2"
        export FT_SSL_OUT="out/ft_ssl_${command}_${file}_enc"
        export OPENSSL_OUT="out/openssl_${command}_${file}_enc"
        envsubst '${CMD} ${FILE} ${FT_SSL_FLAGS} ${OPENSSL_FLAGS} ${FT_SSL_OUT} ${OPENSSL_OUT}' < ./ft_ssl_des/encrypt_test.template >> ./ft_ssl_des/ft_ssl_des.bats
    done
    echo >> ./ft_ssl_des/ft_ssl_des.bats

    echo "# bats file_tags=$command,encrypt,flags" >> ./ft_ssl_des/ft_ssl_des.bats
    for i in "${!ft_ssl_flags[@]}"; do
        echo >> ./ft_ssl_des/ft_ssl_des.bats
        file="32B"
        export CMD="$command"
        export FILE="$file"
        export FT_SSL_FLAGS="${ft_ssl_flags[i]}"
        export OPENSSL_FLAGS="${openssl_flags[i]}"
        export FT_SSL_OUT="out/ft_ssl_${command}_${file}_${i}_enc"
        export OPENSSL_OUT="out/openssl_${command}_${file}_${i}_enc"
        envsubst '${CMD} ${FILE} ${FT_SSL_FLAGS} ${OPENSSL_FLAGS} ${FT_SSL_OUT} ${OPENSSL_OUT}' < ./ft_ssl_des/encrypt_test.template >> ./ft_ssl_des/ft_ssl_des.bats
    done
    echo >> ./ft_ssl_des/ft_ssl_des.bats

    echo "# bats file_tags=$command,decrypt" >> ./ft_ssl_des/ft_ssl_des.bats
    for file in "${files[@]}"; do
        echo >> ./ft_ssl_des/ft_ssl_des.bats
        export CMD="$command"
        export FILE="$file"
        export FT_SSL_FLAGS="-k $key2"
        export OPENSSL_FLAGS="-K $key2"
        export FT_SSL_OUT="out/ft_ssl_${command}_${file}_dec"
        export OPENSSL_OUT="out/openssl_${command}_${file}_dec"
        envsubst '${CMD} ${FILE} ${FT_SSL_FLAGS} ${OPENSSL_FLAGS} ${FT_SSL_OUT} ${OPENSSL_OUT}' < ./ft_ssl_des/decrypt_test.template >> ./ft_ssl_des/ft_ssl_des.bats
    done
    echo >> ./ft_ssl_des/ft_ssl_des.bats

    echo "# bats file_tags=$command,decrypt,flags" >> ./ft_ssl_des/ft_ssl_des.bats
    for i in "${!ft_ssl_flags[@]}"; do
        echo >> ./ft_ssl_des/ft_ssl_des.bats
        file="32B"
        export CMD="$command"
        export FILE="$file"
        export FT_SSL_FLAGS="${ft_ssl_flags[i]}"
        export OPENSSL_FLAGS="${openssl_flags[i]}"
        export FT_SSL_OUT="out/ft_ssl_${command}_${file}_${i}_dec"
        export OPENSSL_OUT="out/openssl_${command}_${file}_${i}_dec"
        envsubst '${CMD} ${FILE} ${FT_SSL_FLAGS} ${OPENSSL_FLAGS} ${FT_SSL_OUT} ${OPENSSL_OUT}' < ./ft_ssl_des/decrypt_test.template >> ./ft_ssl_des/ft_ssl_des.bats
    done
done

