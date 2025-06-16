#!/usr/bin/env bats

setup() {
    load "../test_helper/bats-support/load"
    load "../test_helper/bats-assert/load"
    load "../test_helper/bats-file/load"
}

setup_file() {
    rm -rf out
    mkdir out
    for file in "${files[@]}"; do
        if [ "$file" = "0B" ]; then
            > 0B
        elif [[ "${file: -2:1}" =~ ^[0-9]+$ ]] && [ "${file: -1}" = "B" ]; then
            dd if=/dev/urandom of="$file" bs="${file%?}" count=1 > /dev/null 2>&1
        else
            dd if=/dev/urandom of="$file" bs="$file" count=1 > /dev/null 2>&1
        fi
    done
}

teardown_file() {
    for file in "${files[@]}"; do
        rm -f "$file" "${file}_enc"
    done
}

declare -g files=( "0B" "1B" "2B" "3B" "4B" "32B" "64B" "1KB" "4KB" "64KB" "1MB" "5MB" )

# bats file_tags=base64,encode

@test "base64 0B" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -i 0B -o out/ft_ssl_base64_0B_enc
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    base64 -w 64 0B > out/base64_0B_enc
    assert_files_equal out/ft_ssl_base64_0B_enc out/base64_0B_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_base64_0B_enc out/base64_0B_enc
    fi
    rm -f "$valgrind_log"
}

@test "base64 1B" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -i 1B -o out/ft_ssl_base64_1B_enc
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    base64 -w 64 1B > out/base64_1B_enc
    assert_files_equal out/ft_ssl_base64_1B_enc out/base64_1B_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_base64_1B_enc out/base64_1B_enc
    fi
    rm -f "$valgrind_log"
}

@test "base64 2B" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -i 2B -o out/ft_ssl_base64_2B_enc
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    base64 -w 64 2B > out/base64_2B_enc
    assert_files_equal out/ft_ssl_base64_2B_enc out/base64_2B_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_base64_2B_enc out/base64_2B_enc
    fi
    rm -f "$valgrind_log"
}

@test "base64 3B" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -i 3B -o out/ft_ssl_base64_3B_enc
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    base64 -w 64 3B > out/base64_3B_enc
    assert_files_equal out/ft_ssl_base64_3B_enc out/base64_3B_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_base64_3B_enc out/base64_3B_enc
    fi
    rm -f "$valgrind_log"
}

@test "base64 4B" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -i 4B -o out/ft_ssl_base64_4B_enc
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    base64 -w 64 4B > out/base64_4B_enc
    assert_files_equal out/ft_ssl_base64_4B_enc out/base64_4B_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_base64_4B_enc out/base64_4B_enc
    fi
    rm -f "$valgrind_log"
}

@test "base64 32B" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -i 32B -o out/ft_ssl_base64_32B_enc
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    base64 -w 64 32B > out/base64_32B_enc
    assert_files_equal out/ft_ssl_base64_32B_enc out/base64_32B_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_base64_32B_enc out/base64_32B_enc
    fi
    rm -f "$valgrind_log"
}

@test "base64 64B" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -i 64B -o out/ft_ssl_base64_64B_enc
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    base64 -w 64 64B > out/base64_64B_enc
    assert_files_equal out/ft_ssl_base64_64B_enc out/base64_64B_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_base64_64B_enc out/base64_64B_enc
    fi
    rm -f "$valgrind_log"
}

@test "base64 1KB" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -i 1KB -o out/ft_ssl_base64_1KB_enc
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    base64 -w 64 1KB > out/base64_1KB_enc
    assert_files_equal out/ft_ssl_base64_1KB_enc out/base64_1KB_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_base64_1KB_enc out/base64_1KB_enc
    fi
    rm -f "$valgrind_log"
}

@test "base64 4KB" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -i 4KB -o out/ft_ssl_base64_4KB_enc
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    base64 -w 64 4KB > out/base64_4KB_enc
    assert_files_equal out/ft_ssl_base64_4KB_enc out/base64_4KB_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_base64_4KB_enc out/base64_4KB_enc
    fi
    rm -f "$valgrind_log"
}

@test "base64 64KB" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -i 64KB -o out/ft_ssl_base64_64KB_enc
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    base64 -w 64 64KB > out/base64_64KB_enc
    assert_files_equal out/ft_ssl_base64_64KB_enc out/base64_64KB_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_base64_64KB_enc out/base64_64KB_enc
    fi
    rm -f "$valgrind_log"
}

@test "base64 1MB" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -i 1MB -o out/ft_ssl_base64_1MB_enc
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    base64 -w 64 1MB > out/base64_1MB_enc
    assert_files_equal out/ft_ssl_base64_1MB_enc out/base64_1MB_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_base64_1MB_enc out/base64_1MB_enc
    fi
    rm -f "$valgrind_log"
}

@test "base64 5MB" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -i 5MB -o out/ft_ssl_base64_5MB_enc
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    base64 -w 64 5MB > out/base64_5MB_enc
    assert_files_equal out/ft_ssl_base64_5MB_enc out/base64_5MB_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_base64_5MB_enc out/base64_5MB_enc
    fi
    rm -f "$valgrind_log"
}

# bats file_tags=base64,decode

@test "base64 -d 0B" {
    local valgrind_log=$(mktemp)
    base64 -w 64 0B > 0B_enc
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -d -i 0B_enc -o out/ft_ssl_base64_0B_dec
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    base64 -d 0B_enc > out/base64_0B_dec
    assert_files_equal out/ft_ssl_base64_0B_dec out/base64_0B_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_base64_0B_dec out/base64_0B_dec
    fi
    rm -f "$valgrind_log" 0B_enc
}

@test "base64 -d 1B" {
    local valgrind_log=$(mktemp)
    base64 -w 64 1B > 1B_enc
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -d -i 1B_enc -o out/ft_ssl_base64_1B_dec
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    base64 -d 1B_enc > out/base64_1B_dec
    assert_files_equal out/ft_ssl_base64_1B_dec out/base64_1B_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_base64_1B_dec out/base64_1B_dec
    fi
    rm -f "$valgrind_log" 1B_enc
}

@test "base64 -d 2B" {
    local valgrind_log=$(mktemp)
    base64 -w 64 2B > 2B_enc
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -d -i 2B_enc -o out/ft_ssl_base64_2B_dec
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    base64 -d 2B_enc > out/base64_2B_dec
    assert_files_equal out/ft_ssl_base64_2B_dec out/base64_2B_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_base64_2B_dec out/base64_2B_dec
    fi
    rm -f "$valgrind_log" 2B_enc
}

@test "base64 -d 3B" {
    local valgrind_log=$(mktemp)
    base64 -w 64 3B > 3B_enc
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -d -i 3B_enc -o out/ft_ssl_base64_3B_dec
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    base64 -d 3B_enc > out/base64_3B_dec
    assert_files_equal out/ft_ssl_base64_3B_dec out/base64_3B_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_base64_3B_dec out/base64_3B_dec
    fi
    rm -f "$valgrind_log" 3B_enc
}

@test "base64 -d 4B" {
    local valgrind_log=$(mktemp)
    base64 -w 64 4B > 4B_enc
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -d -i 4B_enc -o out/ft_ssl_base64_4B_dec
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    base64 -d 4B_enc > out/base64_4B_dec
    assert_files_equal out/ft_ssl_base64_4B_dec out/base64_4B_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_base64_4B_dec out/base64_4B_dec
    fi
    rm -f "$valgrind_log" 4B_enc
}

@test "base64 -d 32B" {
    local valgrind_log=$(mktemp)
    base64 -w 64 32B > 32B_enc
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -d -i 32B_enc -o out/ft_ssl_base64_32B_dec
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    base64 -d 32B_enc > out/base64_32B_dec
    assert_files_equal out/ft_ssl_base64_32B_dec out/base64_32B_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_base64_32B_dec out/base64_32B_dec
    fi
    rm -f "$valgrind_log" 32B_enc
}

@test "base64 -d 64B" {
    local valgrind_log=$(mktemp)
    base64 -w 64 64B > 64B_enc
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -d -i 64B_enc -o out/ft_ssl_base64_64B_dec
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    base64 -d 64B_enc > out/base64_64B_dec
    assert_files_equal out/ft_ssl_base64_64B_dec out/base64_64B_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_base64_64B_dec out/base64_64B_dec
    fi
    rm -f "$valgrind_log" 64B_enc
}

@test "base64 -d 1KB" {
    local valgrind_log=$(mktemp)
    base64 -w 64 1KB > 1KB_enc
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -d -i 1KB_enc -o out/ft_ssl_base64_1KB_dec
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    base64 -d 1KB_enc > out/base64_1KB_dec
    assert_files_equal out/ft_ssl_base64_1KB_dec out/base64_1KB_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_base64_1KB_dec out/base64_1KB_dec
    fi
    rm -f "$valgrind_log" 1KB_enc
}

@test "base64 -d 4KB" {
    local valgrind_log=$(mktemp)
    base64 -w 64 4KB > 4KB_enc
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -d -i 4KB_enc -o out/ft_ssl_base64_4KB_dec
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    base64 -d 4KB_enc > out/base64_4KB_dec
    assert_files_equal out/ft_ssl_base64_4KB_dec out/base64_4KB_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_base64_4KB_dec out/base64_4KB_dec
    fi
    rm -f "$valgrind_log" 4KB_enc
}

@test "base64 -d 64KB" {
    local valgrind_log=$(mktemp)
    base64 -w 64 64KB > 64KB_enc
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -d -i 64KB_enc -o out/ft_ssl_base64_64KB_dec
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    base64 -d 64KB_enc > out/base64_64KB_dec
    assert_files_equal out/ft_ssl_base64_64KB_dec out/base64_64KB_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_base64_64KB_dec out/base64_64KB_dec
    fi
    rm -f "$valgrind_log" 64KB_enc
}

@test "base64 -d 1MB" {
    local valgrind_log=$(mktemp)
    base64 -w 64 1MB > 1MB_enc
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -d -i 1MB_enc -o out/ft_ssl_base64_1MB_dec
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    base64 -d 1MB_enc > out/base64_1MB_dec
    assert_files_equal out/ft_ssl_base64_1MB_dec out/base64_1MB_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_base64_1MB_dec out/base64_1MB_dec
    fi
    rm -f "$valgrind_log" 1MB_enc
}

@test "base64 -d 5MB" {
    local valgrind_log=$(mktemp)
    base64 -w 64 5MB > 5MB_enc
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -d -i 5MB_enc -o out/ft_ssl_base64_5MB_dec
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    base64 -d 5MB_enc > out/base64_5MB_dec
    assert_files_equal out/ft_ssl_base64_5MB_dec out/base64_5MB_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_base64_5MB_dec out/base64_5MB_dec
    fi
    rm -f "$valgrind_log" 5MB_enc
}

# bats file_tags=base64,decode,subject
@test "echo -n \"=\" | base64 -d" {
    local valgrind_log=$(mktemp)
    run bash -c "echo -n '=' | valgrind --log-file='$valgrind_log' ../ft_ssl base64 -d 2>/dev/null"
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    assert_output ""
    rm -f "$valgrind_log"
}

@test "echo -n \"Z\" | base64 -d" {
    local valgrind_log=$(mktemp)
    run bash -c "echo -n 'Z' | valgrind --log-file='$valgrind_log' ../ft_ssl base64 -d 2>/dev/null"
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    assert_output ""
    rm -f "$valgrind_log"
}

@test "echo -n \"Z=\" | base64 -d" {
    local valgrind_log=$(mktemp)
    run bash -c "echo -n 'Z=' | valgrind --log-file='$valgrind_log' ../ft_ssl base64 -d 2>/dev/null"
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    assert_output ""
    rm -f "$valgrind_log"
}

@test "echo -n \"Zg\" | base64 -d" {
    local valgrind_log=$(mktemp)
    run bash -c "echo -n 'Zg' | valgrind --log-file='$valgrind_log' ../ft_ssl base64 -d 2>/dev/null"
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    assert_output $(echo -n "Zg" | base64 -d)
    rm -f "$valgrind_log"
}

@test "echo -n \"Zg=\" | base64 -d" {
    local valgrind_log=$(mktemp)
    run bash -c "echo -n 'Zg=' | valgrind --log-file='$valgrind_log' ../ft_ssl base64 -d 2>/dev/null"
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    assert_output $(echo -n "Zg=" | base64 -d)
    rm -f "$valgrind_log"
}

@test "echo -n \"Zg==\" | base64 -d" {
    local valgrind_log=$(mktemp)
    run bash -c "echo -n 'Zg==' | valgrind --log-file='$valgrind_log' ../ft_ssl base64 -d 2>/dev/null"
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    assert_output $(echo -n "Zg==" | base64 -d)
    rm -f "$valgrind_log"
}

@test "echo -n \"Zg=a\" | base64 -d" {
    local valgrind_log=$(mktemp)
    run bash -c "echo -n 'Zg=a' | valgrind --log-file='$valgrind_log' ../ft_ssl base64 -d 2>/dev/null"
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    assert_output $(echo -n "Zg=a" | base64 -d)
    rm -f "$valgrind_log"
}

@test "echo -n \"Zm8\" | base64 -d" {
    local valgrind_log=$(mktemp)
    run bash -c "echo -n 'Zm8' | valgrind --log-file='$valgrind_log' ../ft_ssl base64 -d 2>/dev/null"
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    assert_output $(echo -n "Zm8" | base64 -d)
    rm -f "$valgrind_log"
}

@test "echo -n \"Zm8-\" | base64 -d" {
    local valgrind_log=$(mktemp)
    run bash -c "echo -n 'Zm8-' | valgrind --log-file='$valgrind_log' ../ft_ssl base64 -d 2>/dev/null"
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    assert_output $(echo -n "Zm8-" | base64 -d)
    rm -f "$valgrind_log"
}

@test "echo -n \"Zm8=\" | base64 -d" {
    local valgrind_log=$(mktemp)
    run bash -c "echo -n 'Zm8=' | valgrind --log-file='$valgrind_log' ../ft_ssl base64 -d 2>/dev/null"
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    assert_output $(echo -n "Zm8=" | base64 -d)
    rm -f "$valgrind_log"
}

@test "echo -n \"Zm9v\" | base64 -d" {
    local valgrind_log=$(mktemp)
    run bash -c "echo -n 'Zm9v' | valgrind --log-file='$valgrind_log' ../ft_ssl base64 -d 2>/dev/null"
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    assert_output $(echo -n "Zm9v" | base64 -d)
    rm -f "$valgrind_log"
}

@test "echo -n \"Zm9vYg==\" | base64 -d" {
    local valgrind_log=$(mktemp)
    run bash -c "echo -n 'Zm9vYg==' | valgrind --log-file='$valgrind_log' ../ft_ssl base64 -d 2>/dev/null"
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    assert_output $(echo -n "Zm9vYg==" | base64 -d)
    rm -f "$valgrind_log"
}

@test "echo -n \"Zm9vYmE\" | base64 -d" {
    local valgrind_log=$(mktemp)
    run bash -c "echo -n 'Zm9vYmE' | valgrind --log-file='$valgrind_log' ../ft_ssl base64 -d 2>/dev/null"
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    assert_output $(echo -n "Zm9vYmE" | base64 -d)
    rm -f "$valgrind_log"
}

@test "echo -n \"Zm9vYmFy\" | base64 -d" {
    local valgrind_log=$(mktemp)
    run bash -c "echo -n 'Zm9vYmFy' | valgrind --log-file='$valgrind_log' ../ft_ssl base64 -d 2>/dev/null"
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    assert_output $(echo -n "Zm9vYmFy" | base64 -d)
    rm -f "$valgrind_log"
}

@test "echo -n \"dG90bwo=\" | base64 -d" {
    local valgrind_log=$(mktemp)
    run bash -c "echo -n 'dG90bwo=' | valgrind --log-file='$valgrind_log' ../ft_ssl base64 -d 2>/dev/null"
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    assert_output $(echo -n "dG90bwo=" | base64 -d)
    rm -f "$valgrind_log"
}

@test "echo -n \"d G9 0bwo =\" | base64 -d" {
    local valgrind_log=$(mktemp)
    run bash -c "echo -n 'd G9 0bwo =' | valgrind --log-file='$valgrind_log' ../ft_ssl base64 -d 2>/dev/null"
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    assert_output $(echo -n "dG90bwo=" | base64 -d)
    rm -f "$valgrind_log"
}

# bats file_tags=des-ecb,encrypt

@test "des-ecb 0B -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -i 0B -o out/ft_ssl_des-ecb_0B_enc -k 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 0B -out out/openssl_des-ecb_0B_enc -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-ecb_0B_enc out/openssl_des-ecb_0B_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-ecb_0B_enc out/openssl_des-ecb_0B_enc
    fi
    rm -f "$valgrind_log"
}

@test "des-ecb 1B -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -i 1B -o out/ft_ssl_des-ecb_1B_enc -k 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 1B -out out/openssl_des-ecb_1B_enc -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-ecb_1B_enc out/openssl_des-ecb_1B_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-ecb_1B_enc out/openssl_des-ecb_1B_enc
    fi
    rm -f "$valgrind_log"
}

@test "des-ecb 2B -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -i 2B -o out/ft_ssl_des-ecb_2B_enc -k 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 2B -out out/openssl_des-ecb_2B_enc -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-ecb_2B_enc out/openssl_des-ecb_2B_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-ecb_2B_enc out/openssl_des-ecb_2B_enc
    fi
    rm -f "$valgrind_log"
}

@test "des-ecb 3B -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -i 3B -o out/ft_ssl_des-ecb_3B_enc -k 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 3B -out out/openssl_des-ecb_3B_enc -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-ecb_3B_enc out/openssl_des-ecb_3B_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-ecb_3B_enc out/openssl_des-ecb_3B_enc
    fi
    rm -f "$valgrind_log"
}

@test "des-ecb 4B -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -i 4B -o out/ft_ssl_des-ecb_4B_enc -k 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 4B -out out/openssl_des-ecb_4B_enc -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-ecb_4B_enc out/openssl_des-ecb_4B_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-ecb_4B_enc out/openssl_des-ecb_4B_enc
    fi
    rm -f "$valgrind_log"
}

@test "des-ecb 32B -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -i 32B -o out/ft_ssl_des-ecb_32B_enc -k 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 32B -out out/openssl_des-ecb_32B_enc -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-ecb_32B_enc out/openssl_des-ecb_32B_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-ecb_32B_enc out/openssl_des-ecb_32B_enc
    fi
    rm -f "$valgrind_log"
}

@test "des-ecb 64B -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -i 64B -o out/ft_ssl_des-ecb_64B_enc -k 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 64B -out out/openssl_des-ecb_64B_enc -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-ecb_64B_enc out/openssl_des-ecb_64B_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-ecb_64B_enc out/openssl_des-ecb_64B_enc
    fi
    rm -f "$valgrind_log"
}

@test "des-ecb 1KB -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -i 1KB -o out/ft_ssl_des-ecb_1KB_enc -k 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 1KB -out out/openssl_des-ecb_1KB_enc -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-ecb_1KB_enc out/openssl_des-ecb_1KB_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-ecb_1KB_enc out/openssl_des-ecb_1KB_enc
    fi
    rm -f "$valgrind_log"
}

@test "des-ecb 4KB -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -i 4KB -o out/ft_ssl_des-ecb_4KB_enc -k 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 4KB -out out/openssl_des-ecb_4KB_enc -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-ecb_4KB_enc out/openssl_des-ecb_4KB_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-ecb_4KB_enc out/openssl_des-ecb_4KB_enc
    fi
    rm -f "$valgrind_log"
}

@test "des-ecb 64KB -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -i 64KB -o out/ft_ssl_des-ecb_64KB_enc -k 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 64KB -out out/openssl_des-ecb_64KB_enc -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-ecb_64KB_enc out/openssl_des-ecb_64KB_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-ecb_64KB_enc out/openssl_des-ecb_64KB_enc
    fi
    rm -f "$valgrind_log"
}

@test "des-ecb 1MB -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -i 1MB -o out/ft_ssl_des-ecb_1MB_enc -k 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 1MB -out out/openssl_des-ecb_1MB_enc -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-ecb_1MB_enc out/openssl_des-ecb_1MB_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-ecb_1MB_enc out/openssl_des-ecb_1MB_enc
    fi
    rm -f "$valgrind_log"
}

@test "des-ecb 5MB -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -i 5MB -o out/ft_ssl_des-ecb_5MB_enc -k 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 5MB -out out/openssl_des-ecb_5MB_enc -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-ecb_5MB_enc out/openssl_des-ecb_5MB_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-ecb_5MB_enc out/openssl_des-ecb_5MB_enc
    fi
    rm -f "$valgrind_log"
}

# bats file_tags=des-ecb,encrypt,flags

@test "des-ecb 32B -pass pass:verysecure -S 86A2185F6B1DE243" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -i 32B -o out/ft_ssl_des-ecb_5MB_enc -pass pass:verysecure -S 86A2185F6B1DE243
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 32B -out out/openssl_des-ecb_5MB_enc -pass pass:verysecure -S 86A2185F6B1DE243
    assert_files_equal out/ft_ssl_des-ecb_5MB_enc out/openssl_des-ecb_5MB_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-ecb_5MB_enc out/openssl_des-ecb_5MB_enc
    fi
    rm -f "$valgrind_log"
}

@test "des-ecb 32B -pass pass:verysecure -K 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -i 32B -o out/ft_ssl_des-ecb_5MB_enc -pass pass:verysecure -K 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 32B -out out/openssl_des-ecb_5MB_enc -pass pass:verysecure -K 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-ecb_5MB_enc out/openssl_des-ecb_5MB_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-ecb_5MB_enc out/openssl_des-ecb_5MB_enc
    fi
    rm -f "$valgrind_log"
}

@test "des-ecb 32B -K 5C21918AC1BBEC44 -iv A4B7397EACE23C39" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -i 32B -o out/ft_ssl_des-ecb_5MB_enc -K 5C21918AC1BBEC44 -iv A4B7397EACE23C39
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 32B -out out/openssl_des-ecb_5MB_enc -K 5C21918AC1BBEC44 -iv A4B7397EACE23C39
    assert_files_equal out/ft_ssl_des-ecb_5MB_enc out/openssl_des-ecb_5MB_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-ecb_5MB_enc out/openssl_des-ecb_5MB_enc
    fi
    rm -f "$valgrind_log"
}

@test "des-ecb 32B -pass pass:verysecure -S 86A2185F6B1DE243 -iv A4B7397EACE23C39" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -i 32B -o out/ft_ssl_des-ecb_5MB_enc -pass pass:verysecure -S 86A2185F6B1DE243 -iv A4B7397EACE23C39
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 32B -out out/openssl_des-ecb_5MB_enc -pass pass:verysecure -S 86A2185F6B1DE243 -iv A4B7397EACE23C39
    assert_files_equal out/ft_ssl_des-ecb_5MB_enc out/openssl_des-ecb_5MB_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-ecb_5MB_enc out/openssl_des-ecb_5MB_enc
    fi
    rm -f "$valgrind_log"
}

@test "des-ecb 32B -K 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -i 32B -o out/ft_ssl_des-ecb_5MB_enc -K 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 32B -out out/openssl_des-ecb_5MB_enc -K 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-ecb_5MB_enc out/openssl_des-ecb_5MB_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-ecb_5MB_enc out/openssl_des-ecb_5MB_enc
    fi
    rm -f "$valgrind_log"
}

# bats file_tags=des-ecb,decrypt

@test "des-ecb -d 0B -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 0B -out 0B_enc -k 5C21918AC1BBEC44
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -d -i 0B_enc -o out/ft_ssl_des-ecb_0B_dec -K 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -d -in 0B_enc -out out/openssl_des-ecb_0B_dec -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-ecb_0B_dec out/openssl_des-ecb_0B_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-ecb_0B_dec out/openssl_des-ecb_0B_dec
    fi
    rm -f "$valgrind_log" 0B_enc
}

@test "des-ecb -d 1B -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 1B -out 1B_enc -k 5C21918AC1BBEC44
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -d -i 1B_enc -o out/ft_ssl_des-ecb_1B_dec -K 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -d -in 1B_enc -out out/openssl_des-ecb_1B_dec -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-ecb_1B_dec out/openssl_des-ecb_1B_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-ecb_1B_dec out/openssl_des-ecb_1B_dec
    fi
    rm -f "$valgrind_log" 1B_enc
}

@test "des-ecb -d 2B -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 2B -out 2B_enc -k 5C21918AC1BBEC44
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -d -i 2B_enc -o out/ft_ssl_des-ecb_2B_dec -K 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -d -in 2B_enc -out out/openssl_des-ecb_2B_dec -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-ecb_2B_dec out/openssl_des-ecb_2B_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-ecb_2B_dec out/openssl_des-ecb_2B_dec
    fi
    rm -f "$valgrind_log" 2B_enc
}

@test "des-ecb -d 3B -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 3B -out 3B_enc -k 5C21918AC1BBEC44
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -d -i 3B_enc -o out/ft_ssl_des-ecb_3B_dec -K 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -d -in 3B_enc -out out/openssl_des-ecb_3B_dec -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-ecb_3B_dec out/openssl_des-ecb_3B_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-ecb_3B_dec out/openssl_des-ecb_3B_dec
    fi
    rm -f "$valgrind_log" 3B_enc
}

@test "des-ecb -d 4B -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 4B -out 4B_enc -k 5C21918AC1BBEC44
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -d -i 4B_enc -o out/ft_ssl_des-ecb_4B_dec -K 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -d -in 4B_enc -out out/openssl_des-ecb_4B_dec -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-ecb_4B_dec out/openssl_des-ecb_4B_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-ecb_4B_dec out/openssl_des-ecb_4B_dec
    fi
    rm -f "$valgrind_log" 4B_enc
}

@test "des-ecb -d 32B -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 32B -out 32B_enc -k 5C21918AC1BBEC44
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -d -i 32B_enc -o out/ft_ssl_des-ecb_32B_dec -K 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -d -in 32B_enc -out out/openssl_des-ecb_32B_dec -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-ecb_32B_dec out/openssl_des-ecb_32B_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-ecb_32B_dec out/openssl_des-ecb_32B_dec
    fi
    rm -f "$valgrind_log" 32B_enc
}

@test "des-ecb -d 64B -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 64B -out 64B_enc -k 5C21918AC1BBEC44
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -d -i 64B_enc -o out/ft_ssl_des-ecb_64B_dec -K 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -d -in 64B_enc -out out/openssl_des-ecb_64B_dec -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-ecb_64B_dec out/openssl_des-ecb_64B_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-ecb_64B_dec out/openssl_des-ecb_64B_dec
    fi
    rm -f "$valgrind_log" 64B_enc
}

@test "des-ecb -d 1KB -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 1KB -out 1KB_enc -k 5C21918AC1BBEC44
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -d -i 1KB_enc -o out/ft_ssl_des-ecb_1KB_dec -K 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -d -in 1KB_enc -out out/openssl_des-ecb_1KB_dec -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-ecb_1KB_dec out/openssl_des-ecb_1KB_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-ecb_1KB_dec out/openssl_des-ecb_1KB_dec
    fi
    rm -f "$valgrind_log" 1KB_enc
}

@test "des-ecb -d 4KB -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 4KB -out 4KB_enc -k 5C21918AC1BBEC44
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -d -i 4KB_enc -o out/ft_ssl_des-ecb_4KB_dec -K 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -d -in 4KB_enc -out out/openssl_des-ecb_4KB_dec -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-ecb_4KB_dec out/openssl_des-ecb_4KB_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-ecb_4KB_dec out/openssl_des-ecb_4KB_dec
    fi
    rm -f "$valgrind_log" 4KB_enc
}

@test "des-ecb -d 64KB -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 64KB -out 64KB_enc -k 5C21918AC1BBEC44
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -d -i 64KB_enc -o out/ft_ssl_des-ecb_64KB_dec -K 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -d -in 64KB_enc -out out/openssl_des-ecb_64KB_dec -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-ecb_64KB_dec out/openssl_des-ecb_64KB_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-ecb_64KB_dec out/openssl_des-ecb_64KB_dec
    fi
    rm -f "$valgrind_log" 64KB_enc
}

@test "des-ecb -d 1MB -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 1MB -out 1MB_enc -k 5C21918AC1BBEC44
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -d -i 1MB_enc -o out/ft_ssl_des-ecb_1MB_dec -K 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -d -in 1MB_enc -out out/openssl_des-ecb_1MB_dec -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-ecb_1MB_dec out/openssl_des-ecb_1MB_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-ecb_1MB_dec out/openssl_des-ecb_1MB_dec
    fi
    rm -f "$valgrind_log" 1MB_enc
}

@test "des-ecb -d 5MB -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 5MB -out 5MB_enc -k 5C21918AC1BBEC44
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -d -i 5MB_enc -o out/ft_ssl_des-ecb_5MB_dec -K 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -d -in 5MB_enc -out out/openssl_des-ecb_5MB_dec -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-ecb_5MB_dec out/openssl_des-ecb_5MB_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-ecb_5MB_dec out/openssl_des-ecb_5MB_dec
    fi
    rm -f "$valgrind_log" 5MB_enc
}

# bats file_tags=des-ecb,decrypt,flags

@test "des-ecb -d 32B -pass pass:verysecure -S 86A2185F6B1DE243" {
    local valgrind_log=$(mktemp)
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 32B -out 32B_enc -pass pass:verysecure -S 86A2185F6B1DE243
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -d -i 32B_enc -o out/ft_ssl_des-ecb_5MB_dec -p verysecure -s 86A2185F6B1DE243
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -d -in 32B_enc -out out/openssl_des-ecb_5MB_dec -pass pass:verysecure -S 86A2185F6B1DE243
    assert_files_equal out/ft_ssl_des-ecb_5MB_dec out/openssl_des-ecb_5MB_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-ecb_5MB_dec out/openssl_des-ecb_5MB_dec
    fi
    rm -f "$valgrind_log" 32B_enc
}

@test "des-ecb -d 32B -pass pass:verysecure -K 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 32B -out 32B_enc -pass pass:verysecure -K 5C21918AC1BBEC44
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -d -i 32B_enc -o out/ft_ssl_des-ecb_5MB_dec -p verysecure -k 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -d -in 32B_enc -out out/openssl_des-ecb_5MB_dec -pass pass:verysecure -K 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-ecb_5MB_dec out/openssl_des-ecb_5MB_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-ecb_5MB_dec out/openssl_des-ecb_5MB_dec
    fi
    rm -f "$valgrind_log" 32B_enc
}

@test "des-ecb -d 32B -K 5C21918AC1BBEC44 -iv A4B7397EACE23C39" {
    local valgrind_log=$(mktemp)
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 32B -out 32B_enc -K 5C21918AC1BBEC44 -iv A4B7397EACE23C39
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -d -i 32B_enc -o out/ft_ssl_des-ecb_5MB_dec -k 5C21918AC1BBEC44 -v A4B7397EACE23C39
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -d -in 32B_enc -out out/openssl_des-ecb_5MB_dec -K 5C21918AC1BBEC44 -iv A4B7397EACE23C39
    assert_files_equal out/ft_ssl_des-ecb_5MB_dec out/openssl_des-ecb_5MB_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-ecb_5MB_dec out/openssl_des-ecb_5MB_dec
    fi
    rm -f "$valgrind_log" 32B_enc
}

@test "des-ecb -d 32B -pass pass:verysecure -S 86A2185F6B1DE243 -iv A4B7397EACE23C39" {
    local valgrind_log=$(mktemp)
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 32B -out 32B_enc -pass pass:verysecure -S 86A2185F6B1DE243 -iv A4B7397EACE23C39
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -d -i 32B_enc -o out/ft_ssl_des-ecb_5MB_dec -p verysecure -s 86A2185F6B1DE243 -v A4B7397EACE23C39
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -d -in 32B_enc -out out/openssl_des-ecb_5MB_dec -pass pass:verysecure -S 86A2185F6B1DE243 -iv A4B7397EACE23C39
    assert_files_equal out/ft_ssl_des-ecb_5MB_dec out/openssl_des-ecb_5MB_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-ecb_5MB_dec out/openssl_des-ecb_5MB_dec
    fi
    rm -f "$valgrind_log" 32B_enc
}

@test "des-ecb -d 32B -K 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -in 32B -out 32B_enc -K 5C21918AC1BBEC44
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-ecb -d -i 32B_enc -o out/ft_ssl_des-ecb_5MB_dec -k 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-ecb -pbkdf2 -md sha256 -provider default -provider legacy -d -in 32B_enc -out out/openssl_des-ecb_5MB_dec -K 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-ecb_5MB_dec out/openssl_des-ecb_5MB_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-ecb_5MB_dec out/openssl_des-ecb_5MB_dec
    fi
    rm -f "$valgrind_log" 32B_enc
}
# bats file_tags=des-cbc,encrypt

@test "des-cbc 0B -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -i 0B -o out/ft_ssl_des-cbc_0B_enc -k 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 0B -out out/openssl_des-cbc_0B_enc -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-cbc_0B_enc out/openssl_des-cbc_0B_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-cbc_0B_enc out/openssl_des-cbc_0B_enc
    fi
    rm -f "$valgrind_log"
}

@test "des-cbc 1B -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -i 1B -o out/ft_ssl_des-cbc_1B_enc -k 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 1B -out out/openssl_des-cbc_1B_enc -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-cbc_1B_enc out/openssl_des-cbc_1B_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-cbc_1B_enc out/openssl_des-cbc_1B_enc
    fi
    rm -f "$valgrind_log"
}

@test "des-cbc 2B -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -i 2B -o out/ft_ssl_des-cbc_2B_enc -k 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 2B -out out/openssl_des-cbc_2B_enc -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-cbc_2B_enc out/openssl_des-cbc_2B_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-cbc_2B_enc out/openssl_des-cbc_2B_enc
    fi
    rm -f "$valgrind_log"
}

@test "des-cbc 3B -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -i 3B -o out/ft_ssl_des-cbc_3B_enc -k 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 3B -out out/openssl_des-cbc_3B_enc -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-cbc_3B_enc out/openssl_des-cbc_3B_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-cbc_3B_enc out/openssl_des-cbc_3B_enc
    fi
    rm -f "$valgrind_log"
}

@test "des-cbc 4B -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -i 4B -o out/ft_ssl_des-cbc_4B_enc -k 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 4B -out out/openssl_des-cbc_4B_enc -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-cbc_4B_enc out/openssl_des-cbc_4B_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-cbc_4B_enc out/openssl_des-cbc_4B_enc
    fi
    rm -f "$valgrind_log"
}

@test "des-cbc 32B -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -i 32B -o out/ft_ssl_des-cbc_32B_enc -k 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 32B -out out/openssl_des-cbc_32B_enc -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-cbc_32B_enc out/openssl_des-cbc_32B_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-cbc_32B_enc out/openssl_des-cbc_32B_enc
    fi
    rm -f "$valgrind_log"
}

@test "des-cbc 64B -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -i 64B -o out/ft_ssl_des-cbc_64B_enc -k 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 64B -out out/openssl_des-cbc_64B_enc -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-cbc_64B_enc out/openssl_des-cbc_64B_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-cbc_64B_enc out/openssl_des-cbc_64B_enc
    fi
    rm -f "$valgrind_log"
}

@test "des-cbc 1KB -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -i 1KB -o out/ft_ssl_des-cbc_1KB_enc -k 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 1KB -out out/openssl_des-cbc_1KB_enc -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-cbc_1KB_enc out/openssl_des-cbc_1KB_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-cbc_1KB_enc out/openssl_des-cbc_1KB_enc
    fi
    rm -f "$valgrind_log"
}

@test "des-cbc 4KB -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -i 4KB -o out/ft_ssl_des-cbc_4KB_enc -k 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 4KB -out out/openssl_des-cbc_4KB_enc -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-cbc_4KB_enc out/openssl_des-cbc_4KB_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-cbc_4KB_enc out/openssl_des-cbc_4KB_enc
    fi
    rm -f "$valgrind_log"
}

@test "des-cbc 64KB -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -i 64KB -o out/ft_ssl_des-cbc_64KB_enc -k 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 64KB -out out/openssl_des-cbc_64KB_enc -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-cbc_64KB_enc out/openssl_des-cbc_64KB_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-cbc_64KB_enc out/openssl_des-cbc_64KB_enc
    fi
    rm -f "$valgrind_log"
}

@test "des-cbc 1MB -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -i 1MB -o out/ft_ssl_des-cbc_1MB_enc -k 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 1MB -out out/openssl_des-cbc_1MB_enc -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-cbc_1MB_enc out/openssl_des-cbc_1MB_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-cbc_1MB_enc out/openssl_des-cbc_1MB_enc
    fi
    rm -f "$valgrind_log"
}

@test "des-cbc 5MB -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -i 5MB -o out/ft_ssl_des-cbc_5MB_enc -k 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 5MB -out out/openssl_des-cbc_5MB_enc -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-cbc_5MB_enc out/openssl_des-cbc_5MB_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-cbc_5MB_enc out/openssl_des-cbc_5MB_enc
    fi
    rm -f "$valgrind_log"
}

# bats file_tags=des-cbc,encrypt,flags

@test "des-cbc 32B -pass pass:verysecure -S 86A2185F6B1DE243" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -i 32B -o out/ft_ssl_des-cbc_5MB_enc -pass pass:verysecure -S 86A2185F6B1DE243
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 32B -out out/openssl_des-cbc_5MB_enc -pass pass:verysecure -S 86A2185F6B1DE243
    assert_files_equal out/ft_ssl_des-cbc_5MB_enc out/openssl_des-cbc_5MB_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-cbc_5MB_enc out/openssl_des-cbc_5MB_enc
    fi
    rm -f "$valgrind_log"
}

@test "des-cbc 32B -pass pass:verysecure -K 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -i 32B -o out/ft_ssl_des-cbc_5MB_enc -pass pass:verysecure -K 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 32B -out out/openssl_des-cbc_5MB_enc -pass pass:verysecure -K 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-cbc_5MB_enc out/openssl_des-cbc_5MB_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-cbc_5MB_enc out/openssl_des-cbc_5MB_enc
    fi
    rm -f "$valgrind_log"
}

@test "des-cbc 32B -K 5C21918AC1BBEC44 -iv A4B7397EACE23C39" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -i 32B -o out/ft_ssl_des-cbc_5MB_enc -K 5C21918AC1BBEC44 -iv A4B7397EACE23C39
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 32B -out out/openssl_des-cbc_5MB_enc -K 5C21918AC1BBEC44 -iv A4B7397EACE23C39
    assert_files_equal out/ft_ssl_des-cbc_5MB_enc out/openssl_des-cbc_5MB_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-cbc_5MB_enc out/openssl_des-cbc_5MB_enc
    fi
    rm -f "$valgrind_log"
}

@test "des-cbc 32B -pass pass:verysecure -S 86A2185F6B1DE243 -iv A4B7397EACE23C39" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -i 32B -o out/ft_ssl_des-cbc_5MB_enc -pass pass:verysecure -S 86A2185F6B1DE243 -iv A4B7397EACE23C39
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 32B -out out/openssl_des-cbc_5MB_enc -pass pass:verysecure -S 86A2185F6B1DE243 -iv A4B7397EACE23C39
    assert_files_equal out/ft_ssl_des-cbc_5MB_enc out/openssl_des-cbc_5MB_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-cbc_5MB_enc out/openssl_des-cbc_5MB_enc
    fi
    rm -f "$valgrind_log"
}

@test "des-cbc 32B -K 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -i 32B -o out/ft_ssl_des-cbc_5MB_enc -K 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 32B -out out/openssl_des-cbc_5MB_enc -K 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-cbc_5MB_enc out/openssl_des-cbc_5MB_enc
    if [ "$?" == 0 ]; then
        rm -f out/ft_ssl_des-cbc_5MB_enc out/openssl_des-cbc_5MB_enc
    fi
    rm -f "$valgrind_log"
}

# bats file_tags=des-cbc,decrypt

@test "des-cbc -d 0B -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 0B -out 0B_enc -k 5C21918AC1BBEC44
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -d -i 0B_enc -o out/ft_ssl_des-cbc_0B_dec -K 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -d -in 0B_enc -out out/openssl_des-cbc_0B_dec -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-cbc_0B_dec out/openssl_des-cbc_0B_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-cbc_0B_dec out/openssl_des-cbc_0B_dec
    fi
    rm -f "$valgrind_log" 0B_enc
}

@test "des-cbc -d 1B -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 1B -out 1B_enc -k 5C21918AC1BBEC44
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -d -i 1B_enc -o out/ft_ssl_des-cbc_1B_dec -K 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -d -in 1B_enc -out out/openssl_des-cbc_1B_dec -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-cbc_1B_dec out/openssl_des-cbc_1B_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-cbc_1B_dec out/openssl_des-cbc_1B_dec
    fi
    rm -f "$valgrind_log" 1B_enc
}

@test "des-cbc -d 2B -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 2B -out 2B_enc -k 5C21918AC1BBEC44
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -d -i 2B_enc -o out/ft_ssl_des-cbc_2B_dec -K 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -d -in 2B_enc -out out/openssl_des-cbc_2B_dec -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-cbc_2B_dec out/openssl_des-cbc_2B_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-cbc_2B_dec out/openssl_des-cbc_2B_dec
    fi
    rm -f "$valgrind_log" 2B_enc
}

@test "des-cbc -d 3B -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 3B -out 3B_enc -k 5C21918AC1BBEC44
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -d -i 3B_enc -o out/ft_ssl_des-cbc_3B_dec -K 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -d -in 3B_enc -out out/openssl_des-cbc_3B_dec -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-cbc_3B_dec out/openssl_des-cbc_3B_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-cbc_3B_dec out/openssl_des-cbc_3B_dec
    fi
    rm -f "$valgrind_log" 3B_enc
}

@test "des-cbc -d 4B -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 4B -out 4B_enc -k 5C21918AC1BBEC44
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -d -i 4B_enc -o out/ft_ssl_des-cbc_4B_dec -K 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -d -in 4B_enc -out out/openssl_des-cbc_4B_dec -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-cbc_4B_dec out/openssl_des-cbc_4B_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-cbc_4B_dec out/openssl_des-cbc_4B_dec
    fi
    rm -f "$valgrind_log" 4B_enc
}

@test "des-cbc -d 32B -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 32B -out 32B_enc -k 5C21918AC1BBEC44
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -d -i 32B_enc -o out/ft_ssl_des-cbc_32B_dec -K 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -d -in 32B_enc -out out/openssl_des-cbc_32B_dec -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-cbc_32B_dec out/openssl_des-cbc_32B_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-cbc_32B_dec out/openssl_des-cbc_32B_dec
    fi
    rm -f "$valgrind_log" 32B_enc
}

@test "des-cbc -d 64B -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 64B -out 64B_enc -k 5C21918AC1BBEC44
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -d -i 64B_enc -o out/ft_ssl_des-cbc_64B_dec -K 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -d -in 64B_enc -out out/openssl_des-cbc_64B_dec -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-cbc_64B_dec out/openssl_des-cbc_64B_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-cbc_64B_dec out/openssl_des-cbc_64B_dec
    fi
    rm -f "$valgrind_log" 64B_enc
}

@test "des-cbc -d 1KB -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 1KB -out 1KB_enc -k 5C21918AC1BBEC44
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -d -i 1KB_enc -o out/ft_ssl_des-cbc_1KB_dec -K 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -d -in 1KB_enc -out out/openssl_des-cbc_1KB_dec -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-cbc_1KB_dec out/openssl_des-cbc_1KB_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-cbc_1KB_dec out/openssl_des-cbc_1KB_dec
    fi
    rm -f "$valgrind_log" 1KB_enc
}

@test "des-cbc -d 4KB -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 4KB -out 4KB_enc -k 5C21918AC1BBEC44
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -d -i 4KB_enc -o out/ft_ssl_des-cbc_4KB_dec -K 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -d -in 4KB_enc -out out/openssl_des-cbc_4KB_dec -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-cbc_4KB_dec out/openssl_des-cbc_4KB_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-cbc_4KB_dec out/openssl_des-cbc_4KB_dec
    fi
    rm -f "$valgrind_log" 4KB_enc
}

@test "des-cbc -d 64KB -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 64KB -out 64KB_enc -k 5C21918AC1BBEC44
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -d -i 64KB_enc -o out/ft_ssl_des-cbc_64KB_dec -K 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -d -in 64KB_enc -out out/openssl_des-cbc_64KB_dec -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-cbc_64KB_dec out/openssl_des-cbc_64KB_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-cbc_64KB_dec out/openssl_des-cbc_64KB_dec
    fi
    rm -f "$valgrind_log" 64KB_enc
}

@test "des-cbc -d 1MB -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 1MB -out 1MB_enc -k 5C21918AC1BBEC44
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -d -i 1MB_enc -o out/ft_ssl_des-cbc_1MB_dec -K 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -d -in 1MB_enc -out out/openssl_des-cbc_1MB_dec -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-cbc_1MB_dec out/openssl_des-cbc_1MB_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-cbc_1MB_dec out/openssl_des-cbc_1MB_dec
    fi
    rm -f "$valgrind_log" 1MB_enc
}

@test "des-cbc -d 5MB -k 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 5MB -out 5MB_enc -k 5C21918AC1BBEC44
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -d -i 5MB_enc -o out/ft_ssl_des-cbc_5MB_dec -K 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -d -in 5MB_enc -out out/openssl_des-cbc_5MB_dec -k 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-cbc_5MB_dec out/openssl_des-cbc_5MB_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-cbc_5MB_dec out/openssl_des-cbc_5MB_dec
    fi
    rm -f "$valgrind_log" 5MB_enc
}

# bats file_tags=des-cbc,decrypt,flags

@test "des-cbc -d 32B -pass pass:verysecure -S 86A2185F6B1DE243" {
    local valgrind_log=$(mktemp)
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 32B -out 32B_enc -pass pass:verysecure -S 86A2185F6B1DE243
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -d -i 32B_enc -o out/ft_ssl_des-cbc_5MB_dec -p verysecure -s 86A2185F6B1DE243
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -d -in 32B_enc -out out/openssl_des-cbc_5MB_dec -pass pass:verysecure -S 86A2185F6B1DE243
    assert_files_equal out/ft_ssl_des-cbc_5MB_dec out/openssl_des-cbc_5MB_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-cbc_5MB_dec out/openssl_des-cbc_5MB_dec
    fi
    rm -f "$valgrind_log" 32B_enc
}

@test "des-cbc -d 32B -pass pass:verysecure -K 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 32B -out 32B_enc -pass pass:verysecure -K 5C21918AC1BBEC44
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -d -i 32B_enc -o out/ft_ssl_des-cbc_5MB_dec -p verysecure -k 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -d -in 32B_enc -out out/openssl_des-cbc_5MB_dec -pass pass:verysecure -K 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-cbc_5MB_dec out/openssl_des-cbc_5MB_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-cbc_5MB_dec out/openssl_des-cbc_5MB_dec
    fi
    rm -f "$valgrind_log" 32B_enc
}

@test "des-cbc -d 32B -K 5C21918AC1BBEC44 -iv A4B7397EACE23C39" {
    local valgrind_log=$(mktemp)
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 32B -out 32B_enc -K 5C21918AC1BBEC44 -iv A4B7397EACE23C39
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -d -i 32B_enc -o out/ft_ssl_des-cbc_5MB_dec -k 5C21918AC1BBEC44 -v A4B7397EACE23C39
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -d -in 32B_enc -out out/openssl_des-cbc_5MB_dec -K 5C21918AC1BBEC44 -iv A4B7397EACE23C39
    assert_files_equal out/ft_ssl_des-cbc_5MB_dec out/openssl_des-cbc_5MB_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-cbc_5MB_dec out/openssl_des-cbc_5MB_dec
    fi
    rm -f "$valgrind_log" 32B_enc
}

@test "des-cbc -d 32B -pass pass:verysecure -S 86A2185F6B1DE243 -iv A4B7397EACE23C39" {
    local valgrind_log=$(mktemp)
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 32B -out 32B_enc -pass pass:verysecure -S 86A2185F6B1DE243 -iv A4B7397EACE23C39
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -d -i 32B_enc -o out/ft_ssl_des-cbc_5MB_dec -p verysecure -s 86A2185F6B1DE243 -v A4B7397EACE23C39
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -d -in 32B_enc -out out/openssl_des-cbc_5MB_dec -pass pass:verysecure -S 86A2185F6B1DE243 -iv A4B7397EACE23C39
    assert_files_equal out/ft_ssl_des-cbc_5MB_dec out/openssl_des-cbc_5MB_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-cbc_5MB_dec out/openssl_des-cbc_5MB_dec
    fi
    rm -f "$valgrind_log" 32B_enc
}

@test "des-cbc -d 32B -K 5C21918AC1BBEC44" {
    local valgrind_log=$(mktemp)
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -in 32B -out 32B_enc -K 5C21918AC1BBEC44
    run valgrind --log-file="$valgrind_log" ../ft_ssl des-cbc -d -i 32B_enc -o out/ft_ssl_des-cbc_5MB_dec -k 5C21918AC1BBEC44
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    [ "$?" -eq 0 ]
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    [ "$?" -eq 0 ]
    openssl des-cbc -pbkdf2 -md sha256 -provider default -provider legacy -d -in 32B_enc -out out/openssl_des-cbc_5MB_dec -K 5C21918AC1BBEC44
    assert_files_equal out/ft_ssl_des-cbc_5MB_dec out/openssl_des-cbc_5MB_dec
    if [ "$?" -eq 0 ]; then
        rm -f out/ft_ssl_des-cbc_5MB_dec out/openssl_des-cbc_5MB_dec
    fi
    rm -f "$valgrind_log" 32B_enc
}
