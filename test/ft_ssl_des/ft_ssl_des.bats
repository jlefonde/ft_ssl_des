#!/usr/bin/env bats

setup() {
    load "../test_helper/bats-support/load"
    load "../test_helper/bats-assert/load"
}

setup_file() {
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
    echo
    # for file in "${files[@]}"; do
    #     rm -f "$file"
    # done
}

declare -g files=( "0B" "1B" "56B" "57B" "63B" "64B" "65B" "100B" "128B" "10MB" )

# bats file_tags=base64,decode

@test "echo -n \"=\" | base64 -d" {
    run bats_pipe echo -n "=" \| ../ft_ssl base64 -d 2> /dev/null
    assert_output "$(echo -n "=" | base64 -d)"
}

@test "echo -n \"Z\" | base64 -d" {
    run bats_pipe echo -n "Z" \| ../ft_ssl base64 -d 2> /dev/null
    assert_output "$(echo -n "Z" | base64 -d)"
}

@test "echo -n \"Z=\" | base64 -d" {
    run bats_pipe echo -n "Z=" \| ../ft_ssl base64 -d 2> /dev/null
    assert_output "$(echo -n "Z=" | base64 -d)"
}

@test "echo -n \"Zg\" | base64 -d" {
    run bats_pipe echo -n "Zg" \| ../ft_ssl base64 -d 2> /dev/null
    assert_output "$(echo -n "Zg" | base64 -d)"
}

@test "echo -n \"Zg=\" | base64 -d" {
    run bats_pipe echo -n "Zg=" \| ../ft_ssl base64 -d 2> /dev/null
    assert_output "$(echo -n "Zg=" | base64 -d)"
}

@test "echo -n \"Zg==\" | base64 -d" {
    run bats_pipe echo -n "Zg==" \| ../ft_ssl base64 -d 2> /dev/null
    assert_output "$(echo -n "Zg==" | base64 -d)"
}

@test "echo -n \"Zg=a\" | base64 -d" {
    run bats_pipe echo -n "Zg=a" \| ../ft_ssl base64 -d 2> /dev/null
    assert_output "$(echo -n "Zg=a" | base64 -d)"
}

@test "echo -n \"Zm8\" | base64 -d" {
    run bats_pipe echo -n "Zm8" \| ../ft_ssl base64 -d 2> /dev/null
    assert_output "$(echo -n "Zm8" | base64 -d)"
}

@test "echo -n \"Zm8=\" | base64 -d" {
    run bats_pipe echo -n "Zm8=" \| ../ft_ssl base64 -d 2> /dev/null
    assert_output "$(echo -n "Zm8=" | base64 -d)"
}

@test "echo -n \"Zm9v\" | base64 -d" {
    run bats_pipe echo -n "Zm9v" \| ../ft_ssl base64 -d 2> /dev/null
    assert_output "$(echo -n "Zm9v" | base64 -d)"
}

@test "echo -n \"Zm9vYg==\" | base64 -d" {
    run bats_pipe echo -n "Zm9vYg==" \| ../ft_ssl base64 -d 2> /dev/null
    assert_output "$(echo -n "Zm9vYg==" | base64 -d)"
}

@test "echo -n \"Zm9vYmE\" | base64 -d" {
    run bats_pipe echo -n "Zm9vYmE" \| ../ft_ssl base64 -d 2> /dev/null
    assert_output "$(echo -n "Zm9vYmE" | base64 -d)"
}

@test "echo -n \"Zm9vYmFy\" | base64 -d" {
    run bats_pipe echo -n "Zm9vYmFy" \| ../ft_ssl base64 -d 2> /dev/null
    assert_output "$(echo -n "Zm9vYmFy" | base64 -d)"
}


@test "base64 0B" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -i 0B
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    assert_success
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    assert_success
    assert_output $(base64 0B -w 64)
    rm -f "$valgrind_log"
}

@test "base64 1B" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -i 1B
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    assert_success
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    assert_success
    assert_output $(base64 1B -w 64)
    rm -f "$valgrind_log"
}

@test "base64 56B" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -i 56B
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    assert_success
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    assert_success
    assert_output $(base64 56B -w 64)
    rm -f "$valgrind_log"
}

@test "base64 57B" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -i 57B
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    assert_success
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    assert_success
    assert_output $(base64 57B -w 64)
    rm -f "$valgrind_log"
}

@test "base64 63B" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -i 63B
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    assert_success
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    assert_success
    assert_output $(base64 63B -w 64)
    rm -f "$valgrind_log"
}

@test "base64 64B" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -i 64B
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    assert_success
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    assert_success
    assert_output $(base64 64B -w 64)
    rm -f "$valgrind_log"
}

@test "base64 65B" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -i 65B
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    assert_success
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    assert_success
    assert_output $(base64 65B -w 64)
    rm -f "$valgrind_log"
}

@test "base64 100B" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -i 100B
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    assert_success
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    assert_success
    assert_output $(base64 100B -w 64)
    rm -f "$valgrind_log"
}

@test "base64 128B" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -i 128B
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    assert_success
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    assert_success
    assert_output $(base64 128B -w 64)
    rm -f "$valgrind_log"
}

@test "base64 10MB" {
    local valgrind_log=$(mktemp)
    run valgrind --log-file="$valgrind_log" ../ft_ssl base64 -i 10MB
    grep -q "All heap blocks were freed -- no leaks are possible" "$valgrind_log"
    assert_success
    grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$valgrind_log"
    assert_success
    assert_output $(base64 10MB -w 64)
    rm -f "$valgrind_log"
}
