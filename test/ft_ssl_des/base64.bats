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
