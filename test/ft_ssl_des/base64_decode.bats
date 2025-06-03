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
