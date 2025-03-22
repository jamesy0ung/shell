#!/bin/bash
# Compile the shell
make || { echo "Build failed"; exit 1; }
# Run tests
echo "Running tests..."
run_test() {
    input="$1"
    expected_patterns=("${@:2}")
    output=$(echo -e "$input" | ./shell 2>&1)
    for pattern in "${expected_patterns[@]}"; do
        if echo "$output" | grep -qE "$pattern"; then
            echo "[PASS] $input"
            return 0
        fi
    done
    echo "[FAIL] $input"
    echo "Expected: One of ${expected_patterns[*]}"
    echo "Got: $output"
    exit 1
}
# 1. Test built-in commands
run_test "echo hello" "hello"
run_test "pwd" "$(pwd)"
# 2. Test `type` command for builtins
run_test "type echo" "echo is a shell builtin"
run_test "type pwd" "pwd is a shell builtin"
# 3. Test `type` command for external executables
run_test "type ls" "ls is /bin/ls" "ls is /usr/bin/ls"  # Ensure ls exists
run_test "type grep" "grep is /bin/grep" "grep is /usr/bin/grep"  # Ensure grep exists
# 4. Test running external commands
run_test "ls" "$(ls)"
run_test "whoami" "$(whoami)"
# 5. Test command execution with arguments
run_test "echo Test Args" "Test Args"
run_test "ls -l" "total"
# 6. Test handling of non-existent commands
run_test "invalidcommand" "command not found"
# 7. Test `which` command for builtins
run_test "which echo" "echo: shell builtin command"
run_test "which cd" "cd: shell builtin command"
# 8. Test `which` command for external executables
run_test "which ls" "/bin/ls" "/usr/bin/ls"  # Handle both common locations
run_test "which grep" "/bin/grep" "/usr/bin/grep"  # Handle both common locations
# 9. Test `which` with multiple arguments
run_test "which ls grep" "/bin/ls|/usr/bin/ls" "/bin/grep|/usr/bin/grep"
# 10. Test `which` with nonexistent command
run_test "which nonexistentcmd" "nonexistentcmd not found"
# Clean up
make clean
echo "All tests passed!"
