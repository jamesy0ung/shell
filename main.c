#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <spawn.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>

/**
 * Constants for shell operations
 */
#define MAX_INPUT_SIZE 1024
#define MIN_PATH_DIRS 10
#define MAX_COMMAND_LENGTH 256
#define MAX_COMMAND_ARGS 64

/**
 * Builtin command definitions
 */
static const char *BUILTIN_COMMANDS[] = {"cd", "echo", "exit", "pwd", "type", "which"};
static const size_t NUM_BUILTIN_COMMANDS = sizeof(BUILTIN_COMMANDS) / sizeof(BUILTIN_COMMANDS[0]);

/**
 * Structure to store PATH directories
 */
typedef struct {
    char **directories;  // Array of directory paths
    size_t count;        // Number of directories currently stored
    size_t capacity;     // Total capacity of the array
} PathDirectories;

/**
 * Function prototypes
 */
static PathDirectories *initialize_path_directories(void);
static PathDirectories *parse_path(const char *path);
static void cleanup_path_directories(PathDirectories *dirs);
static char *find_executable(const PathDirectories *dirs, const char *command);
static int is_builtin_command(const char *cmd);
static char *get_user_input(char *buffer, size_t size);
static void process_command(char *input, const PathDirectories *dirs);
static void handle_cd_command(int argc, char **argv);
static void handle_exit_command(int argc, char **argv, const PathDirectories *dirs);
static void handle_echo_command(int argc, char **argv);
static void handle_pwd_command(int argc, char **argv);
static void handle_type_command(int argc, char **argv, const PathDirectories *dirs);
static void handle_which_command(int argc, char **argv, const PathDirectories *dirs);
static void execute_external_command(char **argv, const char *executable_path);

/**
 * Global variable to track the current child process ID
 */
static pid_t current_child_pid = -1;

/**
 * Signal handler for SIGINT (Ctrl+C)
 */
static void sigint_handler(int signum) {
    (void)signum;
    if (current_child_pid > 0) {
        kill(current_child_pid, SIGINT);
    }
}

/**
 * Comparison function for binary search of builtin commands
 */
static int compare_builtin_commands(const void *a, const void *b) {
    const char *key = (const char *)a;
    const char *const *elem = (const char *const *)b;
    return strcmp(key, *elem);
}

/**
 * Check if the given command is a builtin
 */
static int is_builtin_command(const char *cmd) {
    if (!cmd)
        return 0;
    return bsearch(cmd, BUILTIN_COMMANDS, NUM_BUILTIN_COMMANDS,
                   sizeof(char *), compare_builtin_commands) != NULL;
}

/**
 * Initialize the PathDirectories structure
 */
static PathDirectories *initialize_path_directories(void) {
    PathDirectories *dirs = calloc(1, sizeof(PathDirectories));
    if (!dirs)
        return NULL;

    dirs->capacity = MIN_PATH_DIRS;
    dirs->directories = calloc(dirs->capacity, sizeof(char *));

    if (!dirs->directories) {
        free(dirs);
        return NULL;
    }

    return dirs;
}

/**
 * Parse the PATH environment variable into a PathDirectories structure
 */
static PathDirectories *parse_path(const char *path) {
    if (!path)
        return NULL;

    PathDirectories *dirs = initialize_path_directories();
    if (!dirs)
        return NULL;

    char *path_copy = strdup(path);
    if (!path_copy) {
        cleanup_path_directories(dirs);
        return NULL;
    }

    char *token = strtok(path_copy, ":");
    while (token) {
        if (dirs->count >= dirs->capacity) {
            size_t new_capacity = dirs->capacity * 2;
            char **new_dirs = realloc(dirs->directories,
                                    new_capacity * sizeof(char *));
            if (!new_dirs) {
                cleanup_path_directories(dirs);
                free(path_copy);
                return NULL;
            }
            dirs->directories = new_dirs;
            dirs->capacity = new_capacity;
        }

        dirs->directories[dirs->count] = strdup(token);
        if (!dirs->directories[dirs->count]) {
            cleanup_path_directories(dirs);
            free(path_copy);
            return NULL;
        }

        dirs->count++;
        token = strtok(NULL, ":");
    }

    free(path_copy);
    return dirs;
}

/**
 * Free all memory associated with the PathDirectories structure
 */
static void cleanup_path_directories(PathDirectories *dirs) {
    if (!dirs)
        return;

    if (dirs->directories) {
        for (size_t i = 0; i < dirs->count; i++) {
            free(dirs->directories[i]);
        }
        free(dirs->directories);
    }
    free(dirs);
}

/**
 * Find the full path to an executable in the PATH
 */
static char *find_executable(const PathDirectories *dirs, const char *command) {
    if (!dirs || !command || !*command) {
        return NULL;
    }

    // If command contains a path separator, check if it's directly executable
    if (strchr(command, '/') != NULL) {
        if (access(command, X_OK) == 0) {
            return strdup(command);
        }
        return NULL;
    }

    // Otherwise, search for the command in each directory in PATH
    for (size_t i = 0; i < dirs->count; i++) {
        char path[PATH_MAX];
        snprintf(path, PATH_MAX, "%s/%s", dirs->directories[i], command);
        if (access(path, X_OK) == 0) {
            return strdup(path);
        }
    }
    return NULL;
}

/**
 * Handle the 'cd' builtin command
 */
static void handle_cd_command(int argc, char **argv) {
    const char *path;
    if (argc < 2) {
        path = getenv("HOME");
        if (!path) {
            fprintf(stderr, "cd: HOME environment variable not set\n");
            return;
        }
    } else {
        path = argv[1];
    }

    if (chdir(path) != 0) {
        perror("cd");
    }
}

/**
 * Handle the 'exit' builtin command
 */
static void handle_exit_command(int argc, char **argv, const PathDirectories *dirs) {
    int status = 0;
    if (argc > 1) {
        status = atoi(argv[1]);
    }
    cleanup_path_directories((PathDirectories *)dirs);
    exit(status);
}

/**
 * Handle the 'echo' builtin command
 */
static void handle_echo_command(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        printf("%s%s", argv[i], (i < argc - 1) ? " " : "");
    }
    printf("\n");
}

/**
 * Handle the 'pwd' builtin command
 */
static void handle_pwd_command(int argc, char **argv) {
    if (argc > 1) {
        printf("pwd: too many arguments\n");
        return;
    }

    char *cwd = getcwd(NULL, 0);
    if (cwd) {
        printf("%s\n", cwd);
        free(cwd);
    } else {
        perror("pwd");
    }
}

/**
 * Handle the 'type' builtin command
 */
static void handle_type_command(int argc, char **argv, const PathDirectories *dirs) {
    if (argc < 2) {
        printf("type: missing argument\n");
        return;
    }

    const char *arg = argv[1];
    if (is_builtin_command(arg)) {
        printf("%s is a shell builtin\n", arg);
    } else {
        char *executable_path = find_executable(dirs, arg);
        if (executable_path) {
            printf("%s is %s\n", arg, executable_path);
            free(executable_path);
        } else {
            printf("%s: not found\n", arg);
        }
    }
}

/**
 * Handle the 'which' builtin command
 */
static void handle_which_command(int argc, char **argv, const PathDirectories *dirs) {
    if (argc < 2) {
        printf("which: missing argument\n");
        return;
    }

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        
        // Check if it's a builtin command first
        if (is_builtin_command(arg)) {
            printf("%s: shell builtin command\n", arg);
        } else {
            // Use the existing find_executable function
            char *executable_path = find_executable(dirs, arg);
            if (executable_path) {
                printf("%s\n", executable_path);
                free(executable_path);
            } else {
                printf("%s not found\n", arg);
            }
        }
    }
}

/**
 * Get user input from stdin
 */
static char *get_user_input(char *buffer, size_t size) {
    printf("$ ");
    fflush(stdout);

    if (!fgets(buffer, size, stdin)) {
        return NULL;
    }

    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0';
    }

    return buffer;
}

/**
 * Execute an external command using posix_spawn
 */
static void execute_external_command(char **argv, const char *executable_path) {
    pid_t pid;
    extern char **environ;

    struct sigaction action;
    struct sigaction oldaction;

    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = sigint_handler;
    sigaction(SIGINT, &action, &oldaction);

    int spawn_status = posix_spawn(&pid, executable_path, NULL, NULL, argv, environ);

    if (spawn_status != 0) {
        printf("posix_spawn failed: %s\n", strerror(spawn_status));
        return;
    }

    current_child_pid = pid;

    // Wait for the child process to finish
    int wait_status;
    pid_t wait_result;
    
    // Handle EINTR by retrying waitpid
    while ((wait_result = waitpid(pid, &wait_status, 0)) == -1 && errno == EINTR) {
        // Just retry if interrupted by a signal
    }
    
    if (wait_result == -1) {
        perror("waitpid");
        current_child_pid = -1;
        sigaction(SIGINT, &oldaction, NULL);  // Restore previous signal handler
        return;
    }

    current_child_pid = -1;
    sigaction(SIGINT, &oldaction, NULL);
}

/**
 * Process a command string
 */
static void process_command(char *input, const PathDirectories *dirs) {
    if (!input || !*input)
        return;

    // Split input into arguments
    char *args[MAX_COMMAND_ARGS];
    int argc = 0;

    char *token = strtok(input, " ");
    while (token != NULL && argc < MAX_COMMAND_ARGS - 1) {
        args[argc++] = token;
        token = strtok(NULL, " ");
    }
    args[argc] = NULL;

    if (argc == 0)
        return;  // Empty command

    const char *command = args[0];

    // Handle built-in commands
    if (strcmp(command, "cd") == 0) {
        handle_cd_command(argc, args);
    } else if (strcmp(command, "exit") == 0) {
        handle_exit_command(argc, args, dirs);
    } else if (strcmp(command, "echo") == 0) {
        handle_echo_command(argc, args);
    } else if (strcmp(command, "pwd") == 0) {
        handle_pwd_command(argc, args);
    } else if (strcmp(command, "type") == 0) {
        handle_type_command(argc, args, dirs);
    } else if (strcmp(command, "which") == 0) {
        handle_which_command(argc, args, dirs);
    }
    else {
        // Handle external commands
        char *executable_path = find_executable(dirs, command);
        if (executable_path) {
            execute_external_command(args, executable_path);
            free(executable_path);
        } else {
            printf("%s: command not found\n", command);
        }
    }
}

/**
 * Main function - entry point of the shell
 */
int main(int argc, char **argv) {
    // Set up the signal handler for Ctrl+C
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;
    sigaction(SIGINT, &sa, NULL);

    char *path = getenv("PATH");
    if (!path) {
        fprintf(stderr, "Error: PATH environment variable not set\n");
        return EXIT_FAILURE;
    }

    PathDirectories *dirs = parse_path(path);
    if (!dirs) {
        fprintf(stderr, "Error: Failed to initialize path directories\n");
        return EXIT_FAILURE;
    }

    // If command line arguments are provided, execute them and exit
    if (argc > 1) {
        // Create a single command string from all arguments
        char command[MAX_INPUT_SIZE] = "";
        for (int i = 1; i < argc; i++) {
            if (i > 1) strncat(command, " ", MAX_INPUT_SIZE - strlen(command) - 1);
            strncat(command, argv[i], MAX_INPUT_SIZE - strlen(command) - 1);
        }
        
        // Process the command
        process_command(command, dirs);
        cleanup_path_directories(dirs);
        return EXIT_SUCCESS;
    }

    // Normal interactive shell mode
    char input[MAX_INPUT_SIZE];
    while (get_user_input(input, sizeof(input))) {
        process_command(input, dirs);
    }

    // Reached EOF (Ctrl+D)
    printf("\n");
    cleanup_path_directories(dirs);
    return EXIT_SUCCESS;
}
