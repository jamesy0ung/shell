#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/**
 * Constants for shell operations
 */
#define MAX_INPUT_SIZE 1024
#define MIN_PATH_DIRS 10
#define MAX_COMMAND_LENGTH 256
#define MAX_COMMAND_ARGS 64

/**
 * Structure to store PATH directories
 */
typedef struct {
    char **directories;  // Array of directory paths
    size_t count;        // Number of directories currently stored
    size_t capacity;     // Total capacity of the array
} PathDirectories;

/**
 * Function type definition for builtin commands
 */
typedef void (*builtin_handler_func)(int argc, char **argv, const PathDirectories *dirs);

/**
 * Structure to define a builtin command
 */
typedef struct {
    const char *name;
    builtin_handler_func handler;
} BuiltinCommand;

/**
 * Global variable to track the current child process ID
 */
static pid_t current_child_pid = -1;

/**
 * Function prototypes
 */
static PathDirectories *initialize_path_directories(void);
static PathDirectories *parse_path(const char *path);
static void cleanup_path_directories(PathDirectories *dirs);
static char *find_executable(const PathDirectories *dirs, const char *command);
static char *get_user_input(char *buffer, size_t size);
int tokenize_command(char *input, size_t input_size, char *args[], int max_args);
static void process_command(char *input, const PathDirectories *dirs);
static void process_args(int argc, char **argv, const PathDirectories *dirs);
static void execute_external_command(char **argv, const char *executable_path);
static char *get_prompt(void);

/* Builtin command handlers */
static void handle_cd_command(int argc, char **argv);
static void handle_echo_command(int argc, char **argv);
static void handle_pwd_command(int argc, char **argv);

/* Wrapper functions for command handlers with consistent signatures */
static void handle_cd_wrapper(int argc, char **argv, const PathDirectories *dirs);
static void handle_echo_wrapper(int argc, char **argv, const PathDirectories *dirs);
static void handle_pwd_wrapper(int argc, char **argv, const PathDirectories *dirs);
static void handle_exit_command(int argc, char **argv, const PathDirectories *dirs);
static void handle_type_command(int argc, char **argv, const PathDirectories *dirs);
static void handle_which_command(int argc, char **argv, const PathDirectories *dirs);

/**
 * Builtin command definitions
 */
static const char *BUILTIN_COMMANDS[] = {"cd", "echo", "exit", "pwd", "type", "which"};

static const BuiltinCommand BUILTIN_COMMAND_TABLE[] = {{"cd", handle_cd_wrapper},     {"echo", handle_echo_wrapper},
                                                       {"exit", handle_exit_command}, {"pwd", handle_pwd_wrapper},
                                                       {"type", handle_type_command}, {"which", handle_which_command}};
static const size_t NUM_BUILTIN_COMMANDS = sizeof(BUILTIN_COMMAND_TABLE) / sizeof(BuiltinCommand);

/**
 * Signal handler for SIGINT (Ctrl+C)
 */
static void sigint_handler(int signum) {
    (void)signum;
    if (current_child_pid > 0) {
        kill(current_child_pid, SIGINT);
    } else {
        printf("\n%s", get_prompt());
        fflush(stdout);
    }
}

/**
 * Comparison function for binary search of builtin commands
 */
static int compare_builtin_commands(const void *a, const void *b) {
    return strcmp((const char *)a, *(const char *const *)b);
}

/**
 * Check if the given command is a builtin
 */
static int is_builtin_command(const char *cmd) {
    return cmd && bsearch(cmd, BUILTIN_COMMANDS, NUM_BUILTIN_COMMANDS, sizeof(char *), compare_builtin_commands);
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
            size_t new_cap = dirs->capacity * 2;
            char **new_dirs = realloc(dirs->directories, new_cap * sizeof(char *));
            if (!new_dirs) {
                free(path_copy);
                cleanup_path_directories(dirs);
                return NULL;
            }
            dirs->directories = new_dirs;
            dirs->capacity = new_cap;
        }
        dirs->directories[dirs->count] = strdup(token);
        if (!dirs->directories[dirs->count++]) {
            free(path_copy);
            cleanup_path_directories(dirs);
            return NULL;
        }
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
    for (size_t i = 0; i < dirs->count; free(dirs->directories[i++]));
    free(dirs->directories);
    free(dirs);
}

/**
 * Find the full path to an executable in the PATH
 */
static char *find_executable(const PathDirectories *dirs, const char *command) {
    if (!command || !*command) {
        return NULL;
    }

    // If command contains a path separator, check if it's directly executable
    if (strchr(command, '/')) {
        if (access(command, X_OK) == 0) {
            return strdup(command);
        } else {
            return NULL;
        }
    }

    if (!dirs || !dirs->directories) {
        return NULL;
    }

    // Otherwise, search for the command in each directory in PATH
    char full_path[PATH_MAX];
    for (size_t i = 0; i < dirs->count; i++) {
        int len = snprintf(full_path, PATH_MAX, "%s/%s", dirs->directories[i], command);
        if (len < 0 || len >= PATH_MAX) {
            continue;
        }
        if (access(full_path, X_OK) == 0) {
            return strdup(full_path);
        }
    }
    return NULL;
}

/**
 * Handle the 'cd' builtin command
 */
static void handle_cd_command(int argc, char **argv) {
    const char *target;

    if (argc < 2) {
        target = getenv("HOME");
    } else {
        target = argv[1];
    }

    if (!target) {
        fprintf(stderr, "cd: HOME not set\n");
    } else if (chdir(target) != 0) {
        perror("cd");
    }
}

/**
 * Handle the 'exit' builtin command
 */
static void handle_exit_command(int argc, char **argv, const PathDirectories *dirs) {
    int status = 0;
    if (argc > 1) {
        char *end;
        long val = strtol(argv[1], &end, 10);
        if (*end || argv[1] == end) {
            fprintf(stderr, "exit: numeric argument required\n");
            status = 1;
        } else
            status = (int)val;
    }
    cleanup_path_directories((PathDirectories *)dirs);
    exit(status);
}

/**
 * Handle the 'echo' builtin command
 */
static void handle_echo_command(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        printf("%s", argv[i]);
        if (i < argc - 1)
            putchar(' ');
    }
    putchar('\n');
}

/**
 * Handle the 'pwd' builtin command
 */
static void handle_pwd_command(int argc, char **argv) {
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
    for (int i = 1; i < argc; i++) {
        if (is_builtin_command(argv[i])) {
            printf("%s is a shell builtin\n", argv[i]);
            continue;
        }
        char *path = find_executable(dirs, argv[i]);
        if (path) {
            printf("%s is %s\n", argv[i], path);
            free(path);
        } else {
            fprintf(stderr, "bash: type: %s: not found\n", argv[i]);
        }
    }
}

/**
 * Handle the 'which' builtin command
 */
static void handle_which_command(int argc, char **argv, const PathDirectories *dirs) {
    for (int i = 1; i < argc; i++) {
        // Check if it's a builtin command first
        if (is_builtin_command(argv[i])) {
            printf("%s: shell builtin command\n", argv[i]);
            continue;
        }
        // Use the existing find_executable function
        char *path = find_executable(dirs, argv[i]);
        if (path) {
            printf("%s\n", path);
            free(path);
        } else {
            fprintf(stderr, "%s not found\n", argv[i]);
        }
    }
}

static void handle_cd_wrapper(int argc, char **argv, const PathDirectories *dirs) {
    (void)dirs;
    handle_cd_command(argc, argv);
}

static void handle_echo_wrapper(int argc, char **argv, const PathDirectories *dirs) {
    (void)dirs;
    handle_echo_command(argc, argv);
}

static void handle_pwd_wrapper(int argc, char **argv, const PathDirectories *dirs) {
    (void)dirs;
    handle_pwd_command(argc, argv);
}

/**
 * Get user input from stdin
 */
static char *get_user_input(char *buffer, size_t size) {
    printf("%s", get_prompt());
    fflush(stdout);
    if (!fgets(buffer, (int)size, stdin))
        return NULL;
    size_t len = strlen(buffer);
    if (len && buffer[len - 1] == '\n')
        buffer[len - 1] = '\0';
    return buffer;
}

/**
 * Tokenize the input, check for spaces, quotes or escape character
 */
int tokenize_command(char *input, size_t input_size, char *args[], int max_args) {
    int argc = 0;
    char *write_ptr = input;
    char *read_ptr = input;
    char *arg_start = NULL;
    char quote = 0;
    int escaped = 0;

    while (*read_ptr && argc < max_args - 1 && write_ptr < input + input_size - 1) {
        if (escaped) {
            *write_ptr++ = *read_ptr++;
            escaped = 0;
            continue;
        }

        switch (*read_ptr) {
        case '\\':
            escaped = 1;
            read_ptr++;
            break;
        case '\'':
        case '"':
            if (!quote)
                quote = *read_ptr;
            else if (quote == *read_ptr)
                quote = 0;
            else
                *write_ptr++ = *read_ptr;
            read_ptr++;
            break;
        default:
            if (quote) {
                *write_ptr++ = *read_ptr++;
            } else if (isspace(*read_ptr)) {
                if (arg_start) {
                    *write_ptr++ = '\0';
                    args[argc++] = arg_start;
                    arg_start = NULL;
                }
                read_ptr++;
            } else {
                if (!arg_start)
                    arg_start = write_ptr;
                *write_ptr++ = *read_ptr++;
            }
        }
    }

    if (arg_start) {
        *write_ptr++ = '\0';
        args[argc++] = arg_start;
    }

    args[argc] = NULL;
    return quote ? -1 : argc;
}

static void process_args(int argc, char **argv, const PathDirectories *dirs) {
    if (argc == 0)
        return;

    for (size_t i = 0; i < NUM_BUILTIN_COMMANDS; i++) {
        if (strcmp(argv[0], BUILTIN_COMMAND_TABLE[i].name) == 0) {
            BUILTIN_COMMAND_TABLE[i].handler(argc, argv, dirs);
            return;
        }
    }

    char *path = find_executable(dirs, argv[0]);
    if (path) {
        execute_external_command(argv, path);
        free(path);
    } else {
        fprintf(stderr, "%s: command not found\n", argv[0]);
    }
}

/**
 * Process a command string
 */
static void process_command(char *input, const PathDirectories *dirs) {
    char *args[MAX_COMMAND_ARGS];
    int argc = tokenize_command(input, MAX_INPUT_SIZE, args, MAX_COMMAND_ARGS);
    if (argc > 0)
        process_args(argc, args, dirs);
}

/**
 * Execute an external command using posix_spawn
 */
static void execute_external_command(char **argv, const char *path) {
    pid_t pid;
    extern char **environ;
    struct sigaction old, new;

    sigaction(SIGINT, NULL, &old);
    new = old;
    new.sa_handler = SIG_IGN;
    sigaction(SIGINT, &new, NULL);

    if (posix_spawn(&pid, path, NULL, NULL, argv, environ) == 0) {
        current_child_pid = pid;
        int status;
        while (waitpid(pid, &status, 0) == -1 && errno == EINTR);
    } else {
        perror("posix_spawn");
    }

    current_child_pid = -1;
    sigaction(SIGINT, &old, NULL);
}

static char *get_prompt(void) {
    if (geteuid() == 0) {
        return "# ";
    } else {
        return "$ ";
    }
}

int main(int argc, char **argv) {
    // Set up the signal handler for Ctrl+C
    struct sigaction sa = {.sa_handler = sigint_handler, .sa_flags = SA_RESTART};
    sigaction(SIGINT, &sa, NULL);

    const char *path_env = getenv("PATH");
    if (path_env == NULL) {
        path_env = "/bin:/usr/bin";
    }
    
    PathDirectories *dirs = parse_path(path_env);
    if (!dirs)
        return EXIT_FAILURE;

    // If command line arguments are provided, execute them and exit
    if (argc > 1) {
        process_args(argc - 1, argv + 1, dirs);
        cleanup_path_directories(dirs);
        return EXIT_SUCCESS;
    }

    // Normal interactive shell mode
    char input[MAX_INPUT_SIZE];
    while (1) {
        if (!get_user_input(input, sizeof(input))) {
            if (feof(stdin))
                break;
            if (errno == EINTR)
                continue;
            perror("input error");
            break;
        }
        process_command(input, dirs);
    }

    // Reached EOF (Ctrl+D)
    printf("\n");
    cleanup_path_directories(dirs);
    return EXIT_SUCCESS;
}
