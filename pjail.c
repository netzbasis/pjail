#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <paths.h>

/* length of all promises with space between them plus a NUL */
#define MAXLEN_PROMISE 191
#define NUMBER_PROMISES 33
#define EXIT_NO_PROMISES 2
#define EXIT_INVALID_PROMISE 3
#define EXIT_INVALID_UNVEIL 4

const char *allpromises[] = {
    "stdio", "rpath", "wpath", "cpath", "dpath", "tmppath", "inet",
    "mcast", "fattr", "chown", "flock", "unix", "dns", "getpw", "sendfd",
    "recvfd", "tape", "tty", "proc", "exec", "prot_exec", "settime", "ps",
    "vminfo", "id", "pf", "route", "wroute", "audio", "video", "bpf",
    "unveil", "error", NULL
};


int  validpromise(const char *);
int  isunveilperm(const char);
int  validunveil(const char*);
void appendpromise(const char **, const char *);
void invertpromises(const char **);
void listpromises(void);
void usage(void);
void pledgefmt(char *, int, const char **);


int
main(int argc, char **argv)
{
    int ch, invert, verbose, restriction;
    char pledgestr[MAXLEN_PROMISE];
    char *shell, *uoption;
    char *shellargv[2] = {NULL};
    const char *promises[NUMBER_PROMISES+1] = {NULL};

    pledgestr[0] = '\0';
    invert = verbose = restriction = 0;
    uoption = NULL;

    while ((ch = getopt(argc, argv, "d:hilo:p:v")) != -1) {
        switch(ch) {
        case 'd':
            if (!uoption) {
                fprintf(stderr, "Unveil options must be specified before a directory.\n");
                exit(EXIT_FAILURE);
            }
            if (unveil(optarg, uoption) != 0) {
                perror("Failed to unveil");
                exit(EXIT_FAILURE);
            }
            restriction = 1;
            break;
        case 'h':
            usage();
            exit(EXIT_SUCCESS);
        case 'i':
            invert = 1;
            break;
        case 'l':
            listpromises();
            exit(EXIT_SUCCESS);
        case 'o':
            if (!validunveil(optarg)) {
                fprintf(stderr, "%s is not a valid unveil permission string\n", optarg);
                exit(EXIT_INVALID_UNVEIL);
            }
            uoption = optarg;
            break;
        case 'p':
            if (!validpromise(optarg)) {
                fprintf(stderr, "%s is not a valid pledge\n", optarg);
                exit(EXIT_INVALID_PROMISE);
            }
            appendpromise(promises, optarg);
            restriction = 1;
            break;
        case 'v':
            verbose = 1;
            break;
        default:
            usage();
            exit(EXIT_FAILURE);
        }
    }

    argc -= optind;
    argv += optind;


    if (!restriction) {
        fprintf(stderr, "No restrictions\n");
        usage();
        exit(EXIT_NO_PROMISES);
    }

    if (invert)
        invertpromises(promises);

    pledgefmt(pledgestr, MAXLEN_PROMISE, promises);

    if (verbose)
        fprintf(stderr,"pledge string: %s\n", pledgestr);

    if (pledge("stdio exec", pledgestr) != 0)
        perror("Pledge failed");

    if (argc == 0) {
        shell = getenv("SHELL");
        if (!shell)
            shell = _PATH_BSHELL;
        shellargv[0] = shell;
        fprintf(stderr, "No command specified, defaulting to %s\n", shell);
        execv(shell, shellargv);
    }

    execvp(argv[0], argv);
    perror("Exec failed");
    return EXIT_FAILURE;
}

void
usage(void)
{
    printf("pjail: [-hilv] [-p <promise>] [-o <permissions>] [-d <directory>] [command] [args...]\n");
}

void
listpromises(void)
{
    const char *p, **ap;

    ap = allpromises;
    while ((p = *ap++))
        puts(p);
}

int
validpromise(const char *promise)
{
    const char *p, **ap;

    ap = allpromises;
    while ((p = *ap++))
        if ((strcmp(promise, p)) == 0)
            return 1;
    return 0;
}

void
appendpromise(const char **promises, const char *promise)
{
    const char *p, **op;

    op = promises;
    while ((p = *op)) {
        if (strcmp(p, promise) == 0)
            return;
        op++;
    }
    *op = promise;
    assert(op[1] == NULL);
}

void
pledgefmt(char *s, int size, const char **promises)
{
    const char *p, **op;

    op = promises;
    while ((p = *op++)) {
        strlcat(s, p, size);
        if (*op != NULL)
            strlcat(s, " ", size);
    }
}

void
invertpromises(const char **promises)
{
    const char *p, *u, **ap, **au, **pr;
    const char *unwanted[NUMBER_PROMISES+1] = {NULL};

    pr = promises;
    au = unwanted;
    while ((*au++ = *pr++))
        ;

    ap = allpromises;
    while ((p = *ap++)) {
        au = unwanted;
        while ((u = *au++))
            if (strcmp(u, p) == 0)
                goto outer;
        *promises++ = p;
    outer:;
    }
    *promises = NULL;
}

int
validunveil(const char *perms)
{
    char c;
    while ((c = *perms++))
        if (!isunveilperm(c))
            return 0;
    return 1;
}

int
isunveilperm(const char perm)
{
    return strchr("rwxc", perm) != NULL;
}
