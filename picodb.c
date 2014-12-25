/*
 * picodb.c
 *
 * Pico Debugger (picodb) Implementation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <signal.h>

#include <unistd.h>
#include <wait.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/reg.h>			/* Register names */
#include <sys/user.h>
#include <sys/syscall.h>		/* System call symbolic constants */
#include <sys/stat.h>

#include "picodb.h"

#define ARGUMENT_LEN FILENAME_MAX
#define WORDSIZE 4

int pdb_pid;

/*
 *
 */
static void read_trace(Picodb *pdb, const char *input, int count)
{
	char argument[ARGUMENT_LEN];	/* Command argument buffer */
	char ch;

	if ((count = sscanf(&input[count], "%*c %16s %1s", argument, &ch)) != 1) {
		/* Error reading argument */
		if (count == EOF)
			fprintf(stderr, "Error occurred while reading argument\n");
		/* No argument given */
		else if (count == 0)
			fprintf(stderr, "trace command must take one argument\n");
		/* Garbage at the end */
		else if (count == 2)
			fprintf(stderr, "Invalid syntax\n");
		fprintf(stderr, "trace command usage:\ntrace\t<category>\n"
				"t\t<category>\n"
				"<category> must be one of the following:\n"
				"\tprocess-control\n\tfile-management\n\tall\n");
		return;
	}
	/* Correct syntax - sscanf returned 2 */
	if (strcmp(argument, "process-control") == 0) {
		pdb->traceOptions = 1;
		puts("Tracing for process control");
	}
	else if (strcmp(argument, "file-management") == 0) {
		pdb->traceOptions = 2;
		puts("Tracing for file management");
	}
	else if (strcmp(argument, "all") == 0) {
		pdb->traceOptions = 3;
		puts("Tracing all");
	}
	else {
		fprintf(stderr, "Unknown command argument: %s\n", argument);
		fprintf(stderr, "trace command usage:\ntrace\t<category>\n"
				"t\t<category>\n"
				"<category> must be one of the following:\n"
				"\tprocess-control\n\tfile-management\n\tall\n");
	}
}

/*
 *
 */
static void read_redirect(Picodb *pdb, const char *input, int count)
{
	char stream[7];		/* the name of the stream to redirect to */
	char filename[FILENAME_MAX];
	char ch;

	count = sscanf(&input[count], "%*c %6s %4096s %c", stream, filename, &ch);
	if (count != 2) {
		/* Error reading argument */
		if (count == EOF)
			fprintf(stderr, "Error occurred while reading argument\n");
		/* No argument given */
		else if (count == 0 || count == 1)
			fprintf(stderr, "redirect command must take two arguments\n");
		/* Garbage at the end */
		else if (count == 3)
			fprintf(stderr, "Invalid syntax\n");
		fprintf(stderr,"redirect command usage:\n"
			"redirect\t<stream> <filename>\n"
			"r\t<stream> <filename>\n"
			"<stream> must be one of the following:\n"
			"\tstdin\n\tstdout\n\tstderr\n"
			"<filename> in case of stdin must exist)\n");
		return;
	}
	/* Correct syntax - sscanf returned 2 */
	if (strcmp(stream, "stdin") == 0) {
		if (access(filename, F_OK) == -1) {
			fprintf(stderr, "File \"%s\" does not exist.\n", filename);
			return;
		}
		strcpy(pdb->stdinFilename, filename);
		printf("File \"%s\" will be redirected to stdin\n", filename);
	}
	else if (strcmp(stream, "stdout") == 0) {
		strcpy(pdb->stdoutFilename, filename);
		printf("stdout will be redirected to file \"%s\"\n", filename);
	}
	else if (strcmp(stream, "stderr") == 0) {
		strcpy(pdb->stderrFilename, filename);
		printf("stderr will be redirected to file \"%s\"\n", filename);
	}
	else {
		fprintf(stderr, "Unknown stream: %s\n", stream);
		fprintf(stderr,
			"redirect command usage:\n"
			"redirect\t<stream> <filename>\n"
			"r\t<stream> <filename>\n"
			"<stream> must be one of the following:\n"
			"\tstdin\n\tstdout\n\tstderr\n"
			"<filename> must be a file name (in case of stdin, it must exist)\n");
	}
}

/*
 *
 */
static void read_blocking_mode(Picodb *pdb, const char *input, int count)
{
	char mode[4];
	char ch;

	if ((count = sscanf(&input[count], "%*c %3s %1s", mode, &ch)) != 1) {
		/* Error reading argument */
		if (count == EOF)
			fprintf(stderr, "Error occurred while reading argument\n");
		/* No argument given */
		else if (count == 0)
			fprintf(stderr, "blocking-mode command must take one argument\n");
		/* Garbage at the end */
		else if (count == 2)
			fprintf(stderr, "Invalid syntax\n");
		fprintf(stderr, "blocking-mode command usage:\n"
				"blocking-mode\t<mode>\n"
				"t\t<mode>\n"
				"<mode> must be one of the following:\n"
				"\ton\n\toff\n");
		return;
	}
	/* Correct syntax - sscanf returned 2 */
	if (strcmp(mode, "on") == 0) {
		pdb->blockingMode = 1;
		puts("Blocking mode on");
	}
	else if (strcmp(mode, "off") == 0) {
		pdb->blockingMode = 0;
		puts("Blocking mode off");
	}
	else {
		fprintf(stderr, "Unknown mode: %s\n", mode);
		fprintf(stderr, "blocking-mode command usage:\n"
						"blocking-mode\t<mode>\n"
						"t\t<mode>\n"
						"<mode> must be one of the following:\n"
						"\ton\n\toff\n");
	}
}

/*
 *
 */
static void read_limit_trace(Picodb *pdb, const char *input, int count)
{
	int limit;
	char ch;

	if ((count = sscanf(&input[count], "%*c %d %1s", &limit, &ch)) != 1) {
		/* Error reading argument */
		if (count == EOF)
			fprintf(stderr, "Error occurred while reading argument\n");
		/* No argument given */
		else if (count == 0)
			fprintf(stderr, "limit-trace command must take one numerical "
					"argument\n");
		/* Garbage at the end */
		else if (count == 2)
			fprintf(stderr, "Invalid syntax\n");
		fprintf(stderr, "limit-trace command usage:\nlimit-trace\t<number>\n"
				"t\t<number>\n"
				"<number> is the maximum number of system calls\n");
		return;
	}
	/* Correct syntax - sscanf returned 2 */
	pdb->limitFileManagement = pdb->limitProcessControl = limit;
	printf("Limit system calls to %d\n", limit);
}

/******************************************************************************/

void pdb_init(Picodb *pdb)
{
	assert(pdb);
	pdb->traceOptions = 0;
	pdb->blockingMode = 0;
	pdb->limitFileManagement = -1;
	pdb->limitProcessControl = -1;
	pdb->stdinFilename[0] = '\0';
	pdb->stdoutFilename[0] = '\0';
	pdb->stderrFilename[0] = '\0';
	pdb->tracedpid = -1;
}
/*
 * fix go
 */
int pdb_prompt(Picodb *pdb)
{
	char input[PDB_BUFSIZE];		/* Input buffer */
	char command[14];				/* Command buffer */
	int count;

	do {
		fputs("(picodb)>>> ", stdout);
		fgets(input, PDB_BUFSIZE, stdin);
		/* Read the command name, plus the next character (for checking). */
		sscanf(input, " %13s%n", command, &count);
		/* trace (t) <category> */
		if (strcmp(command, "t") == 0 || strcmp(command, "trace") == 0)
			read_trace(pdb, input, count);
		/* redirect (r) <stream> <filename> */
		else if (strcmp(command, "r") == 0 ||
				strcmp(command, "redirect") == 0)
			read_redirect(pdb, input, count);
		/* blocking-mode <mode> */
		else if (strcmp(command, "b") == 0 ||
				strcmp(command, "blocking-mode") == 0)
			read_blocking_mode(pdb, input, count);
		/* limit-trace <number> */
		else if (strcmp(command, "l") == 0 ||
				strcmp(command, "limit-trace") == 0)
			read_limit_trace(pdb, input, count);
		/* go */
		else if (strcmp(command, "g") == 0 || strcmp(command, "go") == 0)
			break;
		/* quit */
		else if (strcmp(command, "q") == 0 || strcmp(command, "quit") == 0)
			return 1;
		/* help */
		else if (strcmp(command, "h") == 0 || strcmp(command, "help") == 0)
			help();
		else
			fprintf(stderr, "Invalid command: %s. Try \"help\".\n", command);
	} while (1);
	return 0;
}

/****************************** Setup Functions *******************************/

int pdb_feed_stdin_pipe(Picodb *pdb)
{
	int fd;
	ssize_t count;
	char buf[512];

	if (close(pdb->pipefdstdin[0]) == -1) {
		perror("Error closing end of pipe");
		return PDB_CLOSEFAIL;
	}
	if ((fd = open(pdb->stdinFilename, O_RDONLY, 0)) == -1) {
		perror("Error opening file for redirection");
		return PDB_OPENFAIL;
	}

	for (;;) {
		if ((count = read(fd, buf, sizeof buf)) == -1) {
			perror("Error reading from file");
			return PDB_READFAIL;
		}
		if (count == 0)
			break;
		if (write(pdb->pipefdstdin[1], buf, (size_t) count) == -1) {
			perror("Error writing to pipe");
			return PDB_WRITEFAIL;
		}
	}

	if (close(fd) == -1) {
		perror("Error closing file descriptor for I/O file");
		return PDB_CLOSEFAIL;
	}
	if (close(pdb->pipefdstdin[1]) == -1) {
		perror("Error closing redirection pipe");
		return PDB_CLOSEFAIL;
	}
	return PDB_SUCCESS;
}

/*
 * Helper function used for feeding stdout/stderr pipes.
 */
static int feed_pipe(int pipefd[2], const char *filename)
{
	int fd;
	ssize_t count;
	char buf[512];

	if (close(pipefd[1]) == -1) {
		perror("Error closing end of pipe");
		return PDB_CLOSEFAIL;
	}
	if ((fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)) == -1) {
		perror("Error opening file for redirection");
		return PDB_OPENFAIL;
	}

	for (;;) {
		if ((count = read(pipefd[0], buf, sizeof buf)) == -1) {
			perror("Error reading from pipe");
			return PDB_READFAIL;
		}
		if (count == 0)
			break;
		if (write(fd, buf, (size_t) count) == -1) {
			perror("Error writing to pipe");
			return PDB_WRITEFAIL;
		}
	}

	if (close(fd) == -1) {
		perror("Error closing file descriptor for I/O file");
		return PDB_CLOSEFAIL;
	}
	if (close(pipefd[0]) == -1) {
		perror("Error closing redirection pipe");
		return PDB_CLOSEFAIL;
	}
	return PDB_SUCCESS;
}

int pdb_feed_stdout_pipe(Picodb *pdb)
{
	return feed_pipe(pdb->pipefdstdout, pdb->stdoutFilename);
}

int pdb_feed_stderr_pipe(Picodb *pdb)
{
	return feed_pipe(pdb->pipefdstderr, pdb->stderrFilename);
}

/*
 * Redirect the fromfd stream to tofd stream.
 */
static int redirect(int fromfd, int tofd)
{
	if (close(tofd) == -1) {
		perror("Error performing redirection - close");
		return PDB_CLOSEFAIL;
	}
	if (dup2(fromfd, tofd) == -1) {
		perror("Error performing redirection - dup2");
		return PDB_FAILURE;
	}
	if (close(fromfd) == -1) {
		perror("Error performing redirection - close");
		return PDB_CLOSEFAIL;
	}
	return PDB_SUCCESS;
}

int pdb_redirect(Picodb *pdb)
{
	if (IS_STDIN_REDIRECTED(*pdb))
		if (redirect(pdb->pipefdstdin[0], STDIN_FILENO) != PDB_SUCCESS)
			return PDB_REDIRECTFAIL;
	if (IS_STDOUT_REDIRECTED(*pdb))
		if (redirect(pdb->pipefdstdout[1], STDOUT_FILENO) != PDB_SUCCESS)
			return PDB_REDIRECTFAIL;
	if (IS_STDERR_REDIRECTED(*pdb))
		if (redirect(pdb->pipefdstderr[1], STDERR_FILENO) != PDB_SUCCESS)
			return PDB_REDIRECTFAIL;
	return PDB_SUCCESS;
}

int pdb_close_pipes(Picodb *pdb)
{
	if (IS_STDIN_REDIRECTED(*pdb)) {
		if (close(pdb->pipefdstdin[0]) == -1) {
			perror("Error closing write end of pipe");
			return PDB_CLOSEFAIL;
		}
		if (close(pdb->pipefdstdin[1]) == -1) {
			perror("Error closing write end of pipe");
			return PDB_CLOSEFAIL;
		}
	}
	if (IS_STDOUT_REDIRECTED(*pdb)) {
		if (close(pdb->pipefdstdout[0]) == -1) {
			perror("Error closing write end of pipe");
			return PDB_CLOSEFAIL;
		}
		if (close(pdb->pipefdstdout[1]) == -1) {
			perror("Error closing write end of pipe");
			return PDB_CLOSEFAIL;
		}
	}
	if (IS_STDERR_REDIRECTED(*pdb)) {
		if (close(pdb->pipefdstderr[1]) == -1) {
			perror("Error closing write end of pipe");
			return PDB_CLOSEFAIL;
		}
		if (close(pdb->pipefdstderr[0]) == -1) {
			perror("Error closing write end of pipe");
			return PDB_CLOSEFAIL;
		}
	}
	return PDB_SUCCESS;
}

/****************************** Signal Handling *******************************/

/*
 *
 */
void pdb_send_signal(int signo)
{
	puts("sending signal");
	if (kill(pdb_pid, signo) == -1)
		perror("Error sending signal to child process");
}

/*
 * The signals are registered using the more portable sigaction system call.
 */
void pdb_register_signals(Picodb *pdb)
{
	struct sigaction act;

	pdb_pid = pdb->tracedpid;
	act.sa_handler = pdb_send_signal;
	act.sa_flags = SA_RESTART;			/* Make wait system call restart */
	sigfillset(&act.sa_mask);
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
}

void pdb_unregister_signals(void)
{
	struct sigaction act;

	act.sa_handler = SIG_DFL;
	sigfillset(&act.sa_mask);
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
}

/*
 * Helper function for printing system calls.
 * Used to avoid boilerplate code.
 */
static void call(const char *syscallname, int *called, int *in, int *limit,
		long orig_eax)
{
	*called = 1;
	if (*in) {
		*in = 0;
		printf("%s system call: code %ld\n", syscallname, orig_eax);
		if (*limit > 0)
			(*limit)--;
	}
	else {
		*in = 1;
	}
}

int pdb_run(Picodb *pdb, pid_t cpid, const char *executable)
{
	int inexecve = 1, infork = 1, inclone = 1, inwait4 = 1, inkill = 1;
	int inopen = 1, inclose = 1, inread = 1, inwrite = 1;
	int called = 0;
	int status;
	long orig_eax;

	/* Handle signals SIGHUP, SIGINT and SIGTERM. */
	pdb->tracedpid = cpid;
	pdb_register_signals(pdb);
	printf("Starting %s...\n", executable);
	for (;;) {
		/* Wait for executable */
		if (waitpid(cpid, &status, 0) == -1) {
			perror("Error waiting child process");
			exit(PDB_WAITFAIL);
		}
		/* Check out the manual page of "wait" for this */
		if (WIFEXITED(status)) {
			printf("Traced program exited with value %d.\n",
					WEXITSTATUS(status));
			break;
		} else if (WIFSIGNALED(status)) {
			printf("Traced program killed by signal %d.\n",
					WTERMSIG(status));
			break;
		} else if (WIFSTOPPED(status)) {
			int signo = WSTOPSIG(status);

			/* If the executable received one of the handled signals,
			 * send it back */
			if (signo == SIGHUP || signo == SIGINT || signo == SIGTERM) {
				ptrace(PTRACE_SYSCALL, cpid, NULL, WSTOPSIG(status));
				if (waitpid(cpid, &status, 0) == -1) {
					perror("Error waiting child process");
					exit(PDB_WAITFAIL);
				}
				break;
			}
		} else if (WIFCONTINUED(status)) {
			printf("Continued.\n");
		}

		orig_eax = ptrace(PTRACE_PEEKUSER, cpid, WORDSIZE * ORIG_EAX, NULL);
		if (pdb->traceOptions == 3 || pdb->traceOptions == 1)
			if (pdb->limitProcessControl == -1 || pdb->limitProcessControl > 0) {
				switch (orig_eax) {
				case SYS_execve:
					call("execve", &called, &inexecve, &pdb->limitProcessControl, orig_eax);
					break;
				case SYS_fork:
					call("fork", &called, &infork, &pdb->limitProcessControl, orig_eax);
					break;
				case SYS_clone:
					call("clone", &called, &inclone, &pdb->limitProcessControl, orig_eax);
					break;
				case SYS_wait4:
					call("wait4", &called, &inwait4, &pdb->limitProcessControl, orig_eax);
					break;
				case SYS_kill:
					call("kill", &called, &inkill, &pdb->limitProcessControl, orig_eax);
					break;
				default:
					break;
				}
			}
		if (pdb->traceOptions == 3 || pdb->traceOptions == 2)
			if (pdb->limitFileManagement == -1 || pdb->limitFileManagement > 0) {
				switch (orig_eax) {
				case SYS_open:
					call("open", &called, &inopen, &pdb->limitFileManagement, orig_eax);
					break;
				case SYS_close:
					call("close", &called, &inclose, &pdb->limitFileManagement, orig_eax);
					break;
				case SYS_read:
					call("read", &called, &inread,&pdb->limitFileManagement,  orig_eax);
					break;
				case SYS_write:
					call("write", &called, &inwrite, &pdb->limitFileManagement, orig_eax);
					break;
				default:
					break;
				}
			}

		if (called && pdb->blockingMode) {
			int ch;

			called = 0;
			puts("Do you want to continue tracing? (y/n)");
			ch = getchar();
			while (getchar() != '\n') {}
			if (ch == 'n') {
				ptrace(PTRACE_KILL, cpid, NULL, NULL);
				if (waitpid(cpid, &status, 0) == -1) {
					perror("Error waiting child process");
					exit(PDB_WAITFAIL);
				}
				break;
			}
		}
		ptrace(PTRACE_SYSCALL, cpid, NULL, NULL);
	}
	pdb_unregister_signals();
	return PDB_SUCCESS;
}

/******************************************************************************/

void help(void)
{
	printf("Available commands:\n"
"trace <category>: Trace the system calls in <category>\n"
"\tcategory must be one of the following:\n"
"\t\tprocess-control, file-management, all\n"
"redirect <stream> <filename>: Redirect the <stream> of the executable\n"
"\tto file <filename> \n"
"\tstream must be one of the following:\n");
	printf("\t\tstdin, stdout, stderr\n"
"blocking-mode <mode>: Tell whether to stop execution at a system call\n"
"\tmode must be one of the following:\n"
"\t\ton, off\n"
"go: Run the executable according to the options given already\n"
"quit: Quit picodb\n"
"help: Print the above message\n");
}
