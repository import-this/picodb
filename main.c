/*
 * main.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <wait.h>
#include <fcntl.h>
#include <signal.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ptrace.h>


#include "picodb.h"

/*
 * Just print out how to call picodb.
 */
void usage(char *progname)
{
	fprintf(stderr, "Usage: %s <executable>\n", progname);
}

int main(int argc, char *argv[])
{
	Picodb pdb;
	pid_t cpid;
	pid_t stdinpid, stdoutpid, stderrpid;
	int status;

	if (argc != 2) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	pdb_init(&pdb);
	/* Command prompt */
	puts("picodb v1.0\nType \"help\" for help or \"quit\" for exit");
	for (;;) {
		/* Display the command prompt. */
		if (pdb_prompt(&pdb) == 1)
			break;
		/* Prepare the redirection requests, if any. */
		if (IS_STDIN_REDIRECTED(pdb)) {
			if (pipe(pdb.pipefdstdin) == -1) {
				perror("Error creating pipe");
				exit(PDB_PIPEFAIL);
			}
			if ((stdinpid = fork()) == -1) {
				perror("fork error");
				exit(PDB_FORKFAIL);
			}
			if (stdinpid == 0)	 	/* Child for stdin redirection handling */
				_Exit(pdb_feed_stdin_pipe(&pdb));
		}
		if (IS_STDOUT_REDIRECTED(pdb)) {
			if (pipe(pdb.pipefdstdout) == -1) {
				perror("Error creating pipe");
				exit(PDB_PIPEFAIL);
			}
			if ((stdoutpid = fork()) == -1) {
				perror("fork error");
				exit(PDB_FORKFAIL);
			}
			if (stdoutpid == 0)	 	/* Child for stdout redirection handling */
				_Exit(pdb_feed_stdout_pipe(&pdb));
		}
		if (IS_STDERR_REDIRECTED(pdb)) {
			if (pipe(pdb.pipefdstderr) == -1) {
				perror("Error creating pipe");
				exit(PDB_PIPEFAIL);
			}
			if ((stderrpid = fork()) == -1) {
				perror("fork error");
				exit(PDB_FORKFAIL);
			}
			if (stderrpid == 0)	 	/* Child for stderr redirection handling */
				_Exit(pdb_feed_stderr_pipe(&pdb));
		}

		/* Run the executable. */
		printf("Starting program tracing for %s\n", argv[1]);
		if ((cpid = fork()) == -1) {
			perror("fork error");
			exit(EXIT_FAILURE);
		}
		if (cpid == 0) {							/* Executable */
			/* Handle the redirection requests, if any. */
			if (pdb_redirect(&pdb) == PDB_REDIRECTFAIL)
				_Exit(PDB_REDIRECTFAIL);
			printf("Starting tracing %s...", argv[1]);
			if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
				perror("ptrace error");
				_Exit(PDB_FAILURE);
			}
			execl(argv[1], argv[1], NULL);
			perror("Error running executable");
			_Exit(PDB_EXECFAIL);
		}
		if (pdb_close_pipes(&pdb) == PDB_CLOSEFAIL)
			exit(PDB_CLOSEFAIL);

		/* picodb execution and inspection */
		pdb_run(&pdb, cpid, argv[1]);

		/* Close redirection streams */
		if (IS_STDIN_REDIRECTED(pdb)) {
			puts("Waiting for stdin redirection to close...");
			if (waitpid(stdinpid, &status, 0) == -1) {
				perror("Error waiting child process");
				exit(PDB_WAITFAIL);
			}
		}
		if (IS_STDOUT_REDIRECTED(pdb)) {
			puts("Waiting for stdout redirection to close...");
			if (waitpid(stdoutpid, &status, 0) == -1) {
				perror("Error waiting child process");
				exit(PDB_WAITFAIL);
			}
		}
		if (IS_STDERR_REDIRECTED(pdb)) {
			puts("Waiting for stderr redirection to close...");
			if (waitpid(stderrpid, &status, 0) == -1) {
				perror("Error waiting child process");
				exit(PDB_WAITFAIL);
			}
		}
	}
	return EXIT_SUCCESS;
}
