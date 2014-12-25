/*
 * picodb.h
 *
 * Pico Debugger (picodb) API.
 */

#ifndef PICODB_H_
#define PICODB_H_

#include <sys/types.h>

#define PDB_REDIRECTFAIL	10
#define PDB_WRITEFAIL		9
#define PDB_READFAIL		8
#define PDB_OPENFAIL		7
#define PDB_CLOSEFAIL		6
#define PDB_PIPEFAIL		5
#define PDB_WAITFAIL		4
#define PDB_EXECFAIL		3
#define PDB_FORKFAIL		2
#define PDB_FAILURE			1		/* failure to perform the required action */
#define PDB_SUCCESS			0		/* success */

#define PDB_BUFSIZE			(FILENAME_MAX << 1)

/*
 *
 */
typedef struct Picodb {
	int traceOptions;
	int blockingMode;
	int limitProcessControl;
	int limitFileManagement;
	char stdinFilename[FILENAME_MAX];
	char stdoutFilename[FILENAME_MAX];
	char stderrFilename[FILENAME_MAX];
	int pipefdstdin[2];
	int pipefdstdout[2];
	int pipefdstderr[2];
	pid_t tracedpid;
} Picodb;

#define PDB_STDIN	0
#define PDB_STDOUT	1
#define PDB_STDERR	2

#define IS_STDIN_REDIRECTED(pdb) ((pdb).stdinFilename[0] != '\0')
#define IS_STDOUT_REDIRECTED(pdb) ((pdb).stdoutFilename[0] != '\0')
#define IS_STDERR_REDIRECTED(pdb) ((pdb).stderrFilename[0] != '\0')

/*
 * Initialize picodb. Everything is turned off by default.
 */
void pdb_init(Picodb *pdb);

/*
 * Display the picodb command prompt.
 */
int pdb_prompt(Picodb *pdb);

/*
 * Read the contents of the file specified earlier and write to the pipe used
 * for stdin stream redirection.
 */
int pdb_feed_stdin_pipe(Picodb *pdb);

/*
 * Read the stream of the pipe used for stdout stream redirection and write them
 * to the file specified earlier.
 */
int pdb_feed_stdout_pipe(Picodb *pdb);

/*
 * Read the stream of the pipe used for stderr stream redirection and write them
 * to the file specified earlier.
 */
int pdb_feed_stderr_pipe(Picodb *pdb);

/*
 * Redirect stdin/stdout/stderr streams, if requested by the user.
 */
int pdb_redirect(Picodb *pdb);

/*
 * Utility function used for closing both ends of redirection pipes.
 */
int pdb_close_pipes(Picodb *pdb);

/*
 * Send the signal identified by number signo to the program being traced.
 */
void pdb_send_signal(int signo);

/*
 * Tell picodb to send any received signals of type SIGHUP, SIGINT and SIGTERM
 * to the program being traced (identified by cpid).
 */
void pdb_register_signals(Picodb *pdb);

/*
 * Tell picodb not to send any signals to the program being traced.
 */
void pdb_unregister_signals(void);

/*
 * Run, wait for and trace the executable given.
 * The core of picodb.
 */
int pdb_run(Picodb *pdb, pid_t cpid, const char *executable);

/*
 * Show the available commands of the picodb prompt.
 */
void help(void);

#endif /* PICODB_H_ */
