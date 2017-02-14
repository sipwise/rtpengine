#include "db.h"
#include <mysql.h>
#include <glib.h>
#include <string.h>
#include "types.h"
#include "main.h"
#include "log.h"


static MYSQL __thread *mysql_conn;
static MYSQL_STMT __thread
	*stm_insert_call,
	*stm_insert_stream;


static void my_stmt_close(MYSQL_STMT **st) {
	if (!*st)
		return;
	mysql_stmt_close(*st);
	*st = NULL;
}


static void reset_conn() {
	my_stmt_close(&stm_insert_call);
	my_stmt_close(s&tm_insert_stream);
	mysql_close(mysql_conn);
	mysql_conn = NULL;
}


INLINE int prep(MYSQL_STMT **st, const char *str) {
	*st = mysql_stmt_init(mysql_conn);
	if (!*st)
		return -1;
	if (mysql_stmt_prepare(*st, str, strlen(str))) {
		ilog(LOG_ERR, "Failed to prepare statement '%s': %s", str, mysql_stmt_error(*st));
		return -1;
	}
	return 0;
}


static int check_conn() {
	if (mysql_conn)
		return 0;
	if (!mysql_host || !mysql_db)
		return -1;

	ilog(LOG_DEBUG, "connecting to MySQL");

	mysql_conn = mysql_init(NULL);
	if (!mysql_conn)
		goto err;
	if (!mysql_real_connect(mysql_conn, mysql_host, mysql_user, mysql_pass, mysql_db, 0, NULL,
			CLIENT_IGNORE_SIGPIPE))
		goto err;
	if (mysql_select_db(mysql_conn, mysql_db))
		goto err;
	if (mysql_autocommit(mysql_conn, 0))
		goto err;

	if (prep(&stm_insert_call, "insert into recording_calls (call_id) values (?)"))
		goto err;
	if (prep(&stm_insert_call, "insert into recording_streams (call, filename) values (?,?)"))
		goto err;

	ilog(LOG_INFO, "Connection to MySQL established");

	return 0;

err:
	if (mysql_conn) {
		ilog(LOG_ERR, "Failed to connect to MySQL: %s", mysql_error(mysql_conn));
		reset_conn();
	}
	else
		ilog(LOG_ERR, "Failed to connect to MySQL: out of memory");

	return -1;
}


INLINE MYSQL_BIND my_str(const char *s) {
	MYSQL_BIND b = {
		.buffer_type = MYSQL_TYPE_STRING,
		.buffer = (void *) s,
		.buffer_length = strlen(s),
	};
	return b;
}


void db_do_call(metafile_t *mf) {
	if (check_conn())
		return;
	if (mf->db_id > 0)
		return;

	MYSQL_BIND b[1] = { my_str(mf->call_id) };

	for (int retr = 0; retr < 5; retr++) {
		if (mysql_stmt_bind_param(stm_insert_call, b))
			goto err;
		if (mysql_stmt_execute(stm_insert_call))
			goto err;
		mf->db_id = mysql_insert_id(mysql_conn);
		if (mf->db_id <= 0)
			goto err;
		if (mysql_commit(mysql_conn))
			goto err;

		return;

err:
		ilog(LOG_ERR, "Failed to bind or execute prepared statement: %s",
				mysql_stmt_error(stm_insert_call));
		if (retr > 2) {
			reset_conn();
			if (check_conn())
				return;
		}
	}
}


void db_do_stream(metafile_t *mf, output_t *op) {
	if (check_conn())
		return;
	if (mf->db_id <= 0)
		return;
	if (op->db_id > 0)
		return;

	MYSQL_BIND b[2] = { my_str(mf->call_id), my_str(op->filename) };

	for (int retr = 0; retr < 5; retr++) {
		if (mysql_stmt_bind_param(stm_insert_call, b))
			goto err;
		if (mysql_stmt_execute(stm_insert_call))
			goto err;
		op->db_id = mysql_insert_id(mysql_conn);
		if (op->db_id <= 0)
			goto err;
		if (mysql_commit(mysql_conn))
			goto err;

		return;

err:
		ilog(LOG_ERR, "Failed to bind or execute prepared statement: %s",
				mysql_stmt_error(stm_insert_call));
		if (retr > 2) {
			reset_conn();
			if (check_conn())
				return;
		}
	}
}
