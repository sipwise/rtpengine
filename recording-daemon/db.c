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
	*stm_close_call,
	*stm_insert_stream,
	*stm_close_stream,
	*stm_config_stream;


static void my_stmt_close(MYSQL_STMT **st) {
	if (!*st)
		return;
	mysql_stmt_close(*st);
	*st = NULL;
}


static void reset_conn() {
	my_stmt_close(&stm_insert_call);
	my_stmt_close(&stm_close_call);
	my_stmt_close(&stm_insert_stream);
	my_stmt_close(&stm_close_stream);
	my_stmt_close(&stm_config_stream);
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
	if (!c_mysql_host || !c_mysql_db)
		return -1;

	ilog(LOG_DEBUG, "connecting to MySQL");

	mysql_conn = mysql_init(NULL);
	if (!mysql_conn)
		goto err;
	if (!mysql_real_connect(mysql_conn, c_mysql_host, c_mysql_user, c_mysql_pass, c_mysql_db, c_mysql_port,
			NULL, CLIENT_IGNORE_SIGPIPE))
		goto err;
	if (mysql_select_db(mysql_conn, c_mysql_db))
		goto err;
	if (mysql_autocommit(mysql_conn, 0))
		goto err;

	if (prep(&stm_insert_call, "insert into recording_calls (call_id) values (?)"))
		goto err;
	if (prep(&stm_insert_stream, "insert into recording_streams (`call`, local_filename, full_filename, " \
				"file_format, " \
				"output_type, " \
				"stream_id) values (?,?,?,?,?,?)"))
		goto err;
	if (prep(&stm_close_call, "update recording_calls set end_time = now() where id = ?"))
		goto err;
	if (prep(&stm_close_stream, "update recording_streams set end_time = now() where id = ?"))
		goto err;
	if (prep(&stm_config_stream, "update recording_streams set channels = ?, sample_rate = ? where id = ?"))
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


INLINE void my_str(MYSQL_BIND *b, const char *s) {
	*b = (MYSQL_BIND) {
		.buffer_type = MYSQL_TYPE_STRING,
		.buffer = (void *) s,
		.buffer_length = strlen(s),
		.length = &b->buffer_length,
	};
}
INLINE void my_ull(MYSQL_BIND *b, const unsigned long long *ull) {
	*b = (MYSQL_BIND) {
		.buffer_type = MYSQL_TYPE_LONGLONG,
		.buffer = (void *) ull,
		.buffer_length = sizeof(*ull),
		.is_unsigned = 1,
	};
}
INLINE void my_i(MYSQL_BIND *b, const int *i) {
	*b = (MYSQL_BIND) {
		.buffer_type = MYSQL_TYPE_LONG,
		.buffer = (void *) i,
		.buffer_length = sizeof(*i),
		.is_unsigned = 0,
	};
}


static void execute_wrap(MYSQL_STMT *stmt, MYSQL_BIND *binds, unsigned long long *auto_id) {
	for (int retr = 0; retr < 5; retr++) {
		if (mysql_stmt_bind_param(stmt, binds))
			goto err;
		if (mysql_stmt_execute(stmt))
			goto err;
		if (auto_id) {
			*auto_id = mysql_insert_id(mysql_conn);
			if (*auto_id <= 0)
				goto err;
		}
		if (mysql_commit(mysql_conn))
			goto err;

		return;

err:
		ilog(LOG_ERR, "Failed to bind or execute prepared statement: %s",
				mysql_stmt_error(stmt));
		if (retr > 2) {
			reset_conn();
			if (check_conn())
				return;
		}
	}
}


void db_do_call(metafile_t *mf) {
	if (check_conn())
		return;
	if (mf->db_id > 0)
		return;

	MYSQL_BIND b[1];
	my_str(&b[0], mf->call_id);

	execute_wrap(stm_insert_call, b, &mf->db_id);
}


void db_do_stream(metafile_t *mf, output_t *op, const char *type, unsigned int id) {
	if (check_conn())
		return;
	if (mf->db_id <= 0)
		return;
	if (op->db_id > 0)
		return;

	MYSQL_BIND b[6];
	my_ull(&b[0], &mf->db_id);
	my_str(&b[1], op->file_name);
	my_str(&b[2], op->full_filename);
	my_str(&b[3], op->file_format);
	my_str(&b[4], type);
	b[5] = (MYSQL_BIND) {
		.buffer_type = MYSQL_TYPE_LONG,
		.buffer = &id,
		.buffer_length = sizeof(id),
		.is_unsigned = 1,
	};

	execute_wrap(stm_insert_stream, b, &op->db_id);
}

void db_close_call(metafile_t *mf) {
	if (check_conn())
		return;
	if (mf->db_id <= 0)
		return;

	MYSQL_BIND b[1];
	my_ull(&b[0], &mf->db_id);

	execute_wrap(stm_close_call, b, NULL);
}
void db_close_stream(output_t *op) {
	if (check_conn())
		return;
	if (op->db_id <= 0)
		return;

	MYSQL_BIND b[1];
	my_ull(&b[0], &op->db_id);

	execute_wrap(stm_close_stream, b, NULL);
}

void db_config_stream(output_t *op) {
	if (check_conn())
		return;
	if (op->db_id <= 0)
		return;

	MYSQL_BIND b[3];
	my_i(&b[0], &op->actual_format.channels);
	my_i(&b[1], &op->actual_format.clockrate);
	my_ull(&b[2], &op->db_id);

	execute_wrap(stm_config_stream, b, NULL);
}
