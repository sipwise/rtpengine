#include "db.h"
#include <errno.h>
#include <mysql.h>
#include <glib.h>
#include <string.h>
#include <sys/time.h>
#include "types.h"
#include "main.h"
#include "log.h"
#include "tag.h"
#include "recaux.h"
#include "output.h"
#include "notify.h"


/*
CREATE TABLE `recording_calls` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `call_id` varchar(250) NOT NULL,
  `start_time` timestamp NOT NULL DEFAULT current_timestamp(),
  `end_time` datetime DEFAULT NULL,
  `start_timestamp` decimal(13,3) DEFAULT NULL,
  `end_timestamp` decimal(13,3) DEFAULT NULL,
  `status` enum('recording','completed','confirmed') DEFAULT 'recording',
  PRIMARY KEY (`id`),
  KEY `call_id` (`call_id`)
);
CREATE TABLE `recording_streams` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `call` int(10) unsigned NOT NULL,
  `local_filename` varchar(250) NOT NULL,
  `full_filename` varchar(250) NOT NULL,
  `file_format` varchar(10) NOT NULL,
  `output_type` enum('mixed','single') NOT NULL,
  `start_time` timestamp NOT NULL DEFAULT current_timestamp(),
  `end_time` datetime DEFAULT NULL,
  `stream_id` int(10) unsigned NOT NULL,
  `sample_rate` int(10) unsigned NOT NULL DEFAULT '0',
  `channels` int(10) unsigned NOT NULL DEFAULT '0',
  `ssrc` int(10) unsigned NOT NULL,
  `start_timestamp` decimal(13,3) DEFAULT NULL,
  `end_timestamp` decimal(13,3) DEFAULT NULL,
  `tag_label` varchar(255) NOT NULL DEFAULT '',
  `stream` longblob NOT NULL DEFAULT '',
  `transcript_status` enum('none','pending','done') NOT NULL DEFAULT 'none',
  `transcript` text NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `call` (`call`),
  KEY `transcript_status_call_idx` (`transcript_status`,`call`),
  CONSTRAINT `fk_call_id` FOREIGN KEY (`call`) REFERENCES `recording_calls` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE TABLE `recording_metakeys` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `call` int(10) unsigned NOT NULL,
  `key` char(255) NOT NULL,
  `value` char(255) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `prim_lookup` (`value`,`key`),
  KEY `fk_call_idx` (`call`),
  CONSTRAINT `fk_call_idx` FOREIGN KEY (`call`) REFERENCES `recording_calls` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
);
*/



struct db_conn {
	MYSQL *mysql_conn;

	MYSQL_STMT
		*stm_insert_call,
		*stm_close_call,
		*stm_delete_call,
		*stm_insert_stream,
		*stm_close_stream,
		*stm_delete_stream,
		*stm_config_stream,
		*stm_insert_metadata;
};
typedef struct db_conn db_conn_t;


static __thread db_conn_t *db_conn;


static void my_stmt_close(MYSQL_STMT **st) {
	if (!*st)
		return;
	mysql_stmt_close(*st);
	*st = NULL;
}


static void reset_conn(db_conn_t *dbc) {
	if (!dbc)
		return;

	if (dbc->mysql_conn) {
		my_stmt_close(&dbc->stm_insert_call);
		my_stmt_close(&dbc->stm_close_call);
		my_stmt_close(&dbc->stm_delete_call);
		my_stmt_close(&dbc->stm_insert_stream);
		my_stmt_close(&dbc->stm_close_stream);
		my_stmt_close(&dbc->stm_delete_stream);
		my_stmt_close(&dbc->stm_config_stream);
		my_stmt_close(&dbc->stm_insert_metadata);
		mysql_close(dbc->mysql_conn);
	}

	g_free(dbc);
}


INLINE int prep(db_conn_t *dbc, MYSQL_STMT **st, const char *s) {
	*st = mysql_stmt_init(dbc->mysql_conn);
	if (!*st)
		return -1;
	if (mysql_stmt_prepare(*st, s, strlen(s))) {
		ilog(LOG_ERR, "Failed to prepare statement '%s': %s", s, mysql_stmt_error(*st));
		return -1;
	}
	return 0;
}


static bool db_wanted(void) {
	return (c_mysql_host && c_mysql_db);
}


static db_conn_t *check_conn(void) {
	if (db_conn)
		return db_conn;

	dbg("connecting to MySQL");

	db_conn_t *dbc = g_new0(db_conn_t, 1);

	dbc->mysql_conn = mysql_init(NULL);
	if (!dbc->mysql_conn)
		goto err;
	if (!mysql_real_connect(dbc->mysql_conn, c_mysql_host, c_mysql_user, c_mysql_pass, c_mysql_db, c_mysql_port,
			NULL, CLIENT_IGNORE_SIGPIPE))
		goto err;
	if (mysql_select_db(dbc->mysql_conn, c_mysql_db))
		goto err;
	if (mysql_autocommit(dbc->mysql_conn, 0))
		goto err;

	if (prep(dbc, &dbc->stm_insert_call, "insert into recording_calls (call_id, start_timestamp, " \
				"`status`) " \
				"values " \
				"(?,?,'recording')"))
		goto err;
	if (prep(dbc, &dbc->stm_insert_stream, "insert into recording_streams (`call`, local_filename, full_filename, " \
				"file_format, " \
				"output_type, " \
				"stream_id, ssrc, " \
				"tag_label, " \
				"start_timestamp) values " \
				"(?,concat(?,'.',?),concat(?,'.',?),?,?,?,?,?,?)"))
		goto err;
	if (prep(dbc, &dbc->stm_close_call, "update recording_calls set " \
				"end_timestamp = ?, status = 'completed' where id = ? " \
				"and status != 'completed'"))
		goto err;
	if (prep(dbc, &dbc->stm_delete_call, "delete from recording_calls where id = ?"))
		goto err;
	if ((output_storage & OUTPUT_STORAGE_DB)) {
		if (prep(dbc, &dbc->stm_close_stream, "update recording_streams set " \
					"end_timestamp = ?, stream = ? where id = ?"))
			goto err;
	}
	else {
		if (prep(dbc, &dbc->stm_close_stream, "update recording_streams set " \
					"end_timestamp = ? where id = ?"))
			goto err;
	}
	if (prep(dbc, &dbc->stm_delete_stream, "delete from recording_streams where id = ?"))
		goto err;
	if (prep(dbc, &dbc->stm_config_stream, "update recording_streams set channels = ?, sample_rate = ? where id = ?"))
		goto err;
	if (prep(dbc, &dbc->stm_insert_metadata, "insert into recording_metakeys (`call`, `key`, `value`) values " \
				"(?,?,?)"))
		goto err;

	dbg("Connection to MySQL established");

	db_conn = dbc;

	return dbc;

err:
	if (dbc->mysql_conn)
		ilog(LOG_ERR, "Failed to connect to MySQL: %s", mysql_error(dbc->mysql_conn));
	else
		ilog(LOG_ERR, "Failed to connect to MySQL: out of memory");

	reset_conn(dbc);

	return NULL;
}


INLINE void my_str_len(MYSQL_BIND *b, const char *s, unsigned int len) {
	*b = (MYSQL_BIND) {
		.buffer_type = MYSQL_TYPE_STRING,
		.buffer = (void *) s,
		.buffer_length = len,
		.length = &b->buffer_length,
	};
}
INLINE void my_str(MYSQL_BIND *b, const str *s) {
	my_str_len(b, s->s, s->len);
}
INLINE void my_cstr(MYSQL_BIND *b, const char *s) {
	my_str_len(b, s, strlen(s));
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
INLINE void my_ts(MYSQL_BIND *b, int64_t ts, double *d) {
	*d = ((double) ts) / 1000000.;
	*b = (MYSQL_BIND) {
		.buffer_type = MYSQL_TYPE_DOUBLE,
		.buffer = (void *) d,
		.buffer_length = sizeof(*d),
		.is_unsigned = 0,
	};
}


static bool __execute_wrap(size_t stmt_offset, MYSQL_BIND *binds, unsigned long long *auto_id) {
	int retr = 0;
	while (1) {
		db_conn_t *dbc;
		MYSQL_STMT *stmt = NULL;
		if (!(dbc = check_conn()))
			goto err;
		stmt = G_STRUCT_MEMBER(MYSQL_STMT *, dbc, stmt_offset);
		if (mysql_stmt_bind_param(stmt, binds))
			goto err;
		if (mysql_stmt_execute(stmt))
			goto err;
		if (auto_id) {
			*auto_id = mysql_insert_id(dbc->mysql_conn);
			if (*auto_id == 0)
				goto err;
		}
		if (mysql_commit(dbc->mysql_conn))
			goto err;

		return true;

err:
		if (retr > 5) {
			// fatal
			if (stmt)
				ilog(LOG_ERR, "Failed to bind or execute prepared statement: %s",
						mysql_stmt_error(stmt));
			reset_conn(dbc);
			return false;
		}
		if (retr > 2) {
			reset_conn(dbc);
			if (!(dbc = check_conn()))
				return false;
		}

		retr++;
	}
}


#define execute_wrap(stmt, binds, auto_id) \
	__execute_wrap(G_STRUCT_OFFSET(db_conn_t, stmt), binds, auto_id)


static void db_do_call_id(metafile_t *mf) {
	if (mf->db_id > 0)
		return;
	if (!mf->call_id)
		return;
	if (mf->skip_db)
		return;
	if (!mf->started)
		return;

	MYSQL_BIND b[2];
	my_cstr(&b[0], mf->call_id);
	double ts;
	my_ts(&b[1], mf->start_time_us, &ts);

	execute_wrap(stm_insert_call, b, &mf->db_id);
}
static void db_do_call_metadata(metafile_t *mf) {
	if (mf->db_metadata_done)
		return;
	if (mf->db_id == 0)
		return;
	if (mf->skip_db)
		return;

	MYSQL_BIND b[3];
	my_ull(&b[0], &mf->db_id); // stays persistent

	__auto_type iter = t_hash_table_iter(mf->metadata_parsed);
	str *key;
	str_q *vals;
	while (t_hash_table_iter_next(&iter, &key, &vals)) {
		for (__auto_type l = vals->head; l; l = l->next) {
			my_str(&b[1], key);
			my_str(&b[2], l->data);

			execute_wrap(stm_insert_metadata, b, NULL);
		}
	}

	mf->db_metadata_done = 1;
}

void db_do_call(metafile_t *mf) {
	if (!db_wanted())
		return;

	db_do_call_id(mf);
	db_do_call_metadata(mf);
}


// mf is locked
void db_do_stream(metafile_t *mf, output_t *op, stream_t *stream, unsigned long ssrc) {
	if (!db_wanted())
		return;
	if (mf->db_id == 0)
		return;
	if (op->db_id > 0)
		return;
	if (mf->skip_db)
		return;

	unsigned long id = stream ? stream->id : 0;

	MYSQL_BIND b[11];
	my_ull(&b[0], &mf->db_id);
	my_cstr(&b[1], op->file_name);
	my_cstr(&b[2], op->file_format);
	my_cstr(&b[3], op->full_filename);
	my_cstr(&b[4], op->file_format);
	my_cstr(&b[5], op->file_format);
	my_cstr(&b[6], op->kind);
	b[7] = (MYSQL_BIND) {
		.buffer_type = MYSQL_TYPE_LONG,
		.buffer = &id,
		.buffer_length = sizeof(id),
		.is_unsigned = 1,
	};
	b[8] = (MYSQL_BIND) {
		.buffer_type = MYSQL_TYPE_LONG,
		.buffer = &ssrc,
		.buffer_length = sizeof(ssrc),
		.is_unsigned = 1,
	};
	if (stream && stream->tag != (unsigned long) -1) {
		tag_t *tag = tag_get(mf, stream->tag);
		my_cstr(&b[9], tag->label ? : "");
	}
	else
		my_cstr(&b[9], "");
	double ts;
	my_ts(&b[10], op->start_time_us, &ts);

	execute_wrap(stm_insert_stream, b, &op->db_id);

	if (op->db_id > 0)
		mf->db_streams++;
}

void db_close_call(metafile_t *mf) {
	if (!db_wanted())
		return;
	if (mf->db_id == 0)
		return;

	int64_t now = now_us();

	MYSQL_BIND b[2];

	if (mf->db_streams > 0) {
		double ts;
		my_ts(&b[0], now, &ts);
		my_ull(&b[1], &mf->db_id);
		execute_wrap(stm_close_call, b, NULL);
	}
	else {
		my_ull(&b[0], &mf->db_id);
		execute_wrap(stm_delete_call, b, NULL);
		mf->db_id = 0;
	}
}


static bool do_notify(notif_req_t *req) {
	if (!db_wanted())
		return false;

	MYSQL_BIND b[3];

	int par_idx = 0;
	double ts;
	my_ts(&b[par_idx++], req->end_time, &ts);
	if (req->content) {
		str stream = STR_GS(req->content->s);
		my_str(&b[par_idx++], &stream);
	}
	my_ull(&b[par_idx++], &req->db_id);

	bool ok = execute_wrap(stm_close_stream, b, NULL);

	// running in a thread pool, don't leave connection behind
	reset_conn(db_conn);

	return ok;
}


static void setup_notify(notif_req_t *req, output_t *o, metafile_t *mf, tag_t *tag) {
	req->end_time = now_us();
	if ((output_storage & OUTPUT_STORAGE_DB))
		req->content = output_get_content(o);
}

static void cleanup_notify(notif_req_t *req) {
	obj_release(req->content);
}

static const notif_action_t db_action = {
	.name = "DB",
	.setup = setup_notify,
	.perform = do_notify,
	.cleanup = cleanup_notify,
};

void db_close_stream(output_t *op) {
	if (!c_mysql_host || !c_mysql_db)
		return;

	if (op->db_id == 0) {
		if (!(output_storage & OUTPUT_STORAGE_DB))
			return;
		ilog(LOG_ERR, "DB storage requested but no entry exists");
		content_t *content = output_get_content(op);
		if (content)
			output_content_failure(content);
		obj_release(content);
	}

	notify_push_setup(&db_action, op, NULL, NULL);
}


void db_delete_stream(metafile_t *mf, output_t *op) {
	if (!db_wanted())
		return;
	if (op->db_id == 0)
		return;

        MYSQL_BIND b[1];
	my_ull(&b[0], &op->db_id);

	execute_wrap(stm_delete_stream, b, NULL);

	mf->db_streams--;
}

void db_config_stream(output_t *op) {
	if (!db_wanted())
		return;
	if (op->db_id == 0)
		return;

	MYSQL_BIND b[3];
	my_i(&b[0], &op->encoder->actual_format.channels);
	my_i(&b[1], &op->encoder->actual_format.clockrate);
	my_ull(&b[2], &op->db_id);

	execute_wrap(stm_config_stream, b, NULL);
}

void db_thread_end(void) {
	reset_conn(db_conn);
	db_conn = NULL;
}
