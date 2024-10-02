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


/*
CREATE TABLE `recording_calls` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `call_id` varchar(250) NOT NULL,
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
  `stream` mediumblob,
  `output_type` enum('mixed','single') NOT NULL,
  `stream_id` int(10) unsigned NOT NULL,
  `sample_rate` int(10) unsigned NOT NULL DEFAULT '0',
  `channels` int(10) unsigned NOT NULL DEFAULT '0',
  `ssrc` int(10) unsigned NOT NULL,
  `start_timestamp` decimal(13,3) DEFAULT NULL,
  `end_timestamp` decimal(13,3) DEFAULT NULL,
  `tag_label` varchar(255) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `call` (`call`),
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



static __thread MYSQL *mysql_conn;
static __thread MYSQL_STMT
	*stm_insert_call,
	*stm_close_call,
	*stm_delete_call,
	*stm_insert_stream,
	*stm_close_stream,
	*stm_delete_stream,
	*stm_config_stream,
	*stm_insert_metadata;


static void my_stmt_close(MYSQL_STMT **st) {
	if (!*st)
		return;
	mysql_stmt_close(*st);
	*st = NULL;
}


static void reset_conn(void) {
	my_stmt_close(&stm_insert_call);
	my_stmt_close(&stm_close_call);
	my_stmt_close(&stm_delete_call);
	my_stmt_close(&stm_insert_stream);
	my_stmt_close(&stm_close_stream);
	my_stmt_close(&stm_delete_stream);
	my_stmt_close(&stm_config_stream);
	my_stmt_close(&stm_insert_metadata);
	mysql_close(mysql_conn);
	mysql_conn = NULL;
}


INLINE int prep(MYSQL_STMT **st, const char *s) {
	*st = mysql_stmt_init(mysql_conn);
	if (!*st)
		return -1;
	if (mysql_stmt_prepare(*st, s, strlen(s))) {
		ilog(LOG_ERR, "Failed to prepare statement '%s': %s", s, mysql_stmt_error(*st));
		return -1;
	}
	return 0;
}


static int check_conn(void) {
	if (mysql_conn)
		return 0;
	if (!c_mysql_host || !c_mysql_db)
		return -1;

	dbg("connecting to MySQL");

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

	if (prep(&stm_insert_call, "insert into recording_calls (call_id, start_timestamp, " \
				"`status`) " \
				"values " \
				"(?,?,'recording')"))
		goto err;
	if (prep(&stm_insert_stream, "insert into recording_streams (`call`, local_filename, full_filename, " \
				"file_format, " \
				"output_type, " \
				"stream_id, ssrc, " \
				"tag_label, " \
				"start_timestamp) values " \
				"(?,concat(?,'.',?),concat(?,'.',?),?,?,?,?,?,?)"))
		goto err;
	if (prep(&stm_close_call, "update recording_calls set " \
				"end_timestamp = ?, status = 'completed' where id = ? " \
				"and status != 'completed'"))
		goto err;
	if (prep(&stm_delete_call, "delete from recording_calls where id = ?"))
		goto err;
	if ((output_storage & OUTPUT_STORAGE_DB)) {
		if (prep(&stm_close_stream, "update recording_streams set " \
					"end_timestamp = ?, stream = ? where id = ?"))
			goto err;
	}
	else {
		if (prep(&stm_close_stream, "update recording_streams set " \
					"end_timestamp = ? where id = ?"))
			goto err;
	}
	if (prep(&stm_delete_stream, "delete from recording_streams where id = ?"))
		goto err;
	if (prep(&stm_config_stream, "update recording_streams set channels = ?, sample_rate = ? where id = ?"))
		goto err;
	if (prep(&stm_insert_metadata, "insert into recording_metakeys (`call`, `key`, `value`) values " \
				"(?,?,?)"))
		goto err;

	dbg("Connection to MySQL established");

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
INLINE void my_d(MYSQL_BIND *b, const double *d) {
	*b = (MYSQL_BIND) {
		.buffer_type = MYSQL_TYPE_DOUBLE,
		.buffer = (void *) d,
		.buffer_length = sizeof(*d),
		.is_unsigned = 0,
	};
}


static void execute_wrap(MYSQL_STMT **stmt, MYSQL_BIND *binds, unsigned long long *auto_id) {
	int retr = 0;
	while (1) {
		if (check_conn())
			goto err;
		if (mysql_stmt_bind_param(*stmt, binds))
			goto err;
		if (mysql_stmt_execute(*stmt))
			goto err;
		if (auto_id) {
			*auto_id = mysql_insert_id(mysql_conn);
			if (*auto_id == 0)
				goto err;
		}
		if (mysql_commit(mysql_conn))
			goto err;

		return;

err:
		if (retr > 5) {
			// fatal
			ilog(LOG_ERR, "Failed to bind or execute prepared statement: %s",
					mysql_stmt_error(*stmt));
			reset_conn();
			return;
		}
		if (retr > 2) {
			reset_conn();
			if (check_conn())
				return;
		}

		retr++;
	}
}


static void db_do_call_id(metafile_t *mf) {
	if (mf->db_id > 0)
		return;
	if (!mf->call_id)
		return;
	if (mf->skip_db)
		return;

	MYSQL_BIND b[2];
	my_cstr(&b[0], mf->call_id);
	my_d(&b[1], &mf->start_time);

	execute_wrap(&stm_insert_call, b, &mf->db_id);
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

	metadata_ht_iter iter;
	t_hash_table_iter_init(&iter, mf->metadata_parsed);
	str *key;
	str_q *vals;
	while (t_hash_table_iter_next(&iter, &key, &vals)) {
		for (__auto_type l = vals->head; l; l = l->next) {
			my_str(&b[1], key);
			my_str(&b[2], l->data);

			execute_wrap(&stm_insert_metadata, b, NULL);
		}
	}

	mf->db_metadata_done = 1;
}

void db_do_call(metafile_t *mf) {
	if (check_conn())
		return;

	db_do_call_id(mf);
	db_do_call_metadata(mf);
}


// mf is locked
void db_do_stream(metafile_t *mf, output_t *op, stream_t *stream, unsigned long ssrc) {
	if (check_conn())
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
	my_d(&b[10], &op->start_time);

	execute_wrap(&stm_insert_stream, b, &op->db_id);

	if (op->db_id > 0)
		mf->db_streams++;
}

void db_close_call(metafile_t *mf) {
	if (check_conn())
		return;
	if (mf->db_id == 0)
		return;

	double now = now_double();

	MYSQL_BIND b[2];

	if (mf->db_streams > 0) {
		my_d(&b[0], &now);
		my_ull(&b[1], &mf->db_id);
		execute_wrap(&stm_close_call, b, NULL);
	}
	else {
		my_ull(&b[0], &mf->db_id);
		execute_wrap(&stm_delete_call, b, NULL);
		mf->db_id = 0;
	}
}

void db_close_stream(output_t *op) {
	if (check_conn())
		return;
	if (op->db_id == 0)
		return;

	double now = now_double();

	str stream = STR_NULL;
	MYSQL_BIND b[3];

	if ((output_storage & OUTPUT_STORAGE_DB)) {
		FILE *f = fopen(op->filename, "rb");
		if (!f) {
			ilog(LOG_ERR, "Failed to open file: %s%s%s", FMT_M(op->filename));
			if ((output_storage & OUTPUT_STORAGE_FILE))
				goto file;
			return;
		}
		fseek(f, 0, SEEK_END);
		long pos = ftell(f);
		if (pos < 0) {
			ilog(LOG_ERR, "Failed to get file position: %s", strerror(errno));
			fclose(f);
			if ((output_storage & OUTPUT_STORAGE_FILE))
				goto file;
			return;
		}
		stream.len = pos;
		fseek(f, 0, SEEK_SET);
		stream.s = malloc(stream.len);
		if (stream.s) {
			size_t count = fread(stream.s, 1, stream.len, f);
			if (count != stream.len) {
				stream.len = 0;
				ilog(LOG_ERR, "Failed to read from stream");
				fclose(f);
				if ((output_storage & OUTPUT_STORAGE_FILE))
					goto file;
				free(stream.s);
				return;
			}
		}
		fclose(f);
        }

file:;
	int par_idx = 0;
	my_d(&b[par_idx++], &now);
	if ((output_storage & OUTPUT_STORAGE_DB))
		my_str(&b[par_idx++], &stream);
	my_ull(&b[par_idx++], &op->db_id);

	execute_wrap(&stm_close_stream, b, NULL);

        if (stream.s)
		free(stream.s);
	if (!(output_storage & OUTPUT_STORAGE_FILE))
		if (unlink(op->filename))
			ilog(LOG_ERR, "Failed to delete file '%s': %s", op->filename, strerror(errno));
}

void db_delete_stream(metafile_t *mf, output_t *op) {
	if (check_conn())
		return;
	if (op->db_id == 0)
		return;

        MYSQL_BIND b[1];
	my_ull(&b[0], &op->db_id);

	execute_wrap(&stm_delete_stream, b, NULL);

	mf->db_streams--;
}

void db_config_stream(output_t *op) {
	if (check_conn())
		return;
	if (op->db_id == 0)
		return;

	MYSQL_BIND b[3];
	my_i(&b[0], &op->encoder->actual_format.channels);
	my_i(&b[1], &op->encoder->actual_format.clockrate);
	my_ull(&b[2], &op->db_id);

	execute_wrap(&stm_config_stream, b, NULL);
}

void db_thread_end(void) {
	reset_conn();
}
