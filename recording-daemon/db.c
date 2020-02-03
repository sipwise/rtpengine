#include "db.h"
#include <mysql.h>
#include <glib.h>
#include <string.h>
#include <sys/time.h>
#include "types.h"
#include "main.h"
#include "log.h"
#include "tag.h"


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



static MYSQL __thread *mysql_conn;
static MYSQL_STMT __thread
	*stm_insert_call,
	*stm_close_call,
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
	my_stmt_close(&stm_insert_stream);
	my_stmt_close(&stm_close_stream);
	my_stmt_close(&stm_delete_stream);
	my_stmt_close(&stm_config_stream);
	my_stmt_close(&stm_insert_metadata);
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
				"end_timestamp = ?, status = 'completed' where id = ?"))
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


static double now_double(void) {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec + tv.tv_usec / 1000000.0;
}

static void db_do_call_id(metafile_t *mf) {
	if (mf->db_id > 0)
		return;
	if (!mf->call_id)
		return;

	double now = now_double();

	MYSQL_BIND b[2];
	my_cstr(&b[0], mf->call_id);
	my_d(&b[1], &now);

	execute_wrap(&stm_insert_call, b, &mf->db_id);
}
static void db_do_call_metadata(metafile_t *mf) {
	if (!mf->metadata_db)
		return;
	if (mf->db_id == 0)
		return;

	MYSQL_BIND b[3];
	my_ull(&b[0], &mf->db_id); // stays persistent

	// XXX offload this parsing to proxy module -> bencode list/dictionary
	str all_meta;
	str_init(&all_meta, mf->metadata_db);
	while (all_meta.len > 1) {
		str token;
		if (str_token_sep(&token, &all_meta, '|'))
			break;

		str key;
		if (str_token(&key, &token, ':')) {
			// key:value separator not found, skip
			continue;
		}

		my_str(&b[1], &key);
		my_str(&b[2], &token);

		execute_wrap(&stm_insert_metadata, b, NULL);
	}

	mf->metadata_db = NULL;
}

void db_do_call(metafile_t *mf) {
	if (check_conn())
		return;

	db_do_call_id(mf);
	db_do_call_metadata(mf);
}


// mf is locked
void db_do_stream(metafile_t *mf, output_t *op, const char *type, stream_t *stream, unsigned long ssrc) {
	if (check_conn())
		return;
	if (mf->db_id == 0)
		return;
	if (op->db_id > 0)
		return;

	unsigned long id = stream ? stream->id : 0;
	double now = now_double();

	MYSQL_BIND b[11];
	my_ull(&b[0], &mf->db_id);
	my_cstr(&b[1], op->file_name);
	my_cstr(&b[2], op->file_format);
	my_cstr(&b[3], op->full_filename);
	my_cstr(&b[4], op->file_format);
	my_cstr(&b[5], op->file_format);
	my_cstr(&b[6], type);
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
	my_d(&b[10], &now);

	execute_wrap(&stm_insert_stream, b, &op->db_id);
}

void db_close_call(metafile_t *mf) {
	if (check_conn())
		return;
	if (mf->db_id == 0)
		return;

	double now = now_double();

	MYSQL_BIND b[2];
	my_d(&b[0], &now);
	my_ull(&b[1], &mf->db_id);

	execute_wrap(&stm_close_call, b, NULL);
}

void db_close_stream(output_t *op) {
	if (check_conn())
		return;
	if (op->db_id == 0)
		return;

	double now = now_double();

	str stream;
        char *filename = 0;
        MYSQL_BIND b[3];
        stream.s = 0;
        stream.len = 0;

	if ((output_storage & OUTPUT_STORAGE_DB)) {
		filename = malloc(strlen(op->full_filename) +
				  strlen(op->file_format) + 2);
		if (!filename) {
			ilog(LOG_ERR, "Failed to allocate memory for filename");
			if ((output_storage & OUTPUT_STORAGE_FILE))
				goto file;
			return;
		}
		strcpy(filename, op->full_filename);
		strcat(filename, ".");
		strcat(filename, op->file_format);
		FILE *f = fopen(filename, "rb");
		if (!f) {
			ilog(LOG_ERR, "Failed to open file: %s%s%s", FMT_M(filename));
			if ((output_storage & OUTPUT_STORAGE_FILE))
				goto file;
			free(filename);
			return;
		}
		fseek(f, 0, SEEK_END);
		stream.len = ftell(f);
		fseek(f, 0, SEEK_SET);
		stream.s = malloc(stream.len);
		if (stream.s) {
			size_t count = fread(stream.s, 1, stream.len, f);
			if (count != stream.len) {
				ilog(LOG_ERR, "Failed to read from stream");
				if ((output_storage & OUTPUT_STORAGE_FILE))
					goto file;
				free(filename);
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
		remove(filename);
        free(filename);
}

void db_delete_stream(output_t *op) {
	if (check_conn())
		return;
	if (op->db_id == 0)
		return;

        MYSQL_BIND b[1];
	my_ull(&b[0], &op->db_id);

	execute_wrap(&stm_delete_stream, b, NULL);
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
