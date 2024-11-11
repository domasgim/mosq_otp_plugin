#include <mosquitto.h>
#include <mosquitto/defs.h>
#include <mosquitto/libcommon_properties.h>
#include <stdio.h>
#include <string.h>
#include <cotp.h>
#include <cjson/cJSON.h>
#include <sqlite3.h>

const char *g_secret = "my_awesome_secret";
char *g_secret_base32 = NULL;
int g_counter = 2;

// MOSQ_ERR_AUTH_CONTINUE
static mosquitto_plugin_id_t *mosq_pid = NULL;
sqlite3 *g_db;


typedef enum { AC_SUCCESS, AC_ERROR } ac_stat;

#define DB_PATH	   "/tmp/mosq_otp_plugin.db"
#define DB_TABLE   "REGISTERED_DEVICES"
#define DB_TIMEOUT 5000
// #define DB_CREATE_FMT                                                                                        \
	// "CREATE TABLE IF NOT EXISTS " DB_TABLE                                                               \
	// "(ID INTEGER PRIMARY KEY AUTOINCREMENT, MAC CHAR(15), SIM_SLOT INTEGER, "                       \
	// "SENT INTEGER, RECEIVED INTEGER)"

#define DB_CREATE_DEVICES_FMT                                                                                \
	"CREATE TABLE IF NOT EXISTS Devices (ID INTEGER PRIMARY KEY AUTOINCREMENT,"                          \
	"MAC CHAR(17) UNIQUE NOT NULL)"

#define DB_CREATE_CRP_FMT                                                                                    \
	"CREATE TABLE IF NOT EXISTS ChallengeResponsePairs ("                                                \
	"DeviceID INTEGER,"                                                                                  \
	"Challenge INTEGER,"                                                                                 \
	"Response INTEGER,"                                                                                  \
	"FOREIGN KEY (DeviceID) REFERENCES Devices(ID)"                                                      \
	")"

#define DB_CHECK_DEVICE_FMT                                                                                  \
	"SELECT MAC FROM Devices WHERE MAC = ?"

#define DB_INSERT_DEVICE_FMT                                                                                 \
	"INSERT INTO Devices (MAC) VALUES (?)"

#define DB_INSERT_CRP_FMT                                                                                    \
	"INSERT INTO ChallengeResponsePairs (DeviceID, Challenge, Response) VALUES (?, ?, ?)"

static ac_stat parse_device_mac(char *json_str, char **out)
{
	const cJSON *device_mac = NULL;
	cJSON *parsed_json = cJSON_Parse(json_str);
	if (parsed_json == NULL) {
		const char *error_ptr = cJSON_GetErrorPtr();
		if (error_ptr != NULL) {
			mosquitto_log_printf(MOSQ_LOG_INFO, "Error before: %s\n", error_ptr);
		}
		return AC_ERROR;
	}

	device_mac = cJSON_GetObjectItemCaseSensitive(parsed_json, "DEVICE_MAC");
	if (cJSON_IsString(device_mac) && (device_mac->valuestring != NULL)) {
		*out = strdup(device_mac->valuestring);
		cJSON_Delete(parsed_json);
		return AC_SUCCESS;
	} else {
		mosquitto_log_printf(MOSQ_LOG_INFO, "Failed to find 'DEVICE_MAC'!\n");
		cJSON_Delete(parsed_json);
		return AC_ERROR;
	}
}

int auth_start_cb(int event, void *event_data, void *user_data)
{
	struct mosquitto_evt_extended_auth *ed = event_data;
	char *auth_data = NULL;
	char *out_data = "{\"hotp_counter\":2}";

	// ed->data_out = strdup(out_data);
	// ed->data_out_len = strlen(out_data);

	if (ed->data_in_len > 0) {
		mosquitto_log_printf(MOSQ_LOG_INFO, "Got some data of len %d: '%s'",
				     ed->data_in_len, ed->data_in);
	} else {
		mosquitto_log_printf(MOSQ_LOG_INFO, "No data in\n");
		return MOSQ_ERR_AUTH;
	}

	if (parse_device_mac((char *)ed->data_in, &auth_data) != AC_SUCCESS) {
		return MOSQ_ERR_AUTH;
	}

	mosquitto_log_printf(MOSQ_LOG_INFO, "Parsed device MAC: '%s'", auth_data);

	mosquitto_log_printf(
		MOSQ_LOG_INFO,
		"%s:%d - event: %d, added authentication_data: '%s' (len %d)",
		__FUNCTION__, __LINE__, event, out_data, ed->data_out_len);
	return MOSQ_ERR_AUTH_CONTINUE;
}

int auth_continue_cb(int event, void *event_data, void *user_data)
{
	struct mosquitto_evt_extended_auth *ed = event_data;
	// struct mosquitto_evt_message *ed = event_data;
	void *auth_data = NULL;
	char *hotp_local;
	cotp_error_t cotp_err;
	uint16_t auth_data_len = 0;

	mosquitto_log_printf(
		MOSQ_LOG_INFO,
		"%s:%d - event: %d | auth_method: %s | data_in_len: %d | data_out_len: %d",
		__FUNCTION__, __LINE__, event, ed->auth_method, ed->data_in_len,
		ed->data_out_len);

	if (ed->data_in_len > 0) {
		mosquitto_log_printf(MOSQ_LOG_INFO, "Got some data: '%s'\n",
				     ed->data_in);
	}

	// TODO: extract hotp_value and calculate it with your own value, compare and permit accordingly
	const cJSON *hotp_value = NULL;
	cJSON *parsed_hotp_json = cJSON_Parse(ed->data_in);
	if (parsed_hotp_json == NULL) {
		const char *error_ptr = cJSON_GetErrorPtr();
		if (error_ptr != NULL) {
			mosquitto_log_printf(MOSQ_LOG_INFO, "Error before: %s\n", error_ptr);
		}
		// TODO handle err
		return MOSQ_ERR_CONN_REFUSED;
	}

	hotp_value = cJSON_GetObjectItemCaseSensitive(parsed_hotp_json,
							"hotp_value");
	if (cJSON_IsString(hotp_value) && (hotp_value->valuestring != NULL)) {
		mosquitto_log_printf(MOSQ_LOG_INFO, "hotp_value: '%s'\n", hotp_value->valuestring);
	} else {
		mosquitto_log_printf(MOSQ_LOG_INFO, "Failed to find 'hotp_value'!\n");
		return MOSQ_ERR_CONN_REFUSED;
	}

	hotp_local = get_hotp(g_secret_base32, g_counter, 6, SHA1, &cotp_err);
	if (cotp_err != 0) {
		// TODO handle err
		return MOSQ_ERR_CONN_REFUSED;
	}

	mosquitto_log_printf(MOSQ_LOG_INFO, "Checking HOTP tokens: got '%s', calculated '%s'\n", hotp_value->valuestring, hotp_local);
	if (!strcmp(hotp_value->valuestring, hotp_local)) {
		mosquitto_log_printf(MOSQ_LOG_INFO, "HOTP values match\n");
		return MOSQ_ERR_SUCCESS;
	} else {
		mosquitto_log_printf(MOSQ_LOG_INFO, "HOTP values do not match, not permitting...\n");
		return MOSQ_ERR_CONN_REFUSED;
	}

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_version(int supported_version_count,
			     const int *supported_versions)
{
	mosquitto_log_printf(MOSQ_LOG_INFO, "mosquitto_plugin_version %d",
			     supported_version_count);
	for (int i = 0; i < supported_version_count; i++) {
		mosquitto_log_printf(MOSQ_LOG_INFO, "%d",
				     supported_versions[i]);
	}
	return 5;
}

/* Callback events */
// enum mosquitto_plugin_event {
// 	MOSQ_EVT_RELOAD = 1,
// 	MOSQ_EVT_ACL_CHECK = 2,
// 	MOSQ_EVT_BASIC_AUTH = 3,
// 	MOSQ_EVT_EXT_AUTH_START = 4,
// 	MOSQ_EVT_EXT_AUTH_CONTINUE = 5,
// 	MOSQ_EVT_CONTROL = 6,
// 	MOSQ_EVT_MESSAGE = 7,
// 	MOSQ_EVT_PSK_KEY = 8,
// 	MOSQ_EVT_TICK = 9,
// 	MOSQ_EVT_DISCONNECT = 10,
// };

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **userdata,
			  struct mosquitto_opt *options, int option_count)
{
	mosq_pid = identifier;
	cotp_error_t cotp_err;

	g_secret_base32 = base32_encode((const uchar *)g_secret,
					strlen(g_secret) + 1, &cotp_err);

	if (cotp_err != 0) {
		// TODO handle
	}

	if (sqlite3_open(DB_PATH, &g_db)) {
		mosquitto_log_printf(MOSQ_LOG_INFO, "Failed to open database '%s'", DB_PATH);
		return MOSQ_ERR_CONN_REFUSED;
	} else {
		mosquitto_log_printf(MOSQ_LOG_INFO, "Opened database '%s'", DB_PATH);
	}

	if (sqlite3_exec(g_db, DB_CREATE_FMT, NULL, NULL, &err_msg) != SQLITE_OK) {
		log(L_ERROR, "Failed creating table error '%s'", err_msg);
		sqlite3_free(err_msg);
		return URCD_ERROR;
	}


	mosquitto_log_printf(MOSQ_LOG_INFO, "mosquitto_plugin_init %d",
			     option_count);
	mosquitto_callback_register(mosq_pid, MOSQ_EVT_EXT_AUTH_START,
				    auth_start_cb, NULL, NULL);
	mosquitto_callback_register(mosq_pid, MOSQ_EVT_EXT_AUTH_CONTINUE,
				    auth_continue_cb, NULL, NULL);
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_cleanup(void *userdata, struct mosquitto_opt *options,
			     int option_count)
{
	mosquitto_log_printf(MOSQ_LOG_INFO, "mosquitto_plugin_cleanup %d",
			     option_count);
	return mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_BASIC_AUTH,
					     auth_continue_cb, NULL);
}
