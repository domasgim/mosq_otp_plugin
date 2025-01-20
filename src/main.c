#include <mosquitto.h>
#include <mosquitto/broker.h>
#include <mosquitto/defs.h>
#include <mosquitto/libcommon_properties.h>
#include <stdio.h>
#include <string.h>
#include <cotp.h>
#include <cjson/cJSON.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <time.h>

const char *g_secret = "my_awesome_secret";
char *g_secret_base32 = NULL;
int g_counter = 2;
int g_temporary_hotp_token = 0;

// MOSQ_ERR_AUTH_CONTINUE
static mosquitto_plugin_id_t *mosq_pid = NULL;
sqlite3 *g_db;


typedef enum { AC_SUCCESS, AC_ERROR } ac_stat;

// #define DB_PATH	   "/home/net-gimzunasdo/Stuff/baigiamasis/mosq_otp_plugin/mosq_otp_plugin.db"
#define DB_PATH	   "/home/domasgim/Desktop/baigiamasis_projektas/mosq_otp_plugin/mosq_otp_plugin.db"
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

static ac_stat insert_device_challenge(int challenge, int device_id)
{
	sqlite3_stmt *stmt;
	int rc;
	rc = sqlite3_prepare_v2(g_db, DB_INSERT_CRP_FMT, -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to prepare statement: %s", sqlite3_errmsg(g_db));
		return AC_ERROR;
	}

	rc = sqlite3_bind_int(stmt, 1, device_id);
	if (rc != SQLITE_OK) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to bind int: %s", sqlite3_errmsg(g_db));
		return AC_ERROR;
	}

	rc = sqlite3_bind_int(stmt, 2, challenge);
	if (rc != SQLITE_OK) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to bind int: %s", sqlite3_errmsg(g_db));
		return AC_ERROR;
	}

	// For now, the response is always 0, they will be updated later
	rc = sqlite3_bind_int(stmt, 3, 0);
	if (rc != SQLITE_OK) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to bind int: %s", sqlite3_errmsg(g_db));
		return AC_ERROR;
	}

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to insert challenge: %s", sqlite3_errmsg(g_db));
		return AC_ERROR;
	}

	sqlite3_finalize(stmt);

	mosquitto_log_printf(MOSQ_LOG_INFO, "Inserted challenge %d for device %d", challenge, device_id);

	return AC_SUCCESS;
}

static ac_stat populate_auth_data_with_challenges(int challenges[], int challenges_len)
{
	// TODO
	return AC_SUCCESS;
}

/**
 * @brief Generate challenge payload to the client
 * 
 * @param challenges 
 * @param challenges_len 
 * @param out 
 * @param reason 0 - registration process, 1 - authentication process
 * @return ac_stat 
 */
static ac_stat generate_json_response_str(int challenges[], int challenges_len, char **out, int reason)
{
	cJSON *json = cJSON_CreateObject();
	cJSON *challenges_json = cJSON_CreateArray();

	for (int i = 0; i < challenges_len; i++) {
		cJSON_AddItemToArray(challenges_json, cJSON_CreateNumber(challenges[i]));
	}

	cJSON_AddItemToObject(json, "CHALLENGES", challenges_json);
	cJSON_AddItemToObject(json, "REASON", cJSON_CreateNumber(reason));

	*out = cJSON_PrintUnformatted(json);
	cJSON_Delete(json);

	return AC_SUCCESS;
}

// Generate 64 challenges for the device, insert them into the database and populate the auth_data field with them in form of a JSON array
static ac_stat generate_device_challenges(char *device_mac, void **data_out, uint16_t *data_out_len)
{
	int challenge[64];
	int rc = 0;

	// Resolve the device ID from the given device MAC address
	sqlite3_stmt *device_stmt;
	int device_id = -1;
	sqlite3_stmt *stmt;

	rc = sqlite3_prepare_v2(g_db, "SELECT ID FROM Devices WHERE MAC = ?", -1, &device_stmt, NULL);
	if (rc != SQLITE_OK) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to prepare statement: %s", sqlite3_errmsg(g_db));
		return AC_ERROR;
	}

	rc = sqlite3_bind_text(device_stmt, 1, device_mac, -1, SQLITE_STATIC);
	if (rc != SQLITE_OK) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to bind text: %s", sqlite3_errmsg(g_db));
		return AC_ERROR;
	}

	rc = sqlite3_step(device_stmt);
	if (rc == SQLITE_ROW) {
		device_id = sqlite3_column_int(device_stmt, 0);
		mosquitto_log_printf(MOSQ_LOG_INFO, "Resolved device ID: %d", device_id);
	} else {
		mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to resolve device ID: %s", sqlite3_errmsg(g_db));
		sqlite3_finalize(device_stmt);
		return AC_ERROR;
	}

	sqlite3_finalize(device_stmt);

	// rc = sqlite3_bind_int(stmt, 1, device_id);
	// if (rc != SQLITE_OK) {
	// 	mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to bind int: %s", sqlite3_errmsg(g_db));
	// 	return AC_ERROR;
	// }

	// Generate 64 random challenges
	for (int i = 0; i < 64; i++) {
		// challenge[i] = rand() % 256;
		challenge[i] = i;
		insert_device_challenge(challenge[i], device_id);
	}

	mosquitto_log_printf(MOSQ_LOG_INFO, "Generating response string...");

	char* data_out_str = NULL;

	// Generate a JSON array of the challenges
	generate_json_response_str(challenge, 64, &data_out_str, 0);

	mosquitto_log_printf(MOSQ_LOG_INFO, "Generated challenges for device '%s'", (char *)data_out_str);

	*data_out = data_out_str;
	*data_out_len = strlen(data_out_str);

	mosquitto_log_printf(MOSQ_LOG_INFO, "Data_out added");

	// data_out_len = strlen((char *)data_out);

	return AC_SUCCESS;
}

static ac_stat process_authenticating_device(char *device_mac, void **data_out, uint16_t *data_out_len)
{
	// Check if device is registered
	sqlite3_stmt *stmt;
	int rc;
	rc = sqlite3_prepare_v2(g_db, DB_CHECK_DEVICE_FMT, -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to prepare statement: %s", sqlite3_errmsg(g_db));
		return AC_ERROR;
	}

	rc = sqlite3_bind_text(stmt, 1, device_mac, -1, SQLITE_STATIC);
	if (rc != SQLITE_OK) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to bind text: %s", sqlite3_errmsg(g_db));
		return AC_ERROR;
	}

	rc = sqlite3_step(stmt);

	if (rc == SQLITE_ROW) {
		mosquitto_log_printf(MOSQ_LOG_INFO, "Device '%s' found", device_mac);
	} else if (rc == SQLITE_DONE) {
		mosquitto_log_printf(MOSQ_LOG_INFO, "Device '%s' not found", device_mac);
		rc = sqlite3_prepare_v2(g_db, DB_INSERT_DEVICE_FMT, -1, &stmt, NULL);
		if (rc != SQLITE_OK) {
			mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to prepare statement: %s", sqlite3_errmsg(g_db));
			return AC_ERROR;
		}

		rc = sqlite3_bind_text(stmt, 1, device_mac, -1, SQLITE_STATIC);
		if (rc != SQLITE_OK) {
			mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to bind text: %s", sqlite3_errmsg(g_db));
			return AC_ERROR;
		}

		rc = sqlite3_step(stmt);
		if (rc != SQLITE_DONE) {
			mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to insert device: %s", sqlite3_errmsg(g_db));
			return AC_ERROR;
		}

		mosquitto_log_printf(MOSQ_LOG_INFO, "Device '%s' inserted", device_mac);

		// TODO generate and insert challenges for the device
		generate_device_challenges(device_mac, data_out, data_out_len);

		// TODO send all the generated challenges to the device

		// TODO receive responses from the device and update the database
	} else {
		mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to step: %s", sqlite3_errmsg(g_db));
		return AC_ERROR;
	}

	return AC_SUCCESS;
}

int auth_start_cb(int event, void *event_data, void *user_data)
{
	struct mosquitto_evt_extended_auth *ed = event_data;
	char *device_mac = NULL;

	if (ed->data_in_len > 0) {
		mosquitto_log_printf(MOSQ_LOG_INFO, "Got some data of len %d: '%s'",
				     ed->data_in_len, ed->data_in);
	} else {
		mosquitto_log_printf(MOSQ_LOG_INFO, "No data in\n");
		return MOSQ_ERR_AUTH;
	}

	if (parse_device_mac((char *)ed->data_in, &device_mac) != AC_SUCCESS) {
		return MOSQ_ERR_AUTH;
	}

	mosquitto_log_printf(MOSQ_LOG_INFO, "Parsed device MAC: '%s'", device_mac);

	// ed->data_out (void *)
	// ed->data_out_len (uint16_t)
	// 65,535 bytes out length
	if (process_authenticating_device(device_mac, &ed->data_out, &ed->data_out_len) != AC_SUCCESS) {
		return MOSQ_ERR_AUTH;
	}

	return MOSQ_ERR_AUTH_CONTINUE;
}

int update_db_responses(char *response, char *device_mac)
{
	unsigned long long crp_value = strtoull(response, NULL, 10);
	sqlite3_stmt *stmt;
	int rc;

	// Prepare the statement to update the Response column
	rc = sqlite3_prepare_v2(g_db, "UPDATE ChallengeResponsePairs SET Response = ? WHERE DeviceID = (SELECT ID FROM Devices WHERE MAC = ?) AND Challenge = ?", -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to prepare statement: %s", sqlite3_errmsg(g_db));
		return AC_ERROR;
	}

	mosquitto_log_printf(MOSQ_LOG_INFO, "response %s | crp_value: %u", response, crp_value);
	// Print the crp_value in binary representation
	char binary_str[65];
	for (int i = 0; i < 64; i++) {
		binary_str[63 - i] = (crp_value & (1ULL << i)) ? '1' : '0';
	}
	binary_str[64] = '\0';
	mosquitto_log_printf(MOSQ_LOG_INFO, "crp_value in binary: %s", binary_str);

	for (int i = 0; i < 64; i++) {
		int bit = (crp_value >> (63 - i)) & 1;
		mosquitto_log_printf(MOSQ_LOG_INFO, "Bit %d: %d", i, bit);

		// Bind the Response value
		rc = sqlite3_bind_int(stmt, 1, bit);
		if (rc != SQLITE_OK) {
			mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to bind int: %s", sqlite3_errmsg(g_db));
			sqlite3_finalize(stmt);
			return AC_ERROR;
		}

		// Bind the Device MAC
		rc = sqlite3_bind_text(stmt, 2, device_mac, -1, SQLITE_STATIC);
		if (rc != SQLITE_OK) {
			mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to bind text: %s", sqlite3_errmsg(g_db));
			sqlite3_finalize(stmt);
			return AC_ERROR;
		}

		// Bind the Challenge value
		rc = sqlite3_bind_int(stmt, 3, i);
		if (rc != SQLITE_OK) {
			mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to bind int: %s", sqlite3_errmsg(g_db));
			sqlite3_finalize(stmt);
			return AC_ERROR;
		}

		// Execute the update statement
		rc = sqlite3_step(stmt);
		if (rc != SQLITE_DONE) {
			mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to update response: %s", sqlite3_errmsg(g_db));
			sqlite3_finalize(stmt);
			return AC_ERROR;
		}

		// Reset the statement to be reused
		sqlite3_reset(stmt);
	}

	// mosquitto_log_printf(MOSQ_LOG_INFO, "KABOOM");
	// exit(1);

	sqlite3_finalize(stmt);
	return AC_SUCCESS;
}

static int append_CRPs(int challenges[], int challenges_len, const char *device_mac, char **out) 
{

	sqlite3_stmt *stmt;
	int rc;
	unsigned long response_value = 0;

	rc = sqlite3_prepare_v2(g_db, "SELECT Response FROM ChallengeResponsePairs WHERE DeviceID = (SELECT ID FROM Devices WHERE MAC = ?) AND Challenge = ?", -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to prepare statement: %s", sqlite3_errmsg(g_db));
		return AC_ERROR;
	}

	for (int i = 0; i < 32; i++) {
		rc = sqlite3_bind_text(stmt, 1, device_mac, -1, SQLITE_STATIC);
		if (rc != SQLITE_OK) {
			mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to bind text: %s", sqlite3_errmsg(g_db));
			sqlite3_finalize(stmt);
			return AC_ERROR;
		}

		// mosquitto_log_printf(MOSQ_LOG_INFO, "trying to bind int: %d-%d", 2, challenges[i]);
		rc = sqlite3_bind_int(stmt, 2, challenges[i]);
		if (rc != SQLITE_OK) {
			mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to bind int: %s", sqlite3_errmsg(g_db));
			sqlite3_finalize(stmt);
			return AC_ERROR;
		}

		rc = sqlite3_step(stmt);
		// fprintf(stdout, "Step result: %d\n", rc);
		if (rc == SQLITE_ROW) {
			int response_bit = sqlite3_column_int(stmt, 0);
			response_value = (response_value << 1) | response_bit;
			fprintf(stdout, "Challenge: %d | Response: %d | response_value: %lu\n", challenges[i], response_bit, response_value);
			// Print the response_value in binary representation
			char response_binary_str[33];
			for (int j = 0; j < 32; j++) {
				response_binary_str[31 - j] = (response_value & (1U << j)) ? '1' : '0';
			}
			response_binary_str[32] = '\0';
			mosquitto_log_printf(MOSQ_LOG_INFO, "response_value in binary: %s", response_binary_str);

		} else {
			mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to step: %s", sqlite3_errmsg(g_db));
			sqlite3_finalize(stmt);
			return AC_ERROR;
		}

		sqlite3_reset(stmt);
	}

	sqlite3_finalize(stmt);

	fprintf(stdout, "Response value: %lu\n", response_value);

	char response_str[64];
	snprintf(response_str, sizeof(response_str), "%lu", response_value);
	*out = strdup(response_str);
	


	// BAD

	// rc = sqlite3_bind_text(stmt, 1, device_mac, -1, SQLITE_STATIC);
	// if (rc != SQLITE_OK) {
	// 	mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to bind text: %s", sqlite3_errmsg(g_db));
	// 	sqlite3_finalize(stmt);
	// 	return AC_ERROR;
	// }

	// int bit_position = 0;
	// while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
	// 	int response_bit = sqlite3_column_int(stmt, 0);
	// 	response_value |= (response_bit << bit_position);
	// 	bit_position++;
	// }

	// if (rc != SQLITE_DONE) {
	// 	mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to step: %s", sqlite3_errmsg(g_db));
	// 	sqlite3_finalize(stmt);
	// 	return AC_ERROR;
	// }

	// sqlite3_finalize(stmt);

	// char response_str[33];
	// snprintf(response_str, sizeof(response_str), "%u", response_value);
	// *out = strdup(response_str);
	return 0;
}

static ac_stat generate_challenge(const char *device_mac, void **data_out, uint16_t *data_out_len, char **hotp_local)
{
	int challenge[32];
	int rc = 0;

	// // Resolve the device ID from the given device MAC address
	// sqlite3_stmt *device_stmt;
	// int device_id = -1;

	// rc = sqlite3_prepare_v2(g_db, "SELECT ID FROM Devices WHERE MAC = ?", -1, &device_stmt, NULL);
	// if (rc != SQLITE_OK) {
	// 	mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to prepare statement: %s", sqlite3_errmsg(g_db));
	// 	return AC_ERROR;
	// }

	// rc = sqlite3_bind_text(device_stmt, 1, device_mac, -1, SQLITE_STATIC);
	// if (rc != SQLITE_OK) {
	// 	mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to bind text: %s", sqlite3_errmsg(g_db));
	// 	return AC_ERROR;
	// }

	// rc = sqlite3_step(device_stmt);
	// if (rc == SQLITE_ROW) {
	// 	device_id = sqlite3_column_int(device_stmt, 0);
	// 	mosquitto_log_printf(MOSQ_LOG_INFO, "Resolved device ID: %d", device_id);
	// } else {
	// 	mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to resolve device ID: %s", sqlite3_errmsg(g_db));
	// 	sqlite3_finalize(device_stmt);
	// 	return AC_ERROR;
	// }

	// sqlite3_finalize(device_stmt);

	// Generate 32 random challenges
	for (int i = 0; i < 32; i++) {
		// TODO update this
		challenge[i] = rand() % 64;
		// insert_device_challenge(challenge[i], device_id);
	}

	char *appended_crp = NULL;

	if (append_CRPs(challenge, 32, device_mac, &appended_crp) != 0) {
		mosquitto_log_printf(MOSQ_LOG_INFO, "Failed to append CRPs");
		return AC_ERROR;
	}

	cotp_error_t cotp_err;
	char *hotp_local_local;
	char *response_base32 = base32_encode((const uchar *)appended_crp,
					strlen(appended_crp) + 1, &cotp_err);
	if (cotp_err != 0) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "Error: Could not encode response to base32");
		return AC_ERROR;
	}

	mosquitto_log_printf(MOSQ_LOG_INFO, "HOTP params: %s / %s, %d, %d, %d", appended_crp, response_base32, 1, 6, SHA1);
	
	hotp_local_local = get_hotp(response_base32, 1, 6, SHA1, &cotp_err);
	if (cotp_err != 0) {
		// TODO handle err
		mosquitto_log_printf(MOSQ_LOG_INFO, "Error: Could not generate HOTP token, check parameters!");
		return AC_ERROR;
	}

	mosquitto_log_printf(MOSQ_LOG_INFO, "Generated HOTP token: %s", hotp_local_local);

	*hotp_local = strdup(hotp_local_local);

	mosquitto_log_printf(MOSQ_LOG_INFO, "Generating response string...");

	char* data_out_str = NULL;

	// Generate a JSON array of the challenges
	generate_json_response_str(challenge, 32, &data_out_str, 1);

	mosquitto_log_printf(MOSQ_LOG_INFO, "Generated challenges for device '%s'", (char *)data_out_str);

	*data_out = data_out_str;
	*data_out_len = strlen(data_out_str);

	mosquitto_log_printf(MOSQ_LOG_INFO, "Data_out added");

	return AC_SUCCESS;
}



int auth_continue_cb(int event, void *event_data, void *user_data)
{
	struct mosquitto_evt_extended_auth *ed = event_data;
	// struct mosquitto_evt_message *ed = event_data;
	void *auth_data = NULL;
	char *hotp_local;
	cotp_error_t cotp_err;
	uint16_t auth_data_len = 0;
	const cJSON *response_data = NULL;
	const cJSON *CRP_result = NULL;
	const cJSON *device_mac = NULL;

	mosquitto_log_printf(
		MOSQ_LOG_INFO,
		"%s:%d - event: %d | auth_method: %s | data_in_len: %d | data_out_len: %d",
		__FUNCTION__, __LINE__, event, ed->auth_method, ed->data_in_len,
		ed->data_out_len);

	if (ed->data_in_len > 0) {
		mosquitto_log_printf(MOSQ_LOG_INFO, "Got some data: '%s'",
				     ed->data_in);
	}

	cJSON *parsed_response_json = cJSON_Parse(ed->data_in);
	if (parsed_response_json == NULL) {
		const char *error_ptr = cJSON_GetErrorPtr();
		if (error_ptr != NULL) {
			mosquitto_log_printf(MOSQ_LOG_INFO, "Error before: %s", error_ptr);
		}
		// TODO handle err
		return MOSQ_ERR_CONN_REFUSED;
	}

	response_data = cJSON_GetObjectItemCaseSensitive(parsed_response_json,
							"REASON");
	
	if (cJSON_IsNumber(response_data) && (response_data->valueint != 0)) {
		mosquitto_log_printf(MOSQ_LOG_INFO, "REASON: '%d'", response_data->valueint);
	} else {
		mosquitto_log_printf(MOSQ_LOG_INFO, "Failed to find 'REASON'!");
		return MOSQ_ERR_CONN_REFUSED;
	}

	// 1 means got the reponse payload from CRP step, now we parse it and insert it into the database
	if (response_data->valueint == 1) {
		// ATM the response pair is a single 64bit number in form of a JSON string with key CHALLENGE_RESPOSNE, each bit will be a response to n-th challenge
		CRP_result = cJSON_GetObjectItemCaseSensitive(parsed_response_json,
								"CHALLENGE_RESPONSE");
		
		device_mac = cJSON_GetObjectItemCaseSensitive(parsed_response_json,
								"DEVICE_MAC");

		if (cJSON_IsString(CRP_result) && (CRP_result->valuestring != NULL) && cJSON_IsString(device_mac) && (device_mac->valuestring != NULL)) {
			mosquitto_log_printf(MOSQ_LOG_INFO, "CHALLENGE_RESPONSE: '%s' | DEVICE_MAC: '%s'", CRP_result->valuestring, device_mac->valuestring);

			// Update the database..
			update_db_responses(CRP_result->valuestring, device_mac->valuestring);

			mosquitto_log_printf(MOSQ_LOG_INFO, "Updated the database with the responses, generating a new challenge...");
			// Okay CRP is registered, send a subset of challenges to run a first HOTP check
			if (generate_challenge(device_mac->valuestring, &ed->data_out, &ed->data_out_len, &hotp_local) != AC_SUCCESS) {
				mosquitto_log_printf(MOSQ_LOG_INFO, "Failed to generate a new challenge");
				return MOSQ_ERR_PROTOCOL;
			}

			mosquitto_log_printf(MOSQ_LOG_INFO, "Generated a new challenge for device '%s', also immediately generated HOTP value %s", device_mac->valuestring, hotp_local);

			g_temporary_hotp_token = atoi(hotp_local);

			// Advanced tomfoolery, we basically want to save device mac and 32 challenge array until the next continue_cb invocation since this info will be reused when checking for HOTP vals
			// Or we can just generate the HOTP token right at this moment and save it as user_data???? GENIUS
			
			

			mosquitto_log_printf(MOSQ_LOG_INFO, "Generated a new challenge for device '%s'", device_mac->valuestring);

			return MOSQ_ERR_AUTH_CONTINUE;
		} else {
			mosquitto_log_printf(MOSQ_LOG_INFO, "Failed to find 'CHALLENGE_RESPONSE'!");
			return MOSQ_ERR_CONN_REFUSED;
		}
	// 2 means got the HOTP token from the device, now we need to check it
	} else if (response_data->valueint == 2) {
		// Got some data: '{"HOTP_TOKEN":"978088","REASON":2}'
		// NOT FULLY IMPLEMENTED ATM
		const cJSON *hotp_token = NULL;
		hotp_token = cJSON_GetObjectItemCaseSensitive(parsed_response_json,
								"HOTP_TOKEN");
		if (cJSON_IsString(hotp_token) && (hotp_token->valuestring != NULL)) {
			mosquitto_log_printf(MOSQ_LOG_INFO, "HOTP_TOKEN: '%s'", hotp_token->valuestring);

			int hotp_token_int = atoi(hotp_token->valuestring);

			if (hotp_token_int == g_temporary_hotp_token) {
				mosquitto_log_printf(MOSQ_LOG_INFO, "HOTP tokens match, permitting...");
				return MOSQ_ERR_SUCCESS;
			} else {
				mosquitto_log_printf(MOSQ_LOG_INFO, "HOTP tokens do not match, not permitting...");
				return MOSQ_ERR_CONN_REFUSED;
			}

		} else {
			mosquitto_log_printf(MOSQ_LOG_INFO, "Failed to find 'HOTP_TOKEN'!");
			return MOSQ_ERR_CONN_REFUSED;
		}
	}else {
		mosquitto_log_printf(MOSQ_LOG_INFO, "NOT IMPLENTED ATM with the response data: '%d'", response_data->valueint);
	}






	// !!!!! Everything below is OLD !!!!!
	/** 

	// TODO: extract hotp_value and calculate it with your own value, compare and permit accordingly
	const cJSON *hotp_value = NULL;
	cJSON *parsed_hotp_json = cJSON_Parse(ed->data_in);
	if (parsed_hotp_json == NULL) {
		const char *error_ptr = cJSON_GetErrorPtr();
		if (error_ptr != NULL) {
			mosquitto_log_printf(MOSQ_LOG_INFO, "Error before: %s", error_ptr);
		}
		// TODO handle err
		return MOSQ_ERR_CONN_REFUSED;
	}

	// TODO try to extract REASON value first to determine if we need to continue with something else


	hotp_value = cJSON_GetObjectItemCaseSensitive(parsed_hotp_json,
							"hotp_value");
	if (cJSON_IsString(hotp_value) && (hotp_value->valuestring != NULL)) {
		mosquitto_log_printf(MOSQ_LOG_INFO, "hotp_value: '%s'", hotp_value->valuestring);
	} else {
		mosquitto_log_printf(MOSQ_LOG_INFO, "Failed to find 'hotp_value'!");
		return MOSQ_ERR_CONN_REFUSED;
	}

	hotp_local = get_hotp(g_secret_base32, g_counter, 6, SHA1, &cotp_err);
	if (cotp_err != 0) {
		// TODO handle err
		return MOSQ_ERR_CONN_REFUSED;
	}

	mosquitto_log_printf(MOSQ_LOG_INFO, "Checking HOTP tokens: got '%s', calculated '%s'", hotp_value->valuestring, hotp_local);
	if (!strcmp(hotp_value->valuestring, hotp_local)) {
		mosquitto_log_printf(MOSQ_LOG_INFO, "HOTP values match");
		return MOSQ_ERR_SUCCESS;
	} else {
		mosquitto_log_printf(MOSQ_LOG_INFO, "HOTP values do not match, not permitting...");
		return MOSQ_ERR_CONN_REFUSED;
	}

	return MOSQ_ERR_SUCCESS;
	*/
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
	char *err_msg			    = NULL;

	g_secret_base32 = base32_encode((const uchar *)g_secret,
					strlen(g_secret) + 1, &cotp_err);

	if (cotp_err != 0) {
		// TODO handle
	}

	// Initialize random seed
	srand(time(NULL));

	if (sqlite3_open(DB_PATH, &g_db)) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to open database '%s'", DB_PATH);
		return MOSQ_ERR_CONN_REFUSED;
	} else {
		mosquitto_log_printf(MOSQ_LOG_INFO, "Opened database '%s'", DB_PATH);
	}

	// Create tables if they don't exist
	if (sqlite3_exec(g_db, DB_CREATE_DEVICES_FMT, NULL, NULL, &err_msg) != SQLITE_OK) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "Failed creating device table error '%s'", err_msg);
		sqlite3_free(err_msg);
		return MOSQ_ERR_CONN_REFUSED;
	}

	if (sqlite3_exec(g_db, DB_CREATE_CRP_FMT, NULL, NULL, &err_msg) != SQLITE_OK) {
		mosquitto_log_printf(MOSQ_LOG_ERR, "Failed creating CRP table error '%s'", err_msg);
		sqlite3_free(err_msg);
		return MOSQ_ERR_CONN_REFUSED;
	}

	// Register callbacks
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
