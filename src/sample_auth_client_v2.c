#include <mosquitto.h>
#include <mosquitto/defs.h>
#include <mosquitto/libcommon_properties.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cotp.h>
#include <cjson/cJSON.h>

typedef enum { AC_SUCCESS, AC_ERROR } ac_stat;

// #define PUF_SCRIPT_PATH "/home/net-gimzunasdo/Stuff/baigiamasis/mosq_otp_plugin/pypuf_simulator/main.py" // darbinis
#define PUF_SCRIPT_PATH "/home/domasgim/Desktop/baigiamasis_projektas/mosq_otp_plugin/pypuf_simulator/main.py" // asmeninis
#define MOCK_MAC    "00:00:00:00:00:00"
#define HOTP_METHOD "KTU-HOTP-AUTH"

static void ac_on_connect(struct mosquitto *mosq, void *obj, int reason_code, int flags,
			  const mosquitto_property *props)
{
	fprintf(stdout, "on_connect: %s\n", mosquitto_connack_string(reason_code));
	if (reason_code != 0) {
		/* If the connection fails for any reason, we don't want to keep on
		 * retrying in this example, so disconnect. Without this, the client
		 * will attempt to reconnect. */
		mosquitto_disconnect(mosq);
	}
}

static void ac_log_callback(struct mosquitto *mosq, void *obj, int level, const char *str)
{
	// Print the log level and message to the console
	fprintf(stdout, "[Level %d]: %s\n", level, str);
}

static void ac_on_publish(struct mosquitto *mosq, void *obj, int mid, int flags,
			  const mosquitto_property *props)
{
	fprintf(stdout, "Message with mid %d has been published.\n", mid);
}

#define BUFSIZE 128

static ac_stat ac_run_python_puf_script_regular_step(int *challenge, int array_count, char **out)
{
        FILE *fp;
        char path[1035];
        char command[512];
	char buf[BUFSIZE] = {0};

        if (array_count != 32) {
                fprintf(stderr, "Error: Challenge array count is not 32\n");
                return AC_ERROR;
        }

	fprintf(stdout, "Preparing PUF script with challenges...\n");

        // Don't ask
        snprintf(command, sizeof(command), "python3.10 %s %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d",
                 PUF_SCRIPT_PATH,
                 challenge[0], challenge[1], challenge[2], challenge[3], challenge[4], challenge[5], challenge[6], challenge[7], 
                 challenge[8], challenge[9], challenge[10], challenge[11], challenge[12], challenge[13], challenge[14], challenge[15], 
                 challenge[16], challenge[17], challenge[18], challenge[19], challenge[20], challenge[21], challenge[22], challenge[23], 
		 challenge[24], challenge[25], challenge[26], challenge[27], challenge[28], challenge[29], challenge[30], challenge[31]);

	fprintf(stdout, "Running PUF script with challenges '%s'\n", command);

        /* Open the command for reading. */
        fp = popen(command, "r");
        if (fp == NULL) {
                fprintf(stderr, "Failed to run command\n");
                return AC_ERROR;
        } else {
		fprintf(stdout, "Command executed, trying to read output AA\n");
	}

        /* Read the output a line at a time - output it. */
        // while (fgets(path, sizeof(path), fp) != NULL) {
	// 	fprintf(stdout, "Output: %s", path);
        //         *out = strdup(path);
        // }
	while (fgets(buf, BUFSIZE, fp) != NULL) {
		// Do whatever you want here...
		fprintf(stdout, "OUTPUT: %s", buf);
	}

	fprintf(stdout, "Output ALL: '%s'\n", buf);
	fprintf(stdout, "Output ALL2: '%s'\n", *out);

	// Remove the trailing newline character from buf
	size_t len = strlen(buf);
	if (len > 0 && buf[len - 1] == '\n') {
		buf[len - 1] = '\0';
	}

	// Copy the result to *out
	*out = strdup(buf);
	if (*out == NULL) {
		fprintf(stderr, "Error: Out of memory\n");
		pclose(fp);
		return AC_ERROR;
	} else {
		fprintf(stdout, "Output FINAL: '%s'\n", *out);
	}

        /* close */
        pclose(fp);

        return AC_SUCCESS;
}

static ac_stat ac_run_python_puf_script(int *challenge, int array_count, char **out)
{
        FILE *fp;
        char path[1035];
        char command[512];
	char buf[BUFSIZE] = {0};

        if (array_count != 64) {
                fprintf(stderr, "Error: Challenge array count is not 64\n");
                return AC_ERROR;
        }

	fprintf(stdout, "Preparing PUF script with challenges...\n");

        // Don't ask
        snprintf(command, sizeof(command), "python3.10 %s %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d",
                 PUF_SCRIPT_PATH,
                 challenge[0], challenge[1], challenge[2], challenge[3], challenge[4], challenge[5], challenge[6], challenge[7], 
                 challenge[8], challenge[9], challenge[10], challenge[11], challenge[12], challenge[13], challenge[14], challenge[15], 
                 challenge[16], challenge[17], challenge[18], challenge[19], challenge[20], challenge[21], challenge[22], challenge[23], 
		 challenge[24], challenge[25], challenge[26], challenge[27], challenge[28], challenge[29], challenge[30], challenge[31],
		 challenge[32], challenge[33], challenge[34], challenge[35], challenge[36], challenge[37], challenge[38], challenge[39],
		 challenge[40], challenge[41], challenge[42], challenge[43], challenge[44], challenge[45], challenge[46], challenge[47],
		 challenge[48], challenge[49], challenge[50], challenge[51], challenge[52], challenge[53], challenge[54], challenge[55],
		 challenge[56], challenge[57], challenge[58], challenge[59], challenge[60], challenge[61], challenge[62], challenge[63]);

	fprintf(stdout, "Running PUF script with challenges '%s'\n", command);

        /* Open the command for reading. */
        fp = popen(command, "r");
        if (fp == NULL) {
                fprintf(stderr, "Failed to run command\n");
                return AC_ERROR;
        } else {
		fprintf(stdout, "Command executed, trying to read output AA\n");
	}

        /* Read the output a line at a time - output it. */
        // while (fgets(path, sizeof(path), fp) != NULL) {
	// 	fprintf(stdout, "Output: %s", path);
        //         *out = strdup(path);
        // }
	while (fgets(buf, BUFSIZE, fp) != NULL) {
		// Do whatever you want here...
		fprintf(stdout, "OUTPUT: %s", buf);
	}

	fprintf(stdout, "Output ALL: '%s'\n", buf);
	fprintf(stdout, "Output ALL2: '%s'\n", *out);

	// Remove the trailing newline character from buf
	size_t len = strlen(buf);
	if (len > 0 && buf[len - 1] == '\n') {
		buf[len - 1] = '\0';
	}

	// Copy the result to *out
	*out = strdup(buf);
	if (*out == NULL) {
		fprintf(stderr, "Error: Out of memory\n");
		pclose(fp);
		return AC_ERROR;
	} else {
		fprintf(stdout, "Output FINAL: '%s'\n", *out);
	}

        /* close */
        pclose(fp);

        return AC_SUCCESS;
}

static ac_stat ac_generate_hotp_token(const cJSON *challenges, char **out) {
	cJSON *challenge = NULL;
        const int challenge_count = 32; // !! ATM it's 32 for each payload that contains challenges which are *NOT* during registration step
        int challenge_int[challenge_count];
        int i = 0;
	cJSON_ArrayForEach(challenge, challenges)
	{
		if (cJSON_IsNumber(challenge)) {
			fprintf(stdout, "Received challenge: %d\n", challenge->valueint);
                        challenge_int[i] = challenge->valueint;
                        i++;
		}
	}

	char *response = NULL;
	fprintf(stdout, "Running PUF script with challenges...\n");
        if (ac_run_python_puf_script_regular_step(challenge_int, challenge_count, &response) == AC_ERROR) {
		fprintf(stderr, "Error: Could not run PUF script\n");
                return AC_ERROR;
        } else {
		fprintf(stdout, "PUF script done, output: '%s'\n", response);
	}

	cotp_error_t cotp_err;
	char *hotp_local;

	// TODO generate the HOTP token from the response
	
	char *response_base32 = base32_encode((const uchar *)response,
					strlen(response) + 1, &cotp_err);

	if (cotp_err != 0) {
		fprintf(stderr, "Error: Could not encode response to base32\n");
		return AC_ERROR;
	}

	fprintf(stdout, "HOTP params: %s / %s, %d, %d, %d\n", response, response_base32, 1, 6, SHA1);
	
	hotp_local = get_hotp(response_base32, 1, 6, SHA1, &cotp_err);
	if (cotp_err != 0) {
		// TODO handle err
		fprintf(stderr, "Error: Could not generate HOTP token, check parameters!\n");
		return AC_ERROR;
	}

	cJSON *hotp_json = cJSON_CreateObject();
	if (hotp_json == NULL) {
		fprintf(stderr, "Error: Could not create JSON object\n");
		return AC_ERROR;
	}

	if (cJSON_AddStringToObject(hotp_json, "HOTP_TOKEN", hotp_local) == NULL) {
		fprintf(stderr, "Error: Could not add HOTP_TOKEN to JSON object\n");
		cJSON_Delete(hotp_json);
		return AC_ERROR;
	}

	// Reason 2 means that the server should check the HOTP token
	if (cJSON_AddNumberToObject(hotp_json, "REASON", 2) == NULL) {
		fprintf(stderr, "Error: Could not add REASON to JSON object\n");
		cJSON_Delete(hotp_json);
		return AC_ERROR;
	}

	char *hotp_str = cJSON_PrintUnformatted(hotp_json);
	if (hotp_str == NULL) {
		fprintf(stderr, "Error: Could not print JSON object\n");
		cJSON_Delete(hotp_json);
		return AC_ERROR;
	}

	*out = strdup(hotp_str);
	cJSON_Delete(hotp_json);
	free(hotp_str);

	// *out = strdup(hotp_local);

	fprintf(stdout, "Generated HOTP token: %s\n", *out);

	return AC_SUCCESS;
}

static ac_stat ac_generate_challenge_response_pairs(const cJSON *registration_challenges, char **out)
{
	cJSON *challenge = NULL;
        const int challenge_count = 64;
        int challenge_int[challenge_count];
        int i = 0;
	cJSON_ArrayForEach(challenge, registration_challenges)
	{
		if (cJSON_IsNumber(challenge)) {
			fprintf(stdout, "Received challenge: %d\n", challenge->valueint);
                        challenge_int[i] = challenge->valueint;
                        i++;
                        // TODO run python script to generate the response
                        // Get the python output and append to new JSON array, lastly print the array contents to string
		}
	}

        char *response = NULL;
	fprintf(stdout, "Running PUF script with challenges...\n");
        if (ac_run_python_puf_script(challenge_int, challenge_count, &response) == AC_ERROR) {
                return AC_ERROR;
        } else {
		fprintf(stdout, "PUF script done, output: '%s'\n", response);
	}

        fprintf(stdout, "Received response: %s\n", response);

        cJSON *response_json = cJSON_CreateObject();
        if (response_json == NULL) {
                fprintf(stderr, "Error: Could not create JSON object\n");
                return AC_ERROR;
        }

        if (cJSON_AddStringToObject(response_json, "CHALLENGE_RESPONSE", response) == NULL) {
                fprintf(stderr, "Error: Could not add string to JSON object\n");
                cJSON_Delete(response_json);
                return AC_ERROR;
        }

        if (cJSON_AddStringToObject(response_json, "DEVICE_MAC", MOCK_MAC) == NULL) {
		fprintf(stderr, "Error: Could not add string to JSON object\n");
                cJSON_Delete(response_json);
		// ret = AC_ERROR;
		// goto out;
	}

        if (cJSON_AddNumberToObject(response_json, "REASON", 1) == NULL) { // reson of 1 means update responses in the database
		fprintf(stderr, "Error: Could not add string to JSON object\n");
                cJSON_Delete(response_json);
		// ret = AC_ERROR;
		// goto out;
	}

        char *response_str = cJSON_PrintUnformatted(response_json);
        if (response_str == NULL) {
                fprintf(stderr, "Error: Could not print JSON object\n");
                cJSON_Delete(response_json);
                return AC_ERROR;
        } else {
                fprintf(stdout, "Generated response: '%s'\n", response_str);
        }

        *out = response_str;
        cJSON_Delete(response_json);

        return AC_SUCCESS;
}

static ac_stat ac_parse_auth_continue_payload(char *auth_data, char **out)
{
	cJSON *parsed_json = cJSON_Parse(auth_data);
	if (parsed_json == NULL) {
		const char *error_ptr = cJSON_GetErrorPtr();
		if (error_ptr != NULL) {
			fprintf(stderr, "Error before: %s\n", error_ptr);
		}
		return AC_ERROR;
	}

	const cJSON *challenges = cJSON_GetObjectItem(parsed_json, "CHALLENGES");
	const cJSON *reason = cJSON_GetObjectItem(parsed_json, "REASON");

	if (cJSON_IsNumber(reason)) {
		fprintf(stdout, "Received reason: '%s'\n", reason->valuestring);

		if (reason->valueint == 0) {
			fprintf(stdout, "Received registration reason\n");
			goto registration;
		} else if (reason->valueint == 1) {
			fprintf(stdout, "Received authentication reason\n");
			goto regular_challenge;
		} else {
			fprintf(stderr, "Received unknown reason: '%s'\n", reason->valuestring);
			return AC_ERROR;
		}
	} else {
		fprintf(stderr, "Did not receive reason!\n");
		return AC_ERROR;
	}

regular_challenge:

	if (ac_generate_hotp_token(challenges, out) != AC_SUCCESS) {
		fprintf(stderr, "Error: Could not generate HOTP token\n");
		return AC_ERROR;
	}

	return AC_SUCCESS;


registration:
	if (cJSON_IsArray(challenges)) {
		if (ac_generate_challenge_response_pairs(challenges, out) == AC_ERROR) {
                        return AC_ERROR;
                }

                if (*out != NULL) {
                        fprintf(stdout, "Received PUF response: '%s'\n", *out);
                } else {
                        fprintf(stderr, "Did not receive PUF response!\n");
                        return AC_ERROR;
                }
	} else {
		fprintf(stdout, "Did not receive challenges!\n");
	}

	// const cJSON *hotp_local = cJSON_GetObjectItem(parsed_json, "hotp_local");
	// if (cJSON_IsString(hotp_local) && (hotp_local->valuestring != NULL)) {
	//         fprintf(stdout, "Received HOTP local: '%s'\n", hotp_local->valuestring);
	// } else {
	//         fprintf(stderr, "Did not receive HOTP local, exiting!\n");
	//         return AC_ERROR;
	// }

	// *out = cJSON_PrintUnformatted(parsed_json);
	// cJSON_Delete(parsed_json);

	return AC_SUCCESS;
}

static int ac_on_ext_auth(struct mosquitto *mosq, void *obj, const char *auth_method, uint16_t auth_data_len,
			  const void *auth_data, const mosquitto_property *properties)
{
	if (auth_data_len > 0) {
		fprintf(stdout, "Received authentication data: '%s'\n", (char *)auth_data);
	} else {
		fprintf(stderr, "Did not receive any AUTH data, exiting!\n");
		return MOSQ_ERR_AUTH;
	}

        char *auth_data_cnt = NULL;

        ac_parse_auth_continue_payload((char *)auth_data, &auth_data_cnt);

        // TODO parse the auth_data and check;
        // if challenges are received, generate the responses and send them back
        // if one challenge is received, generate the OTP and send it

	return mosquitto_ext_auth_continue(mosq, auth_method, strlen(auth_data_cnt),
					   auth_data_cnt, NULL);
}

static ac_stat ac_set_mosq_callbacks(struct mosquitto **mosq)
{
	mosquitto_connect_v5_callback_set(*mosq, ac_on_connect);
	mosquitto_publish_v5_callback_set(*mosq, ac_on_publish);
	mosquitto_log_callback_set(*mosq, ac_log_callback);
	mosquitto_ext_auth_callback_set(*mosq, ac_on_ext_auth);

	return AC_SUCCESS;
}

static ac_stat ac_create_new_client(struct mosquitto **mosq)
{
	*mosq = mosquitto_new(NULL, true, NULL);
	if (*mosq == NULL) {
		fprintf(stderr, "Error: Out of memory\n");
		return AC_ERROR;
	}

	// Must be set, otherwise will not recognise the MQTT v5 specific options
	mosquitto_int_option(*mosq, MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);

	return AC_SUCCESS;
}

static ac_stat parse_opts(int argc, char *argv[], char **mqtt_host, int *mqtt_port, char **mqtt_auth_method)
{
	int opt;
	while ((opt = getopt(argc, argv, "h:p:m:")) != -1) {
		switch (opt) {
		case 'h':
			*mqtt_host = optarg;
			break;
		case 'p':
			*mqtt_port = atoi(optarg);
			break;
		case 'm':
			*mqtt_auth_method = optarg;
			break;
		default:
			fprintf(stderr, "Usage: %s [-h mqtt_host] [-p mqtt_port] [-m mqtt_auth_method]\n",
				argv[0]);
			return AC_ERROR;
		}
	}

	return AC_SUCCESS;
}

static ac_stat create_mac_payload(const char *device_mac, char **out)
{
	cJSON *json = cJSON_CreateObject();
	ac_stat ret = AC_SUCCESS;

	if (json == NULL) {
		fprintf(stderr, "Error: Could not create JSON object\n");
		return AC_ERROR;
	}

	if (cJSON_AddStringToObject(json, "DEVICE_MAC", device_mac) == NULL) {
		fprintf(stderr, "Error: Could not add string to JSON object\n");
		ret = AC_ERROR;
		goto out;
	}

	// It will allocate a string and print a JSON representation of the tree into it. Once it returns, you are fully responsible for deallocating it after use with your allocator. (usually free, depends on what has been set with cJSON_InitHooks).
	*out = cJSON_PrintUnformatted(json);
	if (out == NULL) {
		fprintf(stderr, "Error: Could not print JSON object\n");
		ret = AC_ERROR;
		goto out;
	}

out:
	// TODO does this suffice? since `*out` is a pointer to the cJSON object
	cJSON_Delete(json);
	return AC_SUCCESS;
}

int main(int argc, char *argv[])
{
	char *mqtt_host		     = "127.0.0.1";
	int mqtt_port		     = 1883;
	char *mqtt_auth_method	     = HOTP_METHOD;
	char *mac_payload	     = NULL;
	struct mosquitto *mosq	     = NULL;
	mosquitto_property *proplist = NULL;
	int rc			     = 0;

	printf("Sample Auth Client V2\n");

	parse_opts(argc, argv, &mqtt_host, &mqtt_port, &mqtt_auth_method);

	// Required before calling other mosquitto functions
	mosquitto_lib_init();

	if (ac_create_new_client(&mosq) == AC_ERROR) {
		return 1;
	}

	if (ac_set_mosq_callbacks(&mosq) == AC_ERROR) {
		return 1;
	}

	if (create_mac_payload(MOCK_MAC, &mac_payload)) {
		return AC_ERROR;
	}

	// Populate initial AUTH properties
	rc = mosquitto_property_add_string(&proplist, MQTT_PROP_AUTHENTICATION_METHOD, mqtt_auth_method);
	if (rc) {
		fprintf(stderr, "Error: Unable to add AUTH method property\n");
		mosquitto_property_free_all(&proplist);
		return AC_ERROR;
	}

	rc = mosquitto_property_add_binary(&proplist, MQTT_PROP_AUTHENTICATION_DATA, mac_payload,
					   strlen(mac_payload));
	if (rc) {
		fprintf(stderr, "Error: Unable to add AUTH data property\n");
		mosquitto_property_free_all(&proplist);
		return AC_ERROR;
	}

	// Connect to the broker
	fprintf(stdout, "Connecting to broker %s:%d\n", mqtt_host, mqtt_port);
	rc = mosquitto_connect_bind_v5(mosq, mqtt_host, mqtt_port, 60, NULL, proplist);
	if (rc != MOSQ_ERR_SUCCESS) {
		mosquitto_destroy(mosq);
		fprintf(stderr, "Error binding to broker [%d]: %s\n", rc, mosquitto_strerror(rc));
		return AC_ERROR;
	}

	// Start the network loop
	rc = mosquitto_loop_start(mosq);
	if (rc != MOSQ_ERR_SUCCESS) {
		mosquitto_destroy(mosq);
		fprintf(stderr, "Error: %s\n", mosquitto_strerror(rc));
		return AC_ERROR;
	}

	/* At this point the client is connected to the network socket, but may not
	 * have completed CONNECT/CONNACK.
	 * It is fairly safe to start queuing messages at this point, but if you
	 * want to be really sure you should wait until after a successful call to
	 * the connect callback.
	 * In this case we know it is 1 second before we start publishing.
	 */
	while (1) {

	// TODO: Implement the sensor data publishing
		// publish_sensor_data(mosq);
		sleep(1);
		fprintf(stdout, "Published sensor data\n");
	}

	fprintf(stdout, "Connected to broker %s:%d\n", mqtt_host, mqtt_port);
	sleep(1);

	free(mac_payload);
	mosquitto_lib_cleanup();
	return AC_SUCCESS;
}
