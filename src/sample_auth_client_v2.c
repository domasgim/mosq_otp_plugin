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

static int ac_on_ext_auth(struct mosquitto *mosq, void *obj, const char *auth_method, uint16_t auth_data_len,
			  const void *auth_data, const mosquitto_property *properties)
{
	if (auth_data_len > 0) {
		fprintf(stdout, "Received authentication data: '%s'\n", (char *)auth_data);
	} else {
		fprintf(stderr, "Did not receive any AUTH data, exiting!\n");
		return MOSQ_ERR_AUTH;
	}

        

	return MOSQ_ERR_SUCCESS;
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
	// while (1) {

	// TODO: Implement the sensor data publishing
	// publish_sensor_data(mosq);
	// }

	fprintf(stdout, "Connected to broker %s:%d\n", mqtt_host, mqtt_port);
	sleep(1);

	free(mac_payload);
	mosquitto_lib_cleanup();
	return AC_SUCCESS;
}
