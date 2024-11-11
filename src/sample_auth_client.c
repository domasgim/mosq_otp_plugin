/*
 * This example shows how to publish messages from outside of the Mosquitto network loop.
 */

#include <mosquitto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cotp.h>
#include <cjson/cJSON.h>

const char *g_secret = "my_awesome_secret";
char *g_secret_base32 = NULL;

/* Callback called when the client receives a CONNACK message from the broker. */
void on_connect(struct mosquitto *mosq, void *obj, int reason_code, int flags,
		const mosquitto_property *props)
{
	/* Print out the connection result. mosquitto_connack_string() produces an
	 * appropriate string for MQTT v3.x clients, the equivalent for MQTT v5.0
	 * clients is mosquitto_reason_string().
	 */
	printf("on_connect: %s\n", mosquitto_connack_string(reason_code));
	if (reason_code != 0) {
		/* If the connection fails for any reason, we don't want to keep on
		 * retrying in this example, so disconnect. Without this, the client
		 * will attempt to reconnect. */
		mosquitto_disconnect(mosq);
	}

	/* You may wish to set a flag here to indicate to your application that the
	 * client is now connected. */
}

void log_callback(struct mosquitto *mosq, void *obj, int level, const char *str)
{
	// Print the log level and message to the console
	printf("[Level %d]: %s\n", level, str);
}

/* Callback called when the client knows to the best of its abilities that a
 * PUBLISH has been successfully sent. For QoS 0 this means the message has
 * been completely written to the operating system. For QoS 1 this means we
 * have received a PUBACK from the broker. For QoS 2 this means we have
 * received a PUBCOMP from the broker. */
void on_publish(struct mosquitto *mosq, void *obj, int mid, int flags,
		const mosquitto_property *props)
{
	printf("Message with mid %d has been published.\n", mid);
}

int get_temperature(void)
{
	sleep(1); /* Prevent a storm of messages - this pretend sensor works at 1Hz */
	return random() % 100;
}

/* This function pretends to read some data from a sensor and publish it.*/
void publish_sensor_data(struct mosquitto *mosq)
{
	char payload[20];
	int temp;
	int rc;

	/* Get our pretend data */
	temp = get_temperature();
	/* Print it to a string for easy human reading - payload format is highly
	 * application dependent. */
	snprintf(payload, sizeof(payload), "%d", temp);

	/* Publish the message
	 * mosq - our client instance
	 * *mid = NULL - we don't want to know what the message id for this message is
	 * topic = "example/temperature" - the topic on which this message will be published
	 * payloadlen = strlen(payload) - the length of our payload in bytes
	 * payload - the actual payload
	 * qos = 2 - publish with QoS 2 for this example
	 * retain = false - do not use the retained message feature for this message
	 */
	rc = mosquitto_publish(mosq, NULL, "test", strlen(payload), payload, 2,
			       false);
	if (rc != MOSQ_ERR_SUCCESS) {
		fprintf(stderr, "Error publishing: %s\n",
			mosquitto_strerror(rc));
	}
}

static int on_ext_auth(struct mosquitto *mosq, void *obj,
		       const char *auth_method, uint16_t auth_data_len,
		       const void *auth_data,
		       const mosquitto_property *properties)
{
	(void)obj;
	cotp_error_t cotp_err;
	char *hotp;

	printf("on_ext_auth CALLBACK '%s'\n", auth_method);
	// (void)auth_data;
	// (void)auth_data_len;
	// (void)properties;

	// if (!strcmp(auth_method, "KTU-HOTP-AUTH")) {
	// 	printf("Auth method not supported '%s', ignoring...", auth_method);
	// 	return MOSQ_ERR_AUTH;
	// } else {
	// 	printf("Auth method '%s' supported, continuing\n", auth_method);
	// }
	// if (auth_data_len == 0 ||
	//     (!auth_data || strcmp(auth_data, "test-request"))) {
	// 	return MOSQ_ERR_AUTH;
	// }

	if (auth_data_len > 0) {
		printf("Received authentication data: %s\n", (char *)auth_data);
	} else {
		// TODO: handle nicely, reconnect, something better than this
		printf("Did not receive any auth_data, exiting!\n");
		exit(1);
	}

	const cJSON *hotp_counter = NULL;
	cJSON *parsed_hotp_json = cJSON_Parse((char *)auth_data);

	if (parsed_hotp_json == NULL) {
		const char *error_ptr = cJSON_GetErrorPtr();
		if (error_ptr != NULL) {
			fprintf(stderr, "Error before: %s\n", error_ptr);
		}
		// TODO handle nicely
		exit(1);
		// goto end;
	}

	hotp_counter = cJSON_GetObjectItemCaseSensitive(parsed_hotp_json, "hotp_counter");
	if (cJSON_IsNumber(hotp_counter)) {
		printf("hotp_counter: '%d'\n", hotp_counter->valueint);
	} else {
                printf("Failed to find 'hotp_counter'!\n");
		// TODO handle nicely
		exit(1);
        }

	hotp = get_hotp(g_secret_base32, hotp_counter->valueint + 1, 6, SHA1, &cotp_err);

	cJSON *hotp_val = NULL;
	cJSON *hotp_json = cJSON_CreateObject();
	if (hotp_json == NULL)
	{
		// TODO handle
	}

	hotp_val = cJSON_CreateString(hotp);
	if (hotp_val == NULL)
	{
		// TODO handle
	}

	cJSON_AddItemToObject(hotp_json, "hotp_value", hotp_val);

	char *hotp_json_string = NULL;
	hotp_json_string = cJSON_Print(hotp_json);

	printf("Adding reply: '%s'\n", hotp_json_string);

        cJSON_Delete(parsed_hotp_json);

	return mosquitto_ext_auth_continue(mosq, auth_method, strlen(hotp_json_string),
					   hotp_json_string, NULL);
}

int main(int argc, char *argv[])
{
	cotp_error_t cotp_err;
	struct mosquitto *mosq;
	int rc;

	/* Required before calling other mosquitto functions */
	mosquitto_lib_init();

	g_secret_base32 = base32_encode((const uchar *)g_secret, strlen(g_secret) + 1, &cotp_err);

	/* Create a new client instance.
	 * id = NULL -> ask the broker to generate a client id for us
	 * clean session = true -> the broker should remove old sessions when we connect
	 * obj = NULL -> we aren't passing any of our private data for callbacks
	 */
	mosq = mosquitto_new(NULL, true, NULL);
	if (mosq == NULL) {
		fprintf(stderr, "Error: Out of memory.\n");
		return 1;
	}

	mosquitto_int_option(mosq, MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);

	/* Configure callbacks. This should be done before connecting ideally. */
	mosquitto_connect_v5_callback_set(mosq, on_connect);
	mosquitto_publish_v5_callback_set(mosq, on_publish);
	mosquitto_log_callback_set(mosq, log_callback);
	mosquitto_ext_auth_callback_set(mosq, on_ext_auth);
	// mosquitto_message_v5_callback_set(mosq, on_message_cb);

	mosquitto_property *proplist = NULL;
	rc = mosquitto_property_add_string(
		&proplist, MQTT_PROP_AUTHENTICATION_METHOD, "KTU-HOTP-AUTH");
	if (rc) {
		mosquitto_property_free_all(&proplist);
		return rc;
	}

	/* Connect to test.mosquitto.org on port 1883, with a keepalive of 60 seconds.
	 * This call makes the socket connection only, it does not complete the MQTT
	 * CONNECT/CONNACK flow, you should use mosquitto_loop_start() or
	 * mosquitto_loop_forever() for processing net traffic. */
	rc = mosquitto_connect_bind_v5(mosq, "127.0.0.1", 1883, 60, NULL,
				       proplist);
	if (rc != MOSQ_ERR_SUCCESS) {
		mosquitto_destroy(mosq);
		fprintf(stderr, "Error binding to broker [%d]: %s\n", rc,
			mosquitto_strerror(rc));
		return 1;
	}

	/* Run the network loop in a background thread, this call returns quickly. */
	rc = mosquitto_loop_start(mosq);
	if (rc != MOSQ_ERR_SUCCESS) {
		mosquitto_destroy(mosq);
		fprintf(stderr, "Error: %s\n", mosquitto_strerror(rc));
		return 1;
	}

	/* At this point the client is connected to the network socket, but may not
	 * have completed CONNECT/CONNACK.
	 * It is fairly safe to start queuing messages at this point, but if you
	 * want to be really sure you should wait until after a successful call to
	 * the connect callback.
	 * In this case we know it is 1 second before we start publishing.
	 */
	while (1) {
		publish_sensor_data(mosq);
	}

	mosquitto_lib_cleanup();
	return 0;
}
