// https://www.googleadservices.com/pagead/aclk?sa=L&ai=DChcSEwjQnZaPzMeKAxVkVZEFHX4XH3QYABAAGgJscg&ae=2&aspm=1&co=1&ase=2&gclid=Cj0KCQiAvbm7BhC5ARIsAFjwNHtB9F7sCMqnzGl4FZxnmoPS5j7PZvbxfEU2bIyL-K-O0p0HRWJess0aAlWkEALw_wcB&ohost=www.google.com&cid=CAESVeD2bMqjvZsu1XHwnfm-E916hAY-mOzytUfuP8qrQQVEvbXxyu4mOKbFPg5YrF3ssvQVeCmj-R9Lxu-XCtCNURRB1gofRXc043wjuLpmCNeNM8vPYCs&sig=AOD64_097dWoJISB0Gy4ru1PUdLI9WkVug&q&nis=4&adurl&ved=2ahUKEwj41JGPzMeKAxXuJhAIHeL9EmkQ0Qx6BAgMEAE
// https://developer.confluent.io/get-started/c/?utm_medium=sem&utm_source=google&utm_campaign=ch.sem_br.nonbrand_tp.prs_tgt.dsa_mt.dsa_rgn.emea_lng.eng_dv.all_con.confluent-developer&utm_term=&creative=&device=c&placement=&gad_source=1&gclid=Cj0KCQiAvbm7BhC5ARIsAFjwNHtB9F7sCMqnzGl4FZxnmoPS5j7PZvbxfEU2bIyL-K-O0p0HRWJess0aAlWkEALw_wcB
// https://code.visualstudio.com/docs/cpp/config-wsl

#include <glib.h>
#include <librdkafka/rdkafka.h>
#define _POSIX_C_SOURCE 200809L

#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "common.c"

#define ARR_SIZE(arr) ( sizeof((arr)) / sizeof((arr[0])) )


/* Optional per-message delivery callback (triggered by poll() or flush())
 * when a message has been successfully delivered or permanently
 * failed delivery (after retries).
 */
static void dr_msg_cb (rd_kafka_t *kafka_handle,
                       const rd_kafka_message_t *rkmessage,
                       void *opaque) {
    if (rkmessage->err) {
        g_error("Message delivery failed: %s", rd_kafka_err2str(rkmessage->err));
    }
}

int main (int argc, char **argv) {
    rd_kafka_t *producer;
    rd_kafka_conf_t *conf;
    char errstr[512];
    unsigned long long message_count = 1000;  // default no of messages if nut passed as argument
    unsigned long long num_burst = 1000;
    if (argc > 1) {
        sscanf(argv[1], "%llu", &message_count);
    }
    if (argc > 2) {
        sscanf(argv[2], "%llu", &num_burst);
    }
    
    // Create client configuration
    conf = rd_kafka_conf_new();
    
    // User-specific properties that you must set
    set_config(conf, "bootstrap.servers", "localhost:9092");
    set_config(conf, "security.protocol", "plaintext");

    // Install a delivery-error callback.
    rd_kafka_conf_set_dr_msg_cb(conf, dr_msg_cb);

    // Create the Producer instance.
    producer = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
    if (!producer) {
        g_error("Failed to create new producer: %s", errstr);
        return 1;
    }

    // Configuration object is now owned, and freed, by the rd_kafka_t instance.
    conf = NULL;


    // Produce data by selecting random values from these lists.
  //  const char *topic = "purchases";
    const char *topic = "pers-topic";
    const char *user_ids[6] = {"eabara", "jsmith", "sgarcia", "jbernard", "htanaka", "awalther"};
    const char *products[5] = {"book", "alarm clock", "t-shirts", "gift card", "batteries"};
   // char time_str[80];
    for (unsigned long long  i = 0; i < message_count; i++) {
        const char *key =  user_ids[random() % ARR_SIZE(user_ids)];
        const char *value =  products[random() % ARR_SIZE(products)];
        size_t key_len = strlen(key);
        size_t value_len = strlen(value);

        // Create a unique-key = the message number ensuring distribution on topics
        char unique_key[50];
        snprintf(unique_key, sizeof(unique_key),"Unique_key:%lld", i);
        key = (const char *) &unique_key;

        struct timespec spec;
        clock_gettime(CLOCK_REALTIME, &spec);
        char time_str[80];
        snprintf(time_str, sizeof(time_str), "%"PRIdMAX".%"PRIdMAX"",
            (intmax_t) spec.tv_sec, (intmax_t) spec.tv_nsec);
        char * value_str = (char *) &time_str;
        value_len = strlen(value_str);
        rd_kafka_resp_err_t err;

        err = rd_kafka_producev(producer,
                                RD_KAFKA_V_TOPIC(topic),
                                RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
                                RD_KAFKA_V_KEY((void*)key, key_len),
                                RD_KAFKA_V_VALUE((void*)value_str, value_len),
                                RD_KAFKA_V_OPAQUE(NULL),
                                RD_KAFKA_V_END);

        if (err) {
            g_error("Failed to produce to topic %s: %s", topic, rd_kafka_err2str(err));
            return 1;
        } else {
//            g_message("Produced event to topic %s: key = %12s value = %12s", topic, key, value_str);
        }

        rd_kafka_poll(producer, 0);
        if ( (i % num_burst) == 0) {
            g_message("Flushing after a burst..");
            printf("msg_count %lld\n", i );
            rd_kafka_flush(producer, 10 * 1000);
            sleep(1);     
        }
    }

    // Block until the messages are all sent.
    g_message("Flushing final messages..");
    rd_kafka_flush(producer, 10 * 1000);

    if (rd_kafka_outq_len(producer) > 0) {
        g_error("%d message(s) were not delivered", rd_kafka_outq_len(producer));
    }

    g_message("%lld events were produced to topic %s.", message_count, topic);

    rd_kafka_destroy(producer);

    return 0;
}