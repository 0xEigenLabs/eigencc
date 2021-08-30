#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <eigen/eigentee.h>

eigen_enclave_info_t *g_enclave_info = NULL;
eigen_auditor_set_t *g_auditors = NULL;
int32_t g_tms_port = 8082;

int submit_task(const char* method, const char* args, const char* uid,
  const char* token, char** output, size_t* output_size) {

  struct sockaddr_in tms_addr;
  char recvbuf[2048] = {0};
  int ret;

  tms_addr.sin_family = AF_INET;
  tms_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  tms_addr.sin_port = htons(g_tms_port);

  fprintf(stderr, "[+] This is a single-party task: %s\n", method);

  eigen_t *context = eigen_context_new(g_enclave_info, uid, token,
                                           (struct sockaddr *)&tms_addr);
  if (context == NULL) {
    return EXIT_FAILURE;
  }

  eigen_task_t *task = eigen_create_task(context, method);
  if (task == NULL) {
    return EXIT_FAILURE;
  }
  fprintf(stderr, "args: %s, size=%lu\n", args, strlen(args));
  // BUG result truncating
  ret = eigen_task_invoke_with_payload(task, args, strlen(args),
  recvbuf, sizeof(recvbuf));
  if (ret <= 0) {
    return EXIT_FAILURE;
  }

  fprintf(stderr, "Response: %s\n", recvbuf);
  *output_size = strlen(recvbuf);
  *output = (char*)malloc(strlen(recvbuf) + 1);
  memset(*output, 0, *output_size + 1);
  memcpy(*output, recvbuf, *output_size);

  eigen_task_free(task);
  eigen_context_free(context);
  return 0;
}

int init(const char* pub, const char* pri, const char* conf, int32_t port1) {
  eigen_init();

  g_auditors = eigen_auditor_set_new();
  eigen_auditor_set_add_auditor(
      g_auditors, pub, pri);

  if (g_auditors == NULL) {
    return EXIT_FAILURE;
  }

  g_enclave_info = eigen_enclave_info_load(g_auditors, conf);

  if (g_enclave_info ==  NULL) {
    return EXIT_FAILURE;
  }
  g_tms_port = port1;

  return 0;
}

int release() {
  eigen_enclave_info_free(g_enclave_info);
  eigen_auditor_set_free(g_auditors);
  return 0;
}

int main() {
  int32_t port = 8082;
  int result = 0;
  char *output = NULL; // malloc from `submit_task`
  size_t outputsize = 0;
#if 0
  const char *pub = "/app/release/services/auditors/godzilla/godzilla.public.der";
  const char *pri = "/app/release/services/auditors/godzilla/godzilla.sign.sha256";
  const char *conf = "/app/release/services/enclave_info.toml";
  const char *method = "echo";
  const char *args = "Hello Eigen";
  const char *uid = "uid";
  const char *token = "token";
#else
  // base_dir, e.g.,  "/app/release/services/auditors", without '/'
  const char *base_dir = getenv("TEESDK_AUDITOR_BASE_DIR");
  // auditor_name, e.g., "godzilla"
  const char *auditor_name = getenv("TEESDK_AUDITOR_NAME");
  const char pub[256] = {0};
  const char pri[256] = {0};
  const char *conf = getenv("TEESDK_ENCLAVE_INFO_PATH");
  const char* method = getenv("TEESDK_METHOD");
  const char* args = getenv("TEESDK_ARGS");
  const char* uid = getenv("TEESDK_UID");
  const char *token = getenv("TEESDK_TOKEN");

  // pub, e.g., "/app/release/services/auditors/godzilla/godzilla.public.der"
  sprintf(pub, "%s/%s/%s.public.der", base_dir, auditor_name, auditor_name);
  // pri, e.g., "/app/release/services/auditors/godzilla/godzilla.sign.sha256"
  sprintf(pri, "%s/%s/%s.sign.sha256", base_dir, auditor_name, auditor_name);
#endif

  fprintf(stderr, "method[%d]: `%s'\n", strlen(method), method);
  fprintf(stderr, "args[%d]: `%s'\n", strlen(args), args);
  fprintf(stderr, "uid[%d]: `%s'\n", strlen(uid), uid);
  fprintf(stderr, "token[%d]: `%s'\n", strlen(token), token);

  result = init(pub, pri, conf, port);

  if (result != 0) {
    fprintf(stderr, "init fail: %d\n", result);
    return -1;
  }

  result = submit_task(method, args, uid, token, &output, &outputsize);

  printf("%s", output);

  result = release();

  if (result != 0) {
    fprintf(stderr, "submit_task fail: %d\n", result);
    return -2;
  }

  // XXX: the string should end with '\0'
  fprintf(stderr, "submit_task: %s [%lu]\n", output, outputsize);

  return 0;
}
