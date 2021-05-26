import tensorflow.compat.v1 as tf
from crypto_tensor.config import CLUSTER, JOB_NAME

server = tf.train.Server(CLUSTER, job_name=JOB_NAME, task_index=4)
server.start()
server.join()
