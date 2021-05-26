## Usage

This an exmaple of SPDZ[1] tensor implementation.

1. start tensorboard by `tensorboard --logdir /tmp/tensorboard`
2. start tf cluster by `cd configs && ./start.sh`
3. start trainer by `./run.sh training.py`, the logs looks like:
```
(py36) eigen@eigin lr % ./run.sh training.py
training.py
['/Users/bytedance/Project/eigen/fl/examples/lr', '/Users/bytedance/Project/eigen/fl', '/Users/bytedance/Project/eigen/fl/examples/lr', '/Users/bytedance/miniconda3/envs/py36/lib/python36.zip', '/Users/bytedance/miniconda3/envs/py36/lib/python3.6', '/Users/bytedance/miniconda3/envs/py36/lib/python3.6/lib-dynload', '/Users/bytedance/miniconda3/envs/py36/lib/python3.6/site-packages']
0:00:00.010451
[[-0.23508065]
 [ 1.09503197]
 [-1.26225484]] 0.9536
WARNING:tensorflow:From training.py:104: The name tf.FIFOQueue is deprecated. Please use tf.queue.FIFOQueue instead.

WARNING:tensorflow:From training.py:160: The name tf.placeholder is deprecated. Please use tf.compat.v1.placeholder instead.

WARNING:tensorflow:From /Users/bytedance/Project/eigen/fl/crypto_tensor/spdz.py:165: The name tf.random_uniform is deprecated. Please use tf.random.uniform instead.

WARNING:tensorflow:From training.py:299: The name tf.summary.FileWriter is deprecated. Please use tf.compat.v1.summary.FileWriter instead.

WARNING:tensorflow:From training.py:300: The name tf.RunOptions is deprecated. Please use tf.compat.v1.RunOptions instead.

WARNING:tensorflow:From training.py:301: The name tf.RunMetadata is deprecated. Please use tf.compat.v1.RunMetadata instead.

Distributing...
Training...
[[ 0.07904053]
 [ 0.47259521]
 [-0.11062622]] 0.7917
```
And from the tensorboard `http://localhost:6006/`, you can see the computing graph. 

4. run the prediction by `./run.sh prediction.py`

5. stop cluster by `cd configs && ./stop.sh`

## Refer
[1] https://eprint.iacr.org/2018/482
