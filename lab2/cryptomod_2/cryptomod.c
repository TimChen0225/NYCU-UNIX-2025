#include "cryptomod.h"
#include <crypto/skcipher.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/scatterlist.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#define DEVICE_NAME "cryptodev"
#define CLASS_NAME "cryptoclass"
#define PROC_NAME "cryptomod"

static dev_t devnum;
static struct cdev c_dev;
static struct class *cryptomod_class;
static struct proc_dir_entry *proc_file;
static DEFINE_MUTEX(cryptomod_mutex);
static unsigned long total_bytes_read = 0;
static unsigned long total_bytes_written = 0;
static unsigned long byte_frequency[256] = {0};
enum { wrt, rd };

struct crypto_data {
  struct crypto_skcipher *tfm;
  struct skcipher_request *req;
  struct CryptoSetup setup;
  bool finalized;
  char buffer[1024];
  size_t buffer_len;
  char output_buffer[1024 + CM_BLOCK_SIZE];
  size_t output_len;
  struct mutex lock;
};

static void update_count(int type, size_t num) {
  mutex_lock(&cryptomod_mutex);
  if (type == wrt)
    total_bytes_written += num;
  else
    total_bytes_read += num;
  mutex_unlock(&cryptomod_mutex);
}

static int adv_aes_crypto(struct crypto_data *data, char *src, char *dst,
                          size_t len) {
  int ret;
  struct scatterlist sg_in, sg_out;
  DECLARE_CRYPTO_WAIT(wait);

  data->tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
  if (IS_ERR(data->tfm))
    return PTR_ERR(data->tfm);

  ret = crypto_skcipher_setkey(data->tfm, data->setup.key, data->setup.key_len);
  if (ret)
    goto free_tfm;

  data->req = skcipher_request_alloc(data->tfm, GFP_KERNEL);
  if (!data->req) {
    ret = -ENOMEM;
    goto free_tfm;
  }

  sg_init_one(&sg_in, src, len);
  sg_init_one(&sg_out, dst, len);
  skcipher_request_set_callback(
      data->req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
      crypto_req_done, &wait);
  skcipher_request_set_crypt(data->req, &sg_in, &sg_out, len, NULL);

  ret = (data->setup.c_mode == ENC)
            ? crypto_wait_req(crypto_skcipher_encrypt(data->req), &wait)
            : crypto_wait_req(crypto_skcipher_decrypt(data->req), &wait);

  skcipher_request_free(data->req);
free_tfm:
  crypto_free_skcipher(data->tfm);
  return ret;
}

static int adv_write_block(struct crypto_data *data, size_t process_len) {

  for (size_t offset = 0; offset < process_len; offset += CM_BLOCK_SIZE) {
    int ret = adv_aes_crypto(data, data->buffer + offset, data->buffer + offset,
                             CM_BLOCK_SIZE);
    if (ret < 0)
      return ret;

    memcpy(data->output_buffer + data->output_len, data->buffer + offset,
           CM_BLOCK_SIZE);
    data->output_len += CM_BLOCK_SIZE;
  }

  update_count(wrt, process_len);

  memmove(data->buffer, data->buffer + process_len,
          data->buffer_len - process_len);

  data->buffer_len -= process_len;

  return 0;
}

static int adv_finalize(struct crypto_data *data) {
  int ret;

  if (data->setup.c_mode == ENC) {
    update_count(wrt, data->buffer_len);

    // caculate padding
    size_t pad_len = CM_BLOCK_SIZE - (data->buffer_len % CM_BLOCK_SIZE);
    if (pad_len == 0)
      pad_len = CM_BLOCK_SIZE;

    // put padding
    if (data->buffer_len + pad_len > sizeof(data->buffer))
      return -EINVAL;

    memset(data->buffer + data->buffer_len, pad_len, pad_len);
    data->buffer_len += pad_len;

    // aes for every 16 bytes
    while (data->buffer_len >= CM_BLOCK_SIZE) {
      ret = adv_aes_crypto(data, data->buffer, data->buffer, CM_BLOCK_SIZE);
      if (ret < 0)
        return ret;

      if (data->output_len + CM_BLOCK_SIZE > sizeof(data->output_buffer))
        return -EAGAIN;

      memcpy(data->output_buffer + data->output_len, data->buffer,
             CM_BLOCK_SIZE);
      data->output_len += CM_BLOCK_SIZE;

      memmove(data->buffer, data->buffer + CM_BLOCK_SIZE,
              data->buffer_len - CM_BLOCK_SIZE);
      data->buffer_len -= CM_BLOCK_SIZE;
    }

    return 0;

  } else if (data->setup.c_mode == DEC) {
    printk(KERN_INFO "[finalize] DEC: buffer_len = %zu (should be 16)\n ",
           data->buffer_len);
    if (data->buffer_len != CM_BLOCK_SIZE)
      return -EINVAL;

    ret = adv_aes_crypto(data, data->buffer, data->buffer, CM_BLOCK_SIZE);
    if (ret < 0)
      return ret;

    unsigned char pad = data->buffer[CM_BLOCK_SIZE - 1];
    if (pad == 0 || pad > CM_BLOCK_SIZE)
      return -EINVAL;

    // check padding
    for (int i = 0; i < pad; ++i) {
      if (data->buffer[CM_BLOCK_SIZE - 1 - i] != pad)
        return -EINVAL;
    }

    size_t final_len = CM_BLOCK_SIZE - pad;
    if (data->output_len + final_len > sizeof(data->output_buffer))
      return -EAGAIN;

    memcpy(data->output_buffer + data->output_len, data->buffer, final_len);
    data->output_len += final_len;
    data->buffer_len = 0;

    update_count(wrt, CM_BLOCK_SIZE);
    return 0;
  }

  return -EINVAL;
}

static int basic_aes_crypto(struct crypto_data *data) {
  int ret;
  struct scatterlist sg;
  DECLARE_CRYPTO_WAIT(wait);

  data->tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
  if (IS_ERR(data->tfm))
    return PTR_ERR(data->tfm);

  ret = crypto_skcipher_setkey(data->tfm, data->setup.key, data->setup.key_len);
  if (ret)
    goto free_tfm;

  data->req = skcipher_request_alloc(data->tfm, GFP_KERNEL);
  if (!data->req) {
    ret = -ENOMEM;
    goto free_tfm;
  }

  size_t padding_len = CM_BLOCK_SIZE - (data->buffer_len % CM_BLOCK_SIZE);

  if (data->setup.c_mode == ENC) {
    memset(data->buffer + data->buffer_len, padding_len, padding_len);
    data->buffer_len += padding_len;
  }

  if (data->setup.c_mode == DEC && data->buffer_len % CM_BLOCK_SIZE != 0) {
    ret = -EINVAL;
    goto free_req;
  }

  sg_init_one(&sg, data->buffer, data->buffer_len);
  skcipher_request_set_callback(
      data->req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
      crypto_req_done, &wait);
  skcipher_request_set_crypt(data->req, &sg, &sg, data->buffer_len, NULL);

  ret = (data->setup.c_mode == ENC)
            ? crypto_wait_req(crypto_skcipher_encrypt(data->req), &wait)
            : crypto_wait_req(crypto_skcipher_decrypt(data->req), &wait);
  if (ret)
    goto free_req;

  if (data->setup.c_mode == DEC) {
    padding_len = data->buffer[data->buffer_len - 1];
    if (padding_len > CM_BLOCK_SIZE || padding_len <= 0) {
      ret = -EINVAL;
      goto free_req;
    }
    data->buffer_len -= padding_len;
  }

  memcpy(data->output_buffer, data->buffer, data->buffer_len);
  data->output_len = data->buffer_len;

free_req:
  skcipher_request_free(data->req);
free_tfm:
  crypto_free_skcipher(data->tfm);
  return ret;
}

static int cryptomod_proc_show(struct seq_file *m, void *v) {
  mutex_lock(&cryptomod_mutex);
  seq_printf(m, "%lu %lu", total_bytes_read, total_bytes_written);
  for (int i = 0; i < 256; i++) {
    if (i % 16 == 0)
      seq_printf(m, "\n");
    seq_printf(m, "%lu ", byte_frequency[i]);
  }
  seq_printf(m, "\n");
  mutex_unlock(&cryptomod_mutex);
  return 0;
}

static int cryptomod_proc_open(struct inode *inode, struct file *file) {
  return single_open(file, cryptomod_proc_show, NULL);
}

static const struct proc_ops cryptomod_proc_ops = {
    .proc_open = cryptomod_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int cryptomod_open(struct inode *inode, struct file *file) {
  struct crypto_data *data = kzalloc(sizeof(*data), GFP_KERNEL);
  if (!data)
    return -ENOMEM;

  mutex_init(&data->lock);
  file->private_data = data;
  return 0;
}

static int cryptomod_release(struct inode *inode, struct file *file) {
  kfree(file->private_data);
  return 0;
}

static long cryptomod_ioctl(struct file *file, unsigned int cmd,
                            unsigned long arg) {
  struct crypto_data *data = file->private_data;
  int ret = 0;

  mutex_lock(&data->lock);
  if (cmd == CM_IOC_SETUP) {
    if (copy_from_user(&data->setup, (void __user *)arg, sizeof(data->setup))) {
      mutex_unlock(&data->lock);
      return -EINVAL;
    }
    if (data->setup.key_len != 16 && data->setup.key_len != 24 &&
        data->setup.key_len != 32) {
      mutex_unlock(&data->lock);
      return -EINVAL;
    }
    if (data->setup.io_mode != BASIC && data->setup.io_mode != ADV) {
      mutex_unlock(&data->lock);
      return -EINVAL;
    }
    if (data->setup.c_mode != ENC && data->setup.c_mode != DEC) {
      mutex_unlock(&data->lock);
      return -EINVAL;
    }
    memset(data->buffer, 0, sizeof(data->buffer));
    memset(data->output_buffer, 0, sizeof(data->output_buffer));
    data->buffer_len = 0;
    data->output_len = 0;
    data->finalized = false;
    mutex_unlock(&data->lock);
    return ret;
  } else if (cmd == CM_IOC_FINALIZE) {
    if (data->finalized || !data->setup.key_len) {
      mutex_unlock(&data->lock);
      return -EINVAL;
    }
    if (data->setup.io_mode == BASIC) {
      ret = basic_aes_crypto(data);
    } else if (data->setup.io_mode == ADV) {
      ret = adv_finalize(data);
    }
    data->finalized = true;
    mutex_unlock(&data->lock);
    return ret;
  } else if (cmd == CM_IOC_CLEANUP) {
    memset(data->buffer, 0, sizeof(data->buffer));
    memset(data->output_buffer, 0, sizeof(data->output_buffer));
    data->buffer_len = 0;
    data->output_len = 0;
    data->finalized = false;
    mutex_unlock(&data->lock);
    return ret;
  } else if (cmd == CM_IOC_CNT_RST) {
    mutex_lock(&cryptomod_mutex);
    total_bytes_read = 0;
    total_bytes_written = 0;
    memset(byte_frequency, 0, sizeof(byte_frequency));
    mutex_unlock(&cryptomod_mutex);
    return ret;
  }
  mutex_unlock(&data->lock);
  return -EINVAL;
}

static ssize_t cryptomod_write(struct file *file, const char __user *buf,
                               size_t len, loff_t *offset) {
  struct crypto_data *data = file->private_data;
  size_t copied_total = 0, copied_now = 0;
  int ret = 0;
  mutex_lock(&data->lock);

  if (!data->setup.key_len || data->finalized ||
      (data->setup.io_mode == BASIC && data->buffer_len + len > 1024)) {
    mutex_unlock(&data->lock);
    return -EINVAL;
  }

  while (len > 0) {
    if (len < 1024 - data->buffer_len)
      copied_now = len;
    else
      copied_now = 1024 - data->buffer_len;

    if (copy_from_user(data->buffer + data->buffer_len, buf + copied_total,
                       copied_now)) {
      mutex_unlock(&data->lock);
      return -EBUSY;
    }

    data->buffer_len += copied_now;
    copied_total += copied_now;
    len -= copied_now;

    if (data->setup.io_mode == ADV && data->buffer_len >= CM_BLOCK_SIZE) {
      size_t process_len;
      // check if it is mutiple of block
      process_len = (data->buffer_len / CM_BLOCK_SIZE) * CM_BLOCK_SIZE;
      if (data->buffer_len % CM_BLOCK_SIZE == 0)
        process_len -= CM_BLOCK_SIZE;

      // check output buffer space
      size_t space_remaining = 1024 - data->output_len;
      if (space_remaining < process_len) {
        process_len = space_remaining - (space_remaining % CM_BLOCK_SIZE);
        // if space remian less than a block -> fail
        if (process_len == 0) {
          data->buffer_len -= copied_now;
          len += copied_now;
          mutex_unlock(&data->lock);
          return -EAGAIN;
        }
      }

      if (!process_len)
        continue;

      ret = adv_write_block(data, process_len);
      if (ret < 0) {
        mutex_unlock(&data->lock);
        return ret;
      }
    }
  }

  if (data->setup.io_mode == BASIC)
    update_count(wrt, copied_total);

  mutex_unlock(&data->lock);
  return copied_total;
}

static ssize_t cryptomod_read(struct file *file, char __user *buf, size_t len,
                              loff_t *offset) {
  struct crypto_data *data = file->private_data;
  size_t ret = 0;
  mutex_lock(&data->lock);

  if (!data->setup.key_len ||
      (!data->finalized && data->setup.io_mode == BASIC)) {
    ret = (!data->setup.key_len) ? -EINVAL : -EAGAIN;
    mutex_unlock(&data->lock);
    return ret;
  }

  if (*offset >= data->output_len) {
    data->output_len = 0;
    *offset = 0;
    mutex_unlock(&data->lock);
    return 0;
  }

  if (data->output_len - *offset < len)
    len = data->output_len - *offset;

  if (copy_to_user(buf, data->output_buffer + *offset, len)) {
    mutex_unlock(&data->lock);
    return -EBUSY;
  }

  if (data->setup.c_mode == ENC) {
    mutex_lock(&cryptomod_mutex);
    unsigned char *output = (unsigned char *)(data->output_buffer + *offset);
    for (size_t i = 0; i < len; i++)
      byte_frequency[output[i]]++;
    mutex_unlock(&cryptomod_mutex);
  }

  update_count(rd, len);
  *offset += len;
  ret = len;
  mutex_unlock(&data->lock);
  return ret;
}

static struct file_operations cryptomod_fops = {
    .owner = THIS_MODULE,
    .open = cryptomod_open,
    .release = cryptomod_release,
    .read = cryptomod_read,
    .write = cryptomod_write,
    .unlocked_ioctl = cryptomod_ioctl,
};

static int __init cryptomod_init(void) {
  int ret;
  ret = alloc_chrdev_region(&devnum, 0, 1, DEVICE_NAME);
  if (ret < 0)
    return ret;
  cryptomod_class = class_create(CLASS_NAME);
  if (IS_ERR(cryptomod_class))
    return PTR_ERR(cryptomod_class);
  device_create(cryptomod_class, NULL, devnum, NULL, DEVICE_NAME);
  cdev_init(&c_dev, &cryptomod_fops);
  ret = cdev_add(&c_dev, devnum, 1);
  if (ret < 0)
    return ret;
  proc_file = proc_create(PROC_NAME, 0, NULL, &cryptomod_proc_ops);
  return 0;
}

static void __exit cryptomod_exit(void) {
  remove_proc_entry(PROC_NAME, NULL);
  cdev_del(&c_dev);
  device_destroy(cryptomod_class, devnum);
  class_destroy(cryptomod_class);
  unregister_chrdev_region(devnum, 1);
}

module_init(cryptomod_init);
module_exit(cryptomod_exit);
MODULE_LICENSE("GPL");
