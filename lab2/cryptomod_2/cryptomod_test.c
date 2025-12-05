/*
 * Cryptomod Kernel Module for UNIX programming course
 * Implements AES encryption/decryption with ioctl interface
 * by Chun-Ying Huang (Modified by Student)
 * License: GPLv2
 */
#include <linux/cdev.h>
#include <linux/cred.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "cryptomod.h"
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>

static dev_t devnum;
static struct cdev c_dev;
static struct class *clazz;
static DEFINE_MUTEX(crypto_mutex);

static size_t total_read = 0;
static size_t total_written = 0;
static unsigned int byte_freq[256] = {0}; // 加密後 output 的頻率統計
DEFINE_MUTEX(stat_mutex);

#define BUFFER_SIZE 4096
#define AES_BLOCK_SIZE 16

static struct crypto_dev_data {
  char key[CM_KEY_MAX_LEN];
  int key_len;
  enum IOMode io_mode;
  enum CryptoMode c_mode;
  bool finalized;

  char buffer[BUFFER_SIZE];
  size_t buffer_len;

  char pending[AES_BLOCK_SIZE];
  size_t pending_len;

  char output[BUFFER_SIZE];
  size_t output_len;
} crypto_data;

static int aes_crypt(char *input, char *output, size_t len, bool encrypt,
                     const char *key, int key_len) {
  struct crypto_skcipher *tfm;
  struct skcipher_request *req;
  struct scatterlist sg_in, sg_out;
  struct crypto_wait wait;
  int ret;

  // ✅ 參數檢查
  if (!input || !output || !key || key_len == 0 || len == 0 ||
      len % AES_BLOCK_SIZE != 0) {
    printk("cryptodev: aes_crypt invalid params: in=%px out=%px len=%zu\n",
           input, output, len);
    return -EINVAL;
  }

  tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
  if (IS_ERR(tfm)) {
    return PTR_ERR(tfm);
  }

  ret = crypto_skcipher_setkey(tfm, key, key_len);
  if (ret) {
    goto out_free_tfm;
  }

  req = skcipher_request_alloc(tfm, GFP_KERNEL);
  if (!req) {
    ret = -ENOMEM;
    goto out_free_tfm;
  }

  crypto_init_wait(&wait);
  skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                                crypto_req_done, &wait);

  sg_init_one(&sg_in, input, len);
  sg_init_one(&sg_out, output, len);
  skcipher_request_set_crypt(req, &sg_in, &sg_out, len, NULL);

  ret = encrypt ? crypto_wait_req(crypto_skcipher_encrypt(req), &wait)
                : crypto_wait_req(crypto_skcipher_decrypt(req), &wait);

  skcipher_request_free(req);
out_free_tfm:
  crypto_free_skcipher(tfm);
  return ret;
}

static ssize_t cryptodev_read(struct file *f, char __user *buf, size_t len,
                              loff_t *off) {
  if (!crypto_data.key_len) {
    return -EINVAL;
  }

  if (!crypto_data.finalized) {
    return -EAGAIN;
  }

  if (crypto_data.buffer_len == 0) {
    return 0; // EOF
  }

  if (crypto_data.io_mode == BASIC) {
    if (len > crypto_data.buffer_len) {
      len = crypto_data.buffer_len;
    }

    char *temp_buf = kmalloc(len, GFP_KERNEL);
    if (!temp_buf)
      return -ENOMEM;

    // 先備份 output buffer
    memcpy(temp_buf, crypto_data.buffer, len);

    // 再傳給 user
    if (copy_to_user(buf, temp_buf, len)) {
      kfree(temp_buf);
      return -EBUSY;
    }

    // 移動 buffer，清除已讀區段
    memmove(crypto_data.buffer, crypto_data.buffer + len,
            crypto_data.buffer_len - len);
    crypto_data.buffer_len -= len;

    // 正確統計剛剛傳給 user 的資料
    mutex_lock(&stat_mutex);
    if (crypto_data.c_mode == ENC) {
      for (size_t i = 0; i < len; ++i)
        byte_freq[(unsigned char)temp_buf[i]]++;
    }
    total_read += len;
    mutex_unlock(&stat_mutex);

    kfree(temp_buf);
    return len;
  } else if (crypto_data.io_mode == ADV) {
    if (crypto_data.output_len == 0) {
      if (crypto_data.finalized)
        return 0; // EOF
      else
        return -EAGAIN;
    }

    if (len > crypto_data.output_len) {
      len = crypto_data.output_len;
    }

    char *temp_buf = kmalloc(len, GFP_KERNEL);
    if (!temp_buf)
      return -ENOMEM;

    memcpy(temp_buf, crypto_data.output, len);

    if (copy_to_user(buf, temp_buf, len)) {
      kfree(temp_buf);
      return -EBUSY;
    }

    memmove(crypto_data.output, crypto_data.output + len,
            crypto_data.output_len - len);
    crypto_data.output_len -= len;

    mutex_lock(&stat_mutex);
    if (crypto_data.c_mode == ENC) {
      for (size_t i = 0; i < len; ++i)
        byte_freq[(unsigned char)temp_buf[i]]++;
    }
    total_read += len;
    mutex_unlock(&stat_mutex);

    kfree(temp_buf);
    return len;
  }

  return -EINVAL;
}

static ssize_t cryptodev_write(struct file *f, const char __user *buf,
                               size_t len, loff_t *off) {
  if (!crypto_data.key_len || crypto_data.finalized)
    return -EINVAL;

  if (crypto_data.io_mode == BASIC) {
    if (crypto_data.buffer_len + len > BUFFER_SIZE) {
      len = BUFFER_SIZE - crypto_data.buffer_len;
      if (len == 0)
        return -EAGAIN;
    }

    if (copy_from_user(crypto_data.buffer + crypto_data.buffer_len, buf, len))
      return -EBUSY;

    crypto_data.buffer_len += len;

    mutex_lock(&stat_mutex);
    total_written += len;
    mutex_unlock(&stat_mutex);

    return len;
  }

  // ADV 模式
  else if (crypto_data.io_mode == ADV) {
    size_t written = 0;

    // 安全防呆檢查
    if (crypto_data.output_len > BUFFER_SIZE) {
      printk("cryptodev: output_len corrupted (%zu), reset to 0\n",
             crypto_data.output_len);
      crypto_data.output_len = 0;
    }

    while (written < len) {
      size_t available = AES_BLOCK_SIZE - crypto_data.pending_len;
      size_t remain = len - written;
      size_t to_copy = min(available, remain);

      // ✅ copy 使用正確目的地：pending
      if (copy_from_user(crypto_data.pending + crypto_data.pending_len,
                         buf + written, to_copy))
        return -EBUSY;

      crypto_data.pending_len += to_copy;
      written += to_copy;

      // 滿 16 bytes 就處理
      if (crypto_data.pending_len == AES_BLOCK_SIZE) {
        if (crypto_data.c_mode == ENC) {
          if (crypto_data.output_len + AES_BLOCK_SIZE > BUFFER_SIZE)
            return -EAGAIN;

          char *block_out = kmalloc(AES_BLOCK_SIZE, GFP_KERNEL);
          if (!block_out)
            return -ENOMEM;

          int ret = aes_crypt(crypto_data.pending, block_out, AES_BLOCK_SIZE,
                              true, crypto_data.key, crypto_data.key_len);
          if (ret) {
            printk("cryptodev: aes_crypt ENC failed: %d\n", ret);
            kfree(block_out);
            return ret;
          }

          memcpy(crypto_data.output + crypto_data.output_len, block_out,
                 AES_BLOCK_SIZE);
          crypto_data.output_len += AES_BLOCK_SIZE;
          kfree(block_out);

        } else {
          // DEC 模式，先緩衝，等 FINALIZE 再解
          if (crypto_data.buffer_len + AES_BLOCK_SIZE > BUFFER_SIZE)
            return -EAGAIN;

          memcpy(crypto_data.buffer + crypto_data.buffer_len,
                 crypto_data.pending, AES_BLOCK_SIZE);
          crypto_data.buffer_len += AES_BLOCK_SIZE;
        }

        crypto_data.pending_len = 0;
      }
    }

    mutex_lock(&stat_mutex);
    total_written += written;
    mutex_unlock(&stat_mutex);

    return written;
  }

  return -EINVAL;
}

static int cryptodev_open(struct inode *i, struct file *f) {
  printk("cryptodev: device opened.\n");
  return 0;
}

static int cryptodev_close(struct inode *i, struct file *f) {
  printk("cryptodev: device closed.\n");
  return 0;
}

static long cryptodev_ioctl(struct file *fp, unsigned int cmd,
                            unsigned long arg) {
  struct CryptoSetup setup;
  int ret = 0;

  mutex_lock(&crypto_mutex);
  switch (cmd) {
  case CM_IOC_SETUP:
    if (copy_from_user(&setup, (struct CryptoSetup __user *)arg,
                       sizeof(setup))) {
      ret = -EBUSY;
      break;
    }
    if (setup.key_len != 16 && setup.key_len != 24 && setup.key_len != 32) {
      ret = -EINVAL;
      break;
    }
    memcpy(crypto_data.key, setup.key, setup.key_len);
    crypto_data.key_len = setup.key_len;
    crypto_data.io_mode = setup.io_mode;
    crypto_data.c_mode = setup.c_mode;
    crypto_data.finalized = false;
    printk("cryptodev: Setup AES-%d mode %d c_mode %d\n", setup.key_len * 8,
           setup.io_mode, setup.c_mode);
    break;

  case CM_IOC_FINALIZE:
    if (!crypto_data.key_len) {
      ret = -EINVAL;
      break;
    }

    {
      char *temp_buf = kmalloc(BUFFER_SIZE, GFP_KERNEL);
      char block_in[AES_BLOCK_SIZE];
      char block_out[AES_BLOCK_SIZE];

      if (!temp_buf) {
        ret = -ENOMEM;
        break;
      }

      size_t offset = 0;

      if (crypto_data.io_mode == ADV) {
        char block_in[AES_BLOCK_SIZE];
        char block_out[AES_BLOCK_SIZE];

        if (crypto_data.c_mode == ENC) {
          // 加密：對 pending 填 padding，處理最後一塊
          int pad = AES_BLOCK_SIZE - crypto_data.pending_len;
          if (crypto_data.output_len + AES_BLOCK_SIZE > BUFFER_SIZE) {
            ret = -ENOMEM;
            break;
          }
          for (int i = 0; i < pad; ++i) {
            crypto_data.pending[crypto_data.pending_len + i] = pad;
          }

          aes_crypt(crypto_data.pending, block_out, AES_BLOCK_SIZE, true,
                    crypto_data.key, crypto_data.key_len);
          memcpy(crypto_data.output + crypto_data.output_len, block_out,
                 AES_BLOCK_SIZE);
          crypto_data.output_len += AES_BLOCK_SIZE;
          crypto_data.pending_len = 0;

        } else { // DEC
          // 解密：buffer 裡最後一塊是最後密文，要解開並處理 padding
          if (crypto_data.buffer_len < AES_BLOCK_SIZE) {
            ret = -EINVAL;
            break;
          }

          size_t last_block_offset = crypto_data.buffer_len - AES_BLOCK_SIZE;
          memcpy(block_in, crypto_data.buffer + last_block_offset,
                 AES_BLOCK_SIZE);

          ret = aes_crypt(block_in, block_out, AES_BLOCK_SIZE, false,
                          crypto_data.key, crypto_data.key_len);
          if (ret)
            break;

          int pad = block_out[AES_BLOCK_SIZE - 1];
          if (pad <= 0 || pad > AES_BLOCK_SIZE) {
            ret = -EINVAL;
            break;
          }

          for (int i = 1; i <= pad; ++i) {
            if (block_out[AES_BLOCK_SIZE - i] != pad) {
              ret = -EINVAL;
              break;
            }
          }

          if (ret == -EINVAL)
            break;

          // 將 buffer（前面解好的）和去掉 padding 的最後 block 合併
          if (crypto_data.output_len + last_block_offset + AES_BLOCK_SIZE -
                  pad >
              BUFFER_SIZE) {
            ret = -ENOMEM;
            break;
          }

          // 把前面解好的放進 output
          memcpy(crypto_data.output, crypto_data.buffer, last_block_offset);
          crypto_data.output_len = last_block_offset;

          // 加上最後解密後去掉 padding 的資料
          memcpy(crypto_data.output + crypto_data.output_len, block_out,
                 AES_BLOCK_SIZE - pad);
          crypto_data.output_len += AES_BLOCK_SIZE - pad;

          crypto_data.buffer_len = 0;
          crypto_data.pending_len = 0;
        }

        crypto_data.finalized = true;
        break;
      }

      if (crypto_data.c_mode == ENC) {
        // Apply PKCS#7 padding
        int pad = AES_BLOCK_SIZE - (crypto_data.buffer_len % AES_BLOCK_SIZE);
        if (crypto_data.buffer_len + pad > BUFFER_SIZE) {
          kfree(temp_buf);
          ret = -ENOMEM;
          break;
        }
        for (int i = 0; i < pad; ++i) {
          crypto_data.buffer[crypto_data.buffer_len + i] = pad;
        }
        crypto_data.buffer_len += pad;

        // Encrypt block by block
        while (offset < crypto_data.buffer_len) {
          memcpy(block_in, crypto_data.buffer + offset, AES_BLOCK_SIZE);
          ret = aes_crypt(block_in, block_out, AES_BLOCK_SIZE, true,
                          crypto_data.key, crypto_data.key_len);
          if (ret)
            break;
          memcpy(temp_buf + offset, block_out, AES_BLOCK_SIZE);
          offset += AES_BLOCK_SIZE;
        }

        if (ret == 0) {
          memcpy(crypto_data.buffer, temp_buf, crypto_data.buffer_len);
        }

      } else { // DEC
        // Check input is multiple of block size
        if (crypto_data.buffer_len % AES_BLOCK_SIZE != 0) {
          kfree(temp_buf);
          ret = -EINVAL;
          break;
        }

        // Decrypt block by block
        while (offset < crypto_data.buffer_len) {
          memcpy(block_in, crypto_data.buffer + offset, AES_BLOCK_SIZE);
          ret = aes_crypt(block_in, block_out, AES_BLOCK_SIZE, false,
                          crypto_data.key, crypto_data.key_len);
          if (ret)
            break;
          memcpy(temp_buf + offset, block_out, AES_BLOCK_SIZE);
          offset += AES_BLOCK_SIZE;
        }

        if (ret != 0) {
          kfree(temp_buf);
          break;
        }

        // Check and remove PKCS#7 padding
        int pad = temp_buf[offset - 1];
        if (pad <= 0 || pad > AES_BLOCK_SIZE) {
          kfree(temp_buf);
          ret = -EINVAL;
          break;
        }

        for (int i = 1; i <= pad; ++i) {
          if (temp_buf[offset - i] != pad) {
            kfree(temp_buf);
            ret = -EINVAL;
            break;
          }
        }

        if (ret == -EINVAL)
          break;

        memcpy(crypto_data.buffer, temp_buf, offset - pad);
        crypto_data.buffer_len = offset - pad;
      }

      kfree(temp_buf);
    }

    crypto_data.finalized = true;
    break;

  case CM_IOC_CLEANUP:
    memset(crypto_data.key, 0, CM_KEY_MAX_LEN);
    crypto_data.key_len = 0;
    crypto_data.io_mode = BASIC;
    crypto_data.c_mode = ENC;
    crypto_data.finalized = false;

    memset(crypto_data.buffer, 0, BUFFER_SIZE);
    crypto_data.buffer_len = 0;

    memset(crypto_data.output, 0, BUFFER_SIZE);
    crypto_data.output_len = 0;

    memset(crypto_data.pending, 0, AES_BLOCK_SIZE);
    crypto_data.pending_len = 0;

    printk("cryptodev: Cleanup called.\n");
    break;

  case CM_IOC_CNT_RST:
    mutex_lock(&stat_mutex);
    total_read = 0;
    total_written = 0;
    memset(byte_freq, 0, sizeof(byte_freq));
    mutex_unlock(&stat_mutex);
    printk("cryptodev: reset stats.\n");
    break;

  default:
    ret = -EINVAL;
  }
  mutex_unlock(&crypto_mutex);
  return ret;
}

static const struct file_operations cryptodev_fops = {
    .owner = THIS_MODULE,
    .open = cryptodev_open,
    .read = cryptodev_read,
    .write = cryptodev_write,
    .unlocked_ioctl = cryptodev_ioctl,
    .release = cryptodev_close};

static int cryptomod_proc_read(struct seq_file *m, void *v) {
  mutex_lock(&stat_mutex);

  seq_printf(m, "%zu %zu\n", total_read, total_written);

  for (int i = 0; i < 16; ++i) {
    for (int j = 0; j < 16; ++j) {
      seq_printf(m, "%u ", byte_freq[i * 16 + j]);
    }
    seq_printf(m, "\n");
  }

  mutex_unlock(&stat_mutex);
  return 0;
}

static int cryptomod_proc_open(struct inode *inode, struct file *file) {
  return single_open(file, cryptomod_proc_read, NULL);
}

static const struct proc_ops cryptomod_proc_fops = {
    .proc_open = cryptomod_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int __init cryptodev_init(void) {
  if (alloc_chrdev_region(&devnum, 0, 1, "cryptodev") < 0)
    return -1;
  if ((clazz = class_create("crypto_class")) == NULL)
    goto release_region;
  if (device_create(clazz, NULL, devnum, NULL, "cryptodev") == NULL)
    goto release_class;
  cdev_init(&c_dev, &cryptodev_fops);
  if (cdev_add(&c_dev, devnum, 1) == -1)
    goto release_device;

  proc_create("cryptomod", 0, NULL, &cryptomod_proc_fops);

  printk("cryptodev: initialized.\n");
  return 0;

release_device:
  device_destroy(clazz, devnum);
release_class:
  class_destroy(clazz);
release_region:
  unregister_chrdev_region(devnum, 1);
  return -1;
}

static void __exit cryptodev_cleanup(void) {
  remove_proc_entry("cryptomod", NULL);

  cdev_del(&c_dev);
  device_destroy(clazz, devnum);
  class_destroy(clazz);
  unregister_chrdev_region(devnum, 1);

  printk("cryptodev: cleaned up.\n");
}

module_init(cryptodev_init);
module_exit(cryptodev_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Student");
MODULE_DESCRIPTION("Cryptomod Kernel Module for AES Encryption/Decryption");
