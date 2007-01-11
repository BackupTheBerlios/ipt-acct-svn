/*
 * Copyright (C) 2006 Mikhail V. Vorozhtsov
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it would be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * 
 * Further, this software is distributed without any warranty that it is
 * free of the rightful claim of any third person regarding infringement
 * or the like.  Any license provided herein, whether implied or
 * otherwise, applies only to this software file.  Patent licenses, if
 * any, provided herein do not apply to combinations of this program with
 * other software, or any other product whatsoever.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston MA 02111-1307, USA.
 */

/* $Id$ */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/mm.h>
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include <linux/miscdevice.h>
#include <asm/uaccess.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#include <net/tcp.h>
#include <net/udp.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION (2, 5, 0)
# include <linux/sched.h>
# include <linux/poll.h>
# include <asm/poll.h>
# define get_seconds() CURRENT_TIME
# define try_module_get(x) try_inc_mod_count(x)
# define module_put(x) __MOD_DEC_USE_COUNT(x)
static inline void *
skb_header_pointer(const struct sk_buff *skb, int offset,
                   int len, void *buffer)
{
  int hlen = skb_headlen(skb);

  if (hlen - offset >= len)
    return skb->data + offset;

  if (skb_copy_bits(skb, offset, buffer, len) < 0)
    return NULL;

  return buffer;
}
#endif

#include "ipt_ACCT.h"

MODULE_LICENSE ("GPL");
MODULE_AUTHOR ("Mikhail V. Vorozhtsov <mikhail.vorozhtsov@gmail.com>");
MODULE_DESCRIPTION ("iptables accounting module");

#define DEFAULT_MAX_RECORDS (2 * 1024)

static unsigned int max_records = DEFAULT_MAX_RECORDS;
module_param (max_records, uint, 0000);
MODULE_PARM_DESC (max_records,
  "Maximum number of accouning records to hold in memory.");

static unsigned int timeout = 0;
module_param (timeout, uint, 0000);
MODULE_PARM_DESC (timeout, 
  "Dump records after TIMEOUT seconds. Zero means no dump.");

static unsigned int no_loss_p = 1;
module_param (no_loss_p, bool, 0000);
MODULE_PARM_DESC (no_loss_p, 
  "Drop new packets if accounting information has not been read.");

static const unsigned int primes[] =
{
  13, 19, 29, 41, 59, 79, 107, 149, 197, 263, 347, 457, 599, 787, 1031,
  1361, 1777, 2333, 3037, 3967, 5167, 6719, 8737, 11369, 14783,
  19219, 24989, 32491, 42257, 54941, 71429, 92861, 120721, 156941,
  204047, 265271, 344857, 448321
};

struct ipt_acct_info
{
  struct ipt_entry_target t;
  __u16 magic;
  __u16 header;
  __u8 header_p;
  __u8 critical_p;
  unsigned int retcode;
};

struct item
{
  struct item *next;
  struct ipt_acct_record *record;
};

static struct item *item_pool_0, *item_pool_1;
static struct item *acct_item_pool, *dump_item_pool;
static struct item *free_item;

static struct ipt_acct_record *pool_0, *pool_1;
static struct ipt_acct_record *acct_pool, *dump_pool;
static struct ipt_acct_record *free_record;

static unsigned int ndump;
static DECLARE_WAIT_QUEUE_HEAD (dump_wait);

static struct item **layers;
static unsigned int nlayers;

#define HASH(src,dst,sport,dport,proto,magic) \
  (((src ^ dst) + ((sport << 16) | dport)) + proto + magic)

static int device_opened_p;
static struct timer_list dump_timer;

#ifndef DEFINE_SPINLOCK
#define DEFINE_SPINLOCK(x) spinlock_t x = SPIN_LOCK_UNLOCKED
#endif

static DEFINE_SPINLOCK (hash_table_lock);
static DEFINE_SPINLOCK (dump_lock);
static DEFINE_SPINLOCK (stat_lock);

static __u64 startup_ts;
static __u64 records_lost;
static __u64 pkts_accted;
static __u64 pkts_not_accted;
static __u64 pkts_dropped;

static int
dump_is_empty_p (void)
{
  int result;
  spin_lock_bh (&dump_lock);
  result = (ndump == 0);
  spin_unlock_bh (&dump_lock);
  return result;
}

static void
ipt_acct_dump_records (int from_timer_p)
{
  unsigned int i;
  struct ipt_acct_record *tmp;
  struct item *tmp_item;

  spin_lock_bh (&dump_lock);

  if (ndump)
    {
      if (no_loss_p)
        {
          spin_unlock_bh (&dump_lock);
          return;
        }
      else
        {
          spin_lock_bh (&stat_lock);
          records_lost += ndump;
          spin_unlock_bh (&stat_lock);
        }
    }

  ndump = free_record - acct_pool;

  if (ndump == 0)
    {
      spin_unlock_bh (&dump_lock);
      return;
    }

  for (i = 0; i < nlayers; ++i)
    layers[i] = NULL;

  tmp_item = acct_item_pool;
  acct_item_pool = dump_item_pool;
  dump_item_pool = tmp_item;
  free_item = &acct_item_pool[0];

  tmp = acct_pool;
  acct_pool = dump_pool;
  dump_pool = tmp;
  free_record = &acct_pool[0];

  spin_unlock_bh (&dump_lock);

  wake_up (&dump_wait);
}

static void
ipt_acct_dump_timer (unsigned long data)
{
  spin_lock_bh (&hash_table_lock);
  ipt_acct_dump_records (1);
  spin_unlock_bh (&hash_table_lock);
}

static unsigned int
ipt_acct_handle (struct sk_buff **pskb, const struct net_device *in,
                 const struct net_device *out, unsigned int hook_number,
#if LINUX_VERSION_CODE >= KERNEL_VERSION (2, 6, 17)
                 const struct ipt_target *target,
#endif
                 const void *target_info
#if LINUX_VERSION_CODE < KERNEL_VERSION (2, 6, 19)
                 , void *user_info 
#endif
                 )
{
  unsigned int i;
  struct sk_buff *skb = *pskb;
  struct ipt_acct_info *info = (struct ipt_acct_info *) target_info;
  struct iphdr tmp_iph, *ip_header;
  struct item *item;
  u32 src, dst;
  u16 sport, dport;
  u16 size;
  u8 proto;

  ip_header = skb_header_pointer (skb, 0, sizeof (tmp_iph), &tmp_iph);

  if (!ip_header)
    return info->critical_p ? info->retcode : NF_DROP;

  if (ip_header->protocol == IPPROTO_TCP)
    {
      struct tcphdr tmp_tcph, *tcp_header;
      tcp_header = skb_header_pointer (skb, ip_header->ihl * 4,
                                       sizeof (tmp_tcph), &tmp_tcph);
      if (!tcp_header)
        return info->critical_p ? info->retcode : NF_DROP;
      sport = ntohs (tcp_header->source);
      dport = ntohs (tcp_header->dest);
    }
  else if (ip_header->protocol == IPPROTO_UDP)
    {
      struct udphdr tmp_udph, *udp_header;
      udp_header = skb_header_pointer (skb, ip_header->ihl * 4,
                                       sizeof (tmp_udph), &tmp_udph);
      if (!udp_header)
        return info->critical_p ? info->retcode : NF_DROP;
      sport = ntohs (udp_header->source);
      dport = ntohs (udp_header->dest);
    }
  else
    {
      sport = 0;
      dport = 0;
    }

  proto = ip_header->protocol;
  src = ip_header->saddr;
  dst = ip_header->daddr;
  size = ntohs (ip_header->tot_len);

  if (info->header_p) {
    size += info->header;
  } else {
#if LINUX_VERSION_CODE < KERNEL_VERSION (2, 5, 0)
    size += sizeof (*skb->mac.ethernet);
#else
    size += skb->mac_len;
#endif
  }

  i = HASH (src, dst, sport, dport, proto, info->magic) % nlayers;

  spin_lock_bh (&hash_table_lock);

  for (item = layers[i]; item; item = item->next)
    if (item->record->src == src && item->record->dst == dst
        && item->record->sport == sport && item->record->dport == dport
        && item->record->proto == proto && item->record->magic == info->magic)
      break;

  if (!item)
    {
      if (!free_item)
        ipt_acct_dump_records (0);

      if (!free_item)
        {
	  spin_lock_bh (&stat_lock);
	  if (info->critical_p)
	    pkts_not_accted += 1;
	  else
	    pkts_dropped += 1;
	  spin_unlock_bh (&stat_lock);
          spin_unlock_bh (&hash_table_lock);
          return info->critical_p ? info->retcode : NF_DROP;
        }

      item = free_item;
      item->record = free_record;

      if (++free_item == acct_item_pool + max_records)
        free_item = NULL;

      ++free_record;

      item->next = layers[i];
      layers[i] = item;
      item->record->src = src;
      item->record->dst = dst;
      item->record->sport = sport;
      item->record->dport = dport;
      item->record->proto = proto;
      item->record->npkts = 0;
      item->record->size = 0;
      item->record->first = get_seconds ();
      item->record->magic = info->magic;
    }

  item->record->npkts += 1;
  item->record->size += size;
  item->record->last = get_seconds ();

  spin_lock_bh (&stat_lock);
  if (pkts_accted == 0)
    startup_ts = item->record->last;
  pkts_accted += 1;
  spin_unlock_bh (&stat_lock);

  if (timeout > 0 && !timer_pending (&dump_timer))
    {
      dump_timer.expires = jiffies + timeout * HZ;
      add_timer (&dump_timer);
    }
  
  spin_unlock_bh (&hash_table_lock);
  return info->retcode;
}

static int
#if LINUX_VERSION_CODE >= KERNEL_VERSION (2, 6, 16)
ipt_acct_check_entry (const char *table_name, const void *entry,
# if LINUX_VERSION_CODE >= KERNEL_VERSION (2, 6, 17)
                      const struct ipt_target *target,
# endif
                      void *target_info,
# if LINUX_VERSION_CODE < KERNEL_VERSION (2, 6, 19)
                      unsigned int target_info_size,
# endif
                      unsigned int hook_mask)
#else
ipt_acct_check_entry (const char *table_name, const struct ipt_entry *entry,
                      void *target_info, unsigned int target_info_size,
                      unsigned int hook_mask)
#endif
{
  struct ipt_acct_info *info = (struct ipt_acct_info *) target_info;

#if LINUX_VERSION_CODE < KERNEL_VERSION (2, 6, 19)
  if (target_info_size != IPT_ALIGN (sizeof (struct ipt_acct_info)))
    {
      printk ("ipt_ACCT: wrong target_info_size = %u\n", target_info_size);
      return 0;
    } 
#endif
  
  if (info->retcode != IPT_CONTINUE && info->retcode != NF_ACCEPT
      && info->retcode != NF_DROP)
    {
      printk ("ipt_ACCT: wrong retcode = %u\n", info->retcode);
      return 0;
    }

  return 1;
}

static int
ipt_acct_open_device (struct inode *inode, struct file *file)
{
  if (device_opened_p)
    return -EBUSY;
  device_opened_p = 1;
  try_module_get (THIS_MODULE);
  return 0;
}

unsigned int
ipt_acct_poll_device (struct file *file, struct poll_table_struct *pt)
{
  if (!dump_is_empty_p ())
    return POLLIN | POLLRDNORM;
  poll_wait (file, &dump_wait, pt);
  return dump_is_empty_p () ? 0 : POLLIN | POLLRDNORM;
}

static int
ipt_acct_ioctl_device (struct inode *inode, struct file *file,
                       unsigned int cmd, unsigned long data)
{
  unsigned int tmp;
  struct ipt_acct_stat stat;

  switch (cmd)
    {
    case IPT_ACCT_GET_MAX:
      return max_records;
    case IPT_ACCT_DUMP:
      if (timeout)
        return 0;
      if (!dump_is_empty_p ())
        return 0;
      ipt_acct_dump_timer (0);
      return 0;
    case IPT_ACCT_GET_DUMP:
      spin_lock_bh (&dump_lock);

      if (copy_to_user ((struct ipt_acct_record *) data, dump_pool,
                        ndump * sizeof (struct ipt_acct_record)))
        {
          spin_unlock_bh (&dump_lock);
          return -EFAULT;
        }

      tmp = ndump;
      ndump = 0;
      spin_unlock_bh (&dump_lock);
      return tmp;
    case IPT_ACCT_GET_STAT:
      spin_lock_bh (&stat_lock);
      stat.startup_ts = startup_ts;
      stat.records_lost = records_lost;
      stat.pkts_accted = pkts_accted;
      stat.pkts_not_accted = pkts_not_accted;
      stat.pkts_dropped = pkts_dropped;
      spin_unlock_bh (&stat_lock);

      if (copy_to_user ((struct ipt_acct_stat *) data, &stat, sizeof (stat)))
        return -EFAULT;

      return 0;
    }

  return -EINVAL;
}

static int
ipt_acct_release_device (struct inode *inode, struct file *file)
{
  device_opened_p = 0;
  module_put (THIS_MODULE);
  return 0;
}

static struct file_operations ipt_acct_device_ops =
{
  .open = ipt_acct_open_device,
  .poll = ipt_acct_poll_device,
  .ioctl = ipt_acct_ioctl_device,
  .release = ipt_acct_release_device,
  .owner = THIS_MODULE
};

static struct miscdevice ipt_acct_device =
{
  .minor = MISC_DYNAMIC_MINOR,
  .name = IPT_ACCT_DEVICE,
#if LINUX_VERSION_CODE >= KERNEL_VERSION (2, 6, 0) \
    && LINUX_VERSION_CODE < KERNEL_VERSION (2, 6, 19)
  .devfs_name = IPT_ACCT_DEVICE,
#endif
  .fops = &ipt_acct_device_ops
};

static struct ipt_target ipt_acct_target =
{
  .name = "ACCT",
  .target = ipt_acct_handle,
  .checkentry = ipt_acct_check_entry,
#if LINUX_VERSION_CODE >= KERNEL_VERSION (2, 6, 17)
  .targetsize = sizeof (struct ipt_acct_info),
#endif
  .me = THIS_MODULE
};

static int __init
ip_acct_init (void)
{
  unsigned int i;
  int error;

  printk ("ipt_ACCT v%s\n", IPT_ACCT_VERSION);

  if (max_records == 0)
    max_records = DEFAULT_MAX_RECORDS;

  startup_ts = 0;
  records_lost = 0;
  pkts_accted = 0;
  pkts_not_accted = 0;
  pkts_dropped = 0;

  item_pool_0 = kmalloc (max_records * sizeof (struct item), GFP_KERNEL);
  item_pool_1 = kmalloc (max_records * sizeof (struct item), GFP_KERNEL);
  pool_0 = kmalloc (max_records * sizeof (struct ipt_acct_record), GFP_KERNEL);
  pool_1 = kmalloc (max_records * sizeof (struct ipt_acct_record), GFP_KERNEL);

  if (!item_pool_0 || !item_pool_1 || !pool_0 || !pool_1)
    {
      if (item_pool_0)
        kfree (item_pool_0);
      if (item_pool_1)
        kfree (item_pool_1);
      if (pool_0)
        kfree (pool_0);
      if (pool_1)
        kfree (pool_1);
      return -ENOMEM;
    }

  nlayers = max_records / 2;

  for (i = 0; i < sizeof (primes) / sizeof (primes[0]); ++i)
    if (primes[i] > nlayers)
      {
        if (i == 0)
          nlayers = primes[0];
        else
          nlayers = primes[i - 1];
        break;
      }

  if (i == sizeof (primes) / sizeof (primes[0]))
    nlayers = primes[i - 1];

  layers = kmalloc (nlayers * sizeof (struct item *), GFP_KERNEL);

  if (!layers)
    {
      kfree (item_pool_0);
      kfree (item_pool_1);
      kfree (pool_0);
      kfree (pool_1);
      return -ENOMEM;
    }

  for (i = 0; i < nlayers; ++i)
    layers[i] = NULL;

  acct_item_pool = item_pool_0;
  dump_item_pool = item_pool_1;
  free_item = &acct_item_pool[0];
  acct_pool = pool_0;
  dump_pool = pool_1;
  free_record = &acct_pool[0];
  ndump = 0;

  device_opened_p = 0;
  error = misc_register (&ipt_acct_device);

  if (error != 0)
    {
      kfree (layers);
      kfree (pool_0);
      kfree (pool_1);
      kfree (item_pool_0);
      kfree (item_pool_1);
      return error;
    }

  if (timeout > 0)
    {
      init_timer (&dump_timer);
      dump_timer.function = ipt_acct_dump_timer;
    }

  if (ipt_register_target (&ipt_acct_target) != 0)
    {
      misc_deregister (&ipt_acct_device);
      kfree (layers);
      kfree (pool_0);
      kfree (pool_1);
      kfree (item_pool_0);
      kfree (item_pool_1);
      return -EINVAL;
    }

  return 0;
}

static void __exit
ip_acct_exit (void)
{
  printk ("unloading ipt_ACCT v%s\n", IPT_ACCT_VERSION);
  ipt_unregister_target (&ipt_acct_target);
  if (timeout > 0 && timer_pending (&dump_timer))
    del_timer (&dump_timer);
  misc_deregister (&ipt_acct_device);
  kfree (layers);
  kfree (pool_0);
  kfree (pool_1);
  kfree (item_pool_0);
  kfree (item_pool_1);
}

module_init (ip_acct_init);
module_exit (ip_acct_exit);

