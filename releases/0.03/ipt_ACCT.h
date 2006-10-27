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

#ifndef IPT_ACCT_H
#define IPT_ACCT_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define IPT_ACCT_VERSION "0.03"

#define IPT_ACCT_MAJIC 241
#define IPT_ACCT_DEVICE "ipt_acct"

/* Obtain maximum dump size in records. */
#define IPT_ACCT_GET_MAX _IO (IPT_ACCT_MAJIC, 0)
/* Force dump if had not one in case of zero timeout. */
#define IPT_ACCT_DUMP _IO (IPT_ACCT_MAJIC, 1)
/* Get accounting records from dump. */
#define IPT_ACCT_GET_DUMP _IOW (IPT_ACCT_MAJIC, 2, void *)
/* Obtain statistics. */
#define IPT_ACCT_GET_STAT _IOW (IPT_ACCT_MAJIC, 3, void *)

struct ipt_acct_stat
{
  __u64 startup_ts;
  __u64 records_lost;
  __u64 pkts_accted;
  __u64 pkts_not_accted;
  __u64 pkts_dropped;
};

struct ipt_acct_record
{
  __u32 src;
  __u32 dst;
  __u16 sport;
  __u16 dport;
  __u32 npkts;
  __u32 size;
  __u64 first;
  __u64 last;
  __u8 proto;
  __u16 magic;
};

#endif /* IPT_ACCT_H */

