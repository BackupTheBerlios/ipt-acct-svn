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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>

#include <iptables.h>

#include "ipt_ACCT.h"

struct ipt_acct_info
{
  struct ipt_entry_target t;
  __u16 magic; 
  __u16 header;
  __u8 header_p;
  __u8 critical_p;
  unsigned int retcode;
};

static struct option extra_opts[] =
{
  { "magic", 1, 0, '1' },
  { "header", 2, 0, '2' },
  { "critical", 0, 0, '3' },
  { "continue", 0, 0, '4' },
  { "accept", 0, 0, '5' },
  { "drop", 0, 0, '6' },
  { 0, 0, 0, 0 }
};

static void
help ()
{
  printf ("\
ACCT v%s options:\n\
  --magic <N>  Mark accounted records with magic number <N> (0 by default).\n\
  --header     Count link layer header.\n\
  --critical   Do not drop packet even if it cannot be accounted.\n\
  --continue   Let packet go further through rules after accounting (default).\n\
  --accept     Accept packet after accounting.\n\
  --drop       Drop packet after accounting.\n\n", IPT_ACCT_VERSION);
}

static void
init (struct ipt_entry_target *target, unsigned int *nfcache)
{
  struct ipt_acct_info *info = (struct ipt_acct_info *) target->data;
  info->magic = 0;
  info->header = 0;
  info->header_p = 1;
  info->critical_p = 0;
  info->retcode = IPT_CONTINUE;
}

static int
parse (int c, char **argv, int invert, unsigned int *flags,
       const struct ipt_entry *entry, struct ipt_entry_target **target)
{
  struct ipt_acct_info *info = (struct ipt_acct_info *) (*target)->data;
  unsigned long int_value;
  char *end;

  switch (c)
    {
    case '1':
      errno = 0;
      int_value = strtoul (optarg, &end, 10);
      if (errno != 0 || *end || *optarg == '-' || int_value > 65535)
        exit_error (PARAMETER_PROBLEM,
          "Integer between 0 and 65535 expected as magic value");
      info->magic = int_value;
      break;
    case '2':
      if (optarg) {
        errno = 0;
        int_value = strtoul (optarg, &end, 10);
        if (errno != 0 || *end || *optarg == '-' || int_value > 65535)
          exit_error (PARAMETER_PROBLEM,
            "Integer between 0 and 65535 expected as header size");
        info->header_p = 1;
        info->header = int_value;
      } else
        info->header_p = 0;
      break;
    case '3':
      info->critical_p = 1;
      break;
    case '4':
      info->retcode = IPT_CONTINUE;
      break;
    case '5':
      info->retcode = NF_ACCEPT;
      break;
    case '6':
      info->retcode = NF_DROP;
      break;
    default:
      return 0;
    }

  return 1;
}

static void
final_check (unsigned int flags)
{
}

static void
print (const struct ipt_ip *ip, const struct ipt_entry_target *target,
       int numeric)
{
  struct ipt_acct_info *info = (struct ipt_acct_info *) target->data;
  printf ("ACCT with magic %u and ", info->magic);
  if (info->retcode == NF_ACCEPT)
    printf ("accept");
  else if (info->retcode == NF_DROP)
    printf ("drop");
  else
    printf ("continue");
}

static void
save (const struct ipt_ip *ip, const struct ipt_entry_target *target)
{
  struct ipt_acct_info *info = (struct ipt_acct_info *) target->data;
  if (info->magic != 0)
    printf ("--magic %u ", info->magic);
  if (info->header_p)
    {
      if (info->header != 0)
        printf ("--header=%u ", info->header);
    }
  else
    printf ("--header ");
  if (info->critical_p)
    printf ("--critical ");
  if (info->retcode == NF_ACCEPT)
    printf ("--accept ");
  else if (info->retcode == NF_DROP)
    printf ("--drop ");
}

static struct iptables_target acct_target =
{
  .name = "ACCT",
  .version = IPTABLES_VERSION,
  .size = IPT_ALIGN (sizeof (struct ipt_acct_info)),
  .userspacesize = IPT_ALIGN (sizeof (struct ipt_acct_info)),
  .help = &help,
  .init = &init,
  .parse = &parse,
  .final_check = &final_check,
  .print = &print,
  .save = &save,
  .extra_opts = extra_opts
};

void
_init ()
{
  register_target (&acct_target);
}

