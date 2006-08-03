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

#include <sys/types.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <inttypes.h>
#include <getopt.h>

#include "ipt_ACCT.h"

#define ERROR(msg,...) \
  fprintf (stderr, "stat_ipt_acct: " msg "\n", ## __VA_ARGS__)

static const struct option options[] =
{
  { "version", 0, 0, 0 },
  { "help", 0, 0, 0 },
  { 0, 0, 0, 0}
};

static void
usage ()
{
  printf ("\
Usage: stat_ipt_acct [options]\n\
Options:\n\
  --version\n\
     Print program version and exit.\n\
  --help\n\
     Print this message and exit.\n");
}

static void
version ()
{
  printf ("stat_ipt_acct %s\n", IPT_ACCT_VERSION);
}

int
main (int argc, char * const argv[])
{
  int c, option_index;
  int acct_dev;
  struct ipt_acct_stat stat;

  while (1)
    {
      c = getopt_long (argc, argv, "", options, &option_index);

      if (c == -1)
        break;

      switch (c)
        {
        case 0:
          if (option_index == 0)
            version ();
          else
            usage ();
          return 0;
        case '?':
          return 1;
        }
    }

  argc -= optind;
  argv += optind;

  if (argc != 0)
    {
      ERROR ("No arguments expected.");
      return 1;
    }

  acct_dev = open ("/dev/" IPT_ACCT_DEVICE, O_RDONLY);

  if (acct_dev < 0)
    {
      ERROR ("/dev/%s: %s", IPT_ACCT_DEVICE, strerror (errno));
      return 2;
    }

  if (ioctl (acct_dev, IPT_ACCT_GET_STAT, &stat) == -1)
    {
      ERROR ("IPT_ACCT_GET_STAT: %s", strerror (errno));
      return 3;
    }

  if (stat.startup_ts == 0)
    printf ("Accounting since: no data accounted\n");
  else
    printf ("Accounting since: %s",
            asctime (localtime ((time_t *) &stat.startup_ts)));
  printf ("Records lost: %" PRIu64 "\n", stat.records_lost);
  printf ("Packets accounted: %" PRIu64 "\n", stat.pkts_accted);
  printf ("Not accounted critical packets: %" PRIu64 "\n",
	  stat.pkts_not_accted);
  printf ("Packets dropped: %" PRIu64 "\n", stat.pkts_dropped);

  return 0;
}

