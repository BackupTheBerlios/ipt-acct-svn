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
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <inttypes.h>
#include <getopt.h>

#include "ipt_ACCT.h"

#define ERROR(msg,...) \
  fprintf (stderr, "dump_ipt_acct: " msg "\n", ## __VA_ARGS__)

static const struct option options[] =
{
  { "version", 0, 0, 0 },
  { "help", 0, 0, 0 },
  { "proto-names", 0, 0, 's' },
  { "proto-numbers", 0, 0, 'd' },
  { 0, 0, 0, 0}
};

static void
usage ()
{
  printf ("\
Usage: dump_ipt_acct [options]\n\
Options:\n\
  -s, --proto-names\n\
     Try to print names of protocols instead of numbers if possible.\n\
  -d, --proto-numbers\n\
     Print protocols in numeric form (default).\n\
  --version\n\
     Print program version and exit.\n\
  --help\n\
     Print this message and exit.\n");
}

static void
version ()
{
  printf ("dump_ipt_acct %s\n", IPT_ACCT_VERSION);
}

int
main (int argc, char * const argv[])
{
  int c, option_index;
  int acct_dev;
  int proto_names_p = 0;
  struct ipt_acct_record *records;
  unsigned int max_records, ndump, i;

  struct pollfd pfd;
  char src[] = "XXX.XXX.XXX.XXX";
  char dst[] = "XXX.XXX.XXX.XXX";

  while (1)
    {
      c = getopt_long (argc, argv, "sd", options, &option_index);

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
        case 's':
          proto_names_p = 1;
          break;
        case 'd':
          proto_names_p = 0;
          break;
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

  max_records = ioctl (acct_dev, IPT_ACCT_GET_MAX);

  if (max_records == (unsigned int) -1)
    {
      ERROR ("IPT_ACCT_GET_MAX: %s", strerror (errno));
      return 3;
    }

  if (max_records == 0)
    {
      ERROR ("IPT_ACCT_GET_MAX has returned 0");
      return 3;
    }

  records = malloc (max_records * sizeof (struct ipt_acct_record));

  if (!records)
    {
      ERROR ("Cannot allocate %u records: %s", max_records, strerror (errno));
      return 4;
    }

  bzero (records, max_records * sizeof (struct ipt_acct_record));

  if (ioctl (acct_dev, IPT_ACCT_DUMP) < 0)
    {
      ERROR ("IPT_ACCT_DUMP: %s", strerror (errno));
      return 3;
    }

  bzero (&pfd, sizeof (pfd));
  pfd.fd = acct_dev;
  pfd.events = POLLIN;

  if (poll (&pfd, 1, 0) < 0)
    {
      ERROR ("Polling of /dev/%s failed: %s", IPT_ACCT_DEVICE,
             strerror (errno));
      return 3;
    }

  ndump = ioctl (acct_dev, IPT_ACCT_GET_DUMP, records);

  if (ndump == (unsigned int) -1)
    {
      ERROR ("IPT_ACCT_GET_DUMP: %s", strerror (errno));
      return 3;
    }

  if (proto_names_p)
    for (i = 0; i < ndump; ++i)
      {
        struct protoent *p = getprotobynumber (records[i].proto);
        inet_ntop (AF_INET, &records[i].src, src, sizeof (src));
        inet_ntop (AF_INET, &records[i].dst, dst, sizeof (dst));
        if (p)
          printf ("%u %s %u %s %u %u %u %s %" PRIu64 " %" PRIu64 "\n",
                  records[i].magic,
                  src, records[i].sport, dst, records[i].dport,
                  records[i].npkts, records[i].size, p->p_name,
                  records[i].first, records[i].last);
        else
          printf ("%u %s %u %s %u %u %u %u %" PRIu64 " %" PRIu64 "\n",
                  records[i].magic,
                  src, records[i].sport, dst, records[i].dport,
                  records[i].npkts, records[i].size, records[i].proto,
                  records[i].first, records[i].last);
      }
  else
    for (i = 0; i < ndump; ++i)
      {
        inet_ntop (AF_INET, &records[i].src, src, sizeof (src));
        inet_ntop (AF_INET, &records[i].dst, dst, sizeof (dst));
        printf ("%u %s %u %s %u %u %u %u %" PRIu64 " %" PRIu64 "\n",
                records[i].magic,
                src, records[i].sport, dst, records[i].dport,
                records[i].npkts, records[i].size, records[i].proto,
                records[i].first, records[i].last);
      }

  return 0;
}

