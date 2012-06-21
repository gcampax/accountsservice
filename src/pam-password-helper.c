/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
 *
 * Copyright (C) 2012 Giovanni Campagna <scampa.giovanni@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <glib.h>

static char *password;

static int
answer_pam_message (int                        num_msg,
                    const struct pam_message **msg,
                    struct pam_response      **resp,
                    void                      *appdata_ptr)
{
        int i;
        struct pam_response *resps;

        /* Must use malloc here, not g_malloc (and same below, must
           use strdup, not g_strdup) */
        resps = malloc((sizeof (struct pam_response)) * num_msg);

        /* We run non-interactively, so just copy the password
           into each question, and hope that configuration is
           correct. */
        /* Despite what's documented, msg is not a pointer
           to an array of pointers. It's a pointer to a pointer
           to an array of structures. Ugh!
        */
        for (i = 0; i < num_msg; i++) {
                if ((*msg)[i].msg_style == PAM_PROMPT_ECHO_OFF) {
                        resps[i].resp = strdup(password);
                } else {
                        resps[i].resp = NULL;
                }

                resps[i].resp_retcode = 0;

        }

        *resp = resps;

        return PAM_SUCCESS;
}

static char *
read_word (GIOChannel *from,
           gboolean can_fail)
{
        char *str, *decoded;
        gsize term_pos;
        GIOStatus ok;
        GError *error;

        error = NULL;
        while ((ok = g_io_channel_read_line (from,
                                             &str,
                                             NULL,
                                             &term_pos,
                                             &error)) == G_IO_STATUS_AGAIN);

        if (ok == G_IO_STATUS_EOF && can_fail)
                return NULL;

        if (ok != G_IO_STATUS_NORMAL) {
                if (error) {
                        g_printerr ("Error reading from standard input: %s\n", error->message);
                        g_error_free (error);
                } else {
                        g_printerr ("Generic error reading from standard input\n");
                }

                exit(1);
        }

        str[term_pos] = 0;

        /* URI escaping is a simple form of encoding that avoids
           ambiguity with \n while allowing arbitrary byte sequences */
        decoded = g_uri_unescape_string (str, "");

        if (decoded == NULL) {
                g_printerr ("Failed to decode password (probably contained a NUL).\n");
                exit(1);
        }

        g_free (str);
        return decoded;
}

int
main (int    argc,
      char **argv)
{
        const char *username;
        pam_handle_t *pamh;
        struct pam_conv conv = { answer_pam_message, NULL };
        int res;
        GIOChannel *stdin;

        if (argc != 2) {
                g_printerr ("Wrong number of arguments passed, 1 expected\n");
                return 1;
        }

        username = argv[1];

        stdin = g_io_channel_unix_new (STDIN_FILENO);
        password = read_word (stdin, FALSE);
        g_io_channel_unref (stdin);

        res = pam_start ("accountsservice", username,
                         &conv, &pamh);
        if (res != PAM_SUCCESS) {
                /* pam_strerror can't be used without a pam handle */
                g_printerr ("Pam handle creation failed (not enough memory?)\n");
                return 2;
        }

        res = pam_chauthtok (pamh, PAM_SILENT);
        if (res != PAM_SUCCESS) {
                g_printerr ("Password change failed: %s\n", pam_strerror (pamh, res));
        }
        pam_end (pamh, res);

        g_free (password);

        return res == PAM_SUCCESS ? 0 : 2;
}
