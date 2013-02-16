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
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <security/pam_modules.h>
#include <security/pam_misc.h>
#include <security/pam_ext.h>
#include <glib.h>
#include <gcrypt.h>

/* We use AES256 in Cipher Block Chaining mode,
   using a key derived from the PIN, salted with the machine id
   and passed through PBKDF2.
*/
#define KEY_LENGTH 256/8
#define N_ITERATIONS 100000

static void
init_libgcrypt (void)
{
        /* Despite the name, this is a library init function... */
        gcry_check_version (GCRYPT_VERSION);
}

static char *
make_key (const char *pin)
{
        char *key;
        char *machine_id;
        size_t machine_id_len;

        if (!g_file_get_contents ("/etc/machine-id", &machine_id,
                                  &machine_id_len, NULL))
                return NULL;

        key = g_malloc (KEY_LENGTH);

        if (gcry_kdf_derive (pin, strlen (pin),
                             GCRY_KDF_PBKDF2, GCRY_MD_SHA1,
                             machine_id, machine_id_len,
                             N_ITERATIONS, KEY_LENGTH, key)) {
                g_free (key);
                key = NULL;
        }

        g_free (machine_id);
        return key;
}

static size_t
get_block_size (void)
{
        size_t sz;

        gcry_cipher_algo_info (GCRY_CIPHER_AES256, GCRYCTL_GET_BLKLEN, NULL, &sz);
        return sz;
}

static char *
make_iv (void)
{
        char *iv;
        size_t sz;

        sz = get_block_size ();
        iv = g_malloc (sz);
        memset(iv, 0, sz);

        return iv;
}

static char *
make_padded_password (const char *password,
                      size_t     *out_size)
{
        size_t total;
        size_t blksz;
        size_t current;
        char *padded;

        blksz = get_block_size ();
        current = strlen (password);

        if (current % blksz) {
                total = (current / blksz + 1) * blksz;
                padded = g_malloc (total + 1);
                stpncpy (padded, password, total + 1);

                *out_size = total;
                return padded;
        } else {
                *out_size = current;
                return g_strdup (password);
        }
}

static char *
decode_password (const char *ciphertext,
                 size_t      ciphertext_len,
                 const char *pin)
{
        gcry_cipher_hd_t hd = NULL;
        char *key = NULL;
        char *iv = NULL;
        char *password = NULL;

        key = make_key (pin);
        if (key == NULL)
                return NULL;

        if (gcry_cipher_open (&hd, GCRY_CIPHER_AES256,
                              GCRY_CIPHER_MODE_CBC, 0))
                goto out;

        iv = make_iv ();
        gcry_cipher_setiv (hd, iv, get_block_size ());
        gcry_cipher_setkey (hd, key, KEY_LENGTH);

        password = g_malloc (ciphertext_len + 1);
        if (password == NULL)
                goto out;

        if (gcry_cipher_decrypt (hd, password, ciphertext_len,
                                 ciphertext, ciphertext_len)) {
                g_free (password);
                password = NULL;
        } else {
                password[ciphertext_len] = 0;
        }

 out:
        g_free (key);
        g_free (iv);
        gcry_cipher_close (hd);
        return password;
}

static char *
encode_password (const char *password,
                 const char *pin,
                 size_t     *ciphertext_len)
{
        gcry_cipher_hd_t hd = NULL;
        char *key = NULL;
        char *iv = NULL;
        char *ciphertext = NULL;
        char *padded = NULL;
        size_t password_len;

        key = make_key (pin);
        if (key == NULL)
                return NULL;

        if (gcry_cipher_open (&hd, GCRY_CIPHER_AES256,
                              GCRY_CIPHER_MODE_CBC, 0))
                goto out;

        iv = make_iv ();
        gcry_cipher_setiv (hd, iv, get_block_size ());
        gcry_cipher_setkey (hd, key, KEY_LENGTH);

        padded = make_padded_password (password, &password_len);
        *ciphertext_len = password_len;
        ciphertext = g_malloc(*ciphertext_len + 1);

        if (gcry_cipher_encrypt (hd, ciphertext, password_len,
                                 padded, password_len)) {
                g_free (ciphertext);
                ciphertext = NULL;
        }

 out:
        g_free (key);
        g_free (iv);
        g_free (padded);
        gcry_cipher_close (hd);
        return ciphertext;
}

int
pam_sm_authenticate (pam_handle_t  *handle,
		     int            flags,
		     int            argc,
		     const char   **argv)
{
        const char *username;
        char *filename = NULL;
        char *ciphertext = NULL;
        size_t ciphertext_len;
        const char *pin;
        char *password;
        int result;
        GError *error;

        init_libgcrypt ();

        /* We require CAP_DAC_OVERRIDE to access the encrypted password
           (like /etc/shadow) */
        if (g_mkdir_with_parents (PASSWDDIR, 0) < 0)
                return PAM_AUTHINFO_UNAVAIL;

        /* Username must not be localized, there is an exact match
           in gnome-shell */
        result = pam_get_user (handle, &username, "Username: ");
        if (result != PAM_SUCCESS)
                return result;

        filename = g_build_filename (PASSWDDIR, username, NULL);

        error = NULL;
        if (!g_file_get_contents (filename, &ciphertext, &ciphertext_len, &error)) {
                if (g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
                        result = PAM_AUTHINFO_UNAVAIL;
                else
                        result = PAM_AUTHTOK_ERR;

                g_error_free (error);
                goto out;
        }

        /* Do not translate this string, it's a marker used by gnome-shell
           to show the PIN keypad */
        result = pam_get_authtok (handle, PAM_AUTHTOK, &pin, "PIN");
        if (result != PAM_SUCCESS)
                goto out;

        password = decode_password (ciphertext, ciphertext_len, pin);
        if (password)
                result = pam_set_item (handle, PAM_AUTHTOK, password);
        else
                result = PAM_AUTH_ERR;

 out:
        g_free (ciphertext);
        g_free (filename);

        return result;
}

static int
do_preliminary_check(pam_handle_t *handle)
{
        char *filename;
        const char *username;
        int result, fd;

        if (g_mkdir_with_parents (PASSWDDIR, 0) < 0)
                return PAM_AUTHINFO_UNAVAIL;

        result = pam_get_user (handle, &username, "Username: ");
        if (result != PAM_SUCCESS)
                return result;

        /* Check that we can access and write the database */
        filename = g_build_filename (PASSWDDIR, username, NULL);

        fd = open(filename, O_RDWR);
        if (fd < 0 && errno != ENOENT)
                result = PAM_AUTHTOK_ERR;
        else
                result = PAM_SUCCESS;

        g_free(filename);
        if (fd >= 0)
                close(fd);
        return result;
}

static int
request_and_encrypt_pin(pam_handle_t  *handle,
                        const char    *username,
                        char         **ciphertext,
                        size_t        *ciphertext_len)
{
        const char *password;
        char *pin;
        int result;

        *ciphertext = NULL;

        result = pam_get_authtok (handle, PAM_AUTHTOK, &password, "Password: ");
        if (result != PAM_SUCCESS)
                return result;

        result = pam_prompt (handle, PAM_PROMPT_ECHO_OFF, &pin, "PIN");
        if (result != PAM_SUCCESS)
                return result;

        if (pin == NULL || strlen (pin) == 0) {
                result = PAM_SUCCESS;
        } else {
                *ciphertext = encode_password (password, pin, ciphertext_len);
                if (!*ciphertext)
                        result = PAM_AUTHTOK_ERR;
                else
                        result = PAM_SUCCESS;
        }

        /* Don't use g_free here, the string comes from PAM */
        free(pin);
        return result;
}

static int
do_change_authtok(pam_handle_t  *handle)
{
        const char *username;
        char *filename;
        char *ciphertext;
        size_t ciphertext_len;
        int result, ok;
        uid_t ruid, euid;

        result = pam_get_user (handle, &username, "Username: ");
        if (result != PAM_SUCCESS)
                return result;

        filename = g_build_filename (PASSWDDIR, username, NULL);

        ciphertext = NULL;
        result = PAM_AUTHTOK_ERR;

        /* libgcrypt has the interesting habit to drop
           all privileges when allocating secure memory,
           and it does so with setuid() instead of seteuid()
           Workaround that by dropping the priviliges ourselves
           and then regaining them before leaving control to
           the rest of the PAM stack.

           This is not thread-safe and very, very bad in general!
        */
        ruid = getuid();
        euid = geteuid();

        if (euid != ruid) {
                ok = seteuid(ruid);
                if (ok < 0)
                        goto out;
        }

        result = request_and_encrypt_pin (handle, username,
                                          &ciphertext, &ciphertext_len);

        ok = seteuid (euid);

        if (result != PAM_SUCCESS)
                goto out;
        if (ok < 0) {
                result = PAM_AUTHTOK_ERR;
                goto out;
        }

        if (ciphertext) {
                if (!g_file_set_contents (filename, ciphertext, ciphertext_len, NULL))
                        goto out;

                /* Set file mode to 0, and require DAC_OVERRIDE to access it */
                if (chmod (filename, 0) < 0)
                        goto out;
        } else {
                if (unlink (filename) < 0 && errno != ENOENT)
                        goto out;
        }

        result = PAM_SUCCESS;

 out:
        g_free(filename);
        g_free(ciphertext);
        return result;
}

int
pam_sm_setcred(pam_handle_t  *handle,
               int            flags,
               int            argc,
               const char   **argv)
{
        return PAM_SUCCESS;
}

int
pam_sm_chauthtok (pam_handle_t  *handle,
                  int            flags,
                  int            argc,
                  const char   **argv)
{
        init_libgcrypt ();

        if (flags & PAM_PRELIM_CHECK)
                return do_preliminary_check(handle);
        else if (flags & PAM_UPDATE_AUTHTOK)
                return do_change_authtok(handle);

        return PAM_SUCCESS;
}
