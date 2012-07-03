NULL =
BUILT_SOURCES =
SUBDIRS = . libaccountsservice

if HAVE_PAM_MODULE
SUBDIRS += pam-pin
endif

INCLUDES = 			\
	-DLOCALSTATEDIR=\""$(localstatedir)"\" \
	-DDATADIR=\""$(datadir)"\" \
	-DICONDIR=\"$(localstatedir)/lib/AccountsService/icons\" \
	-DUSERDIR=\"$(localstatedir)/lib/AccountsService/users\" \
	-DLIBEXECDIR=\"$(libexecdir)\" \
	-I$(srcdir)		\
	-I$(builddir)		\
	$(DBUS_GLIB_CFLAGS) 	\
	$(GIO_CFLAGS)	 	\
	$(GLIB_CFLAGS)		\
	$(POLKIT_CFLAGS)	\
	$(GCR_CFLAGS)		\
	$(WARN_CFLAGS)

noinst_LTLIBRARIES = libaccounts-generated.la

libaccounts_generated_la_SOURCES = \
	accounts-generated.c		\
	accounts-generated.h		\
	accounts-user-generated.c	\
	accounts-user-generated.h	\
	$(NULL)
BUILT_SOURCES += $(libaccounts_generated_la_SOURCES)

accounts-generated.c accounts-generated.h: $(top_srcdir)/data/org.freedesktop.Accounts.xml Makefile
	gdbus-codegen --generate-c-code accounts-generated --c-namespace Accounts --interface-prefix=org.freedesktop. $(top_srcdir)/data/org.freedesktop.Accounts.xml

accounts-user-generated.c accounts-user-generated.h: $(top_srcdir)/data/org.freedesktop.Accounts.User.xml Makefile
	gdbus-codegen --generate-c-code accounts-user-generated --c-namespace Accounts --interface-prefix=org.freedesktop.Accounts. $(top_srcdir)/data/org.freedesktop.Accounts.User.xml

libexec_PROGRAMS = accounts-daemon accounts-daemon-pam-password-helper

accounts_daemon_SOURCES = 	\
	$(enums_h_sources)	\
	types.h			\
	daemon.h		\
	daemon.c		\
	user.h			\
	user.c			\
	util.h			\
	util.c			\
	main.c

accounts_daemon_LDADD = 	\
	libaccounts-generated.la	\
	$(GCR_LIBS)			\
	$(POLKIT_LIBS)

accounts_daemon_pam_password_helper_SOURCES = \
	pam-password-helper.c
accounts_daemon_pam_password_helper_LDADD = \
	$(GLIB_LIBS) 		\
	-lpam

CLEANFILES = $(BUILT_SOURCES)

install-data-hook:
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/AccountsService/users"
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/lib/AccountsService/icons"
