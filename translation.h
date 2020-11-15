#ifndef __TRANSLATION_H_
#define __TRANSLATION_H_

#ifdef USE_LIBINTL

#include <locale.h>
#include <libintl.h>
#define _(a) gettext(a)

#ifndef GETTEXT_PACKAGE
#define GETTEXT_PACKAGE NULL
#endif /* GETTEXT_DOMAIN */

#ifndef GETTEXT_DIR
#define GETTEXT_DIR NULL
#endif /* GETTEXT_DIR */

#else /* USE_LIBINTL */

#define _(a) a
#define setlocale(a,b)
#define bindtextdomain(a,b)
#define textdomain(a)

#endif /* USE_LIBINTL */

#endif // __TRANSLATION_H_
