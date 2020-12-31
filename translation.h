#ifndef __TRANSLATION_H_
#define __TRANSLATION_H_

#include <locale.h>

#ifdef USE_LIBINTL
# include <libintl.h>
# define _(a) gettext(a)
#else /* USE_LIBINTL */
# define _(a) a
#endif /* USE_LIBINTL */

// use this only in main()
static inline void loc_init(void)
{
    // so libc understands utf8
    setlocale(LC_CTYPE, "");
    // so messages are localized
    setlocale(LC_MESSAGES, "");
#ifdef USE_LIBINTL
    // to load my localization
    bindtextdomain(GETTEXT_PACKAGE, GETTEXT_DIR);
    textdomain(GETTEXT_PACKAGE);
#endif
}

#endif // __TRANSLATION_H_
