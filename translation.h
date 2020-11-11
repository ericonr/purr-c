#ifndef __TRANSLATION_H_
#define __TRANSLATION_H_

#include <locale.h>
#include <libintl.h>
#define _(a) gettext(a)

#ifndef GETTEXT_PACKAGE
#define GETTEXT_PACKAGE NULL
#endif /* GETTEXT_DOMAIN */

#ifndef GETTEXT_DIR
#define GETTEXT_DIR NULL
#endif /* GETTEXT_DIR */

#endif // __TRANSLATION_H_
