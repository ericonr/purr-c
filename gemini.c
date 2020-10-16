#define _XOPEN_SOURCE 500 /* strdup */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

#include "gemini.h"

// reasonable UI limit
#define MAX_NUM_LINKS 100

static bool is_terminator(int c)
{
    return c == '\n' || c == '\r' || c == 0;
}

int get_links_from_gmi(const char *text, struct gemini_link_node **nodes)
{
    int rv = 0;
    struct gemini_link_node *tail = *nodes;

    if (tail) {
        while (tail->next) {
            tail = tail->next;
            rv++;
        }
    }

    while (rv < MAX_NUM_LINKS) {
        if (text[0] == '=' && text[1] == '>') {
            // found link
            rv++;

            if (tail == NULL) {
                tail = calloc(1, sizeof *tail);
                if (tail == NULL) {
                    perror("calloc()");
                    return rv;
                }
                *nodes = tail;
            } else {
                tail->next = calloc(1, sizeof *tail);
                if (tail->next == NULL) {
                    perror("calloc()");
                    return rv;
                }
                tail = tail->next;
            }

            // eat =>
            text += 2;

            while (isblank(*text) && !is_terminator(*text)) {
                // eat whitespace
                text++;
            }
            int i;
            for (i = 0;
                 !isblank(text[i]) && !is_terminator(text[i]) && i < GEMINI_LINK_SIZE;
                 i++) {
                tail->path[i] = text[i];
            }
            text += i;

            while (isblank(*text) && !is_terminator(*text)) {
                // eat whitespace
                text++;
            }
            for (i = 0;
                 !is_terminator(text[i]) && i < GEMINI_NAME_SIZE;
                 i++) {
                tail->name[i] = text[i];
            }
            text += i;
        } else {
            // didn't find link match, goto next line / end function
            const char *new_line = strchr(text, '\n');
            if (new_line) {
                text = new_line + 1;
                continue;
            } else {
                break;
            }
        }
    }

    return rv;
}

/*
 * Expects linked lists with at least 1 member
 */
void print_gemini_nodes(struct gemini_link_node *head, FILE *stream)
{
    int i = 0;
    do {
        fprintf(stream, "#%02d path: %s - name: %s\n", i++, head->path, head->name);
    } while ((head = head->next));
}

/*
 * Expects linked lists with at least n members
 */
struct gemini_link_node *get_gemini_node_by_n(struct gemini_link_node *head, int n)
{
    struct gemini_link_node *rv = head;
    while (n--) {
        rv = rv->next;
    }
    return rv;
}

static char *redirect_link = NULL;

void store_gemini_redirect_link(int s, const char *l)
{
    // only store URL if it is a redirect.
    // this comes from a header, so will always end with \r\n
    // cut \r
    if (s == '3') {
        redirect_link = strdup(l);
        // if allocation fails, redirection simply won't be detected
        if (redirect_link) {
            *(strchr(redirect_link, '\r')) = 0;
        }
    }
}

char *get_gemini_redirect_link(void)
{
    return redirect_link;
}

void free_gemini_redirect_link(void)
{
    free(redirect_link);
}

/*
 * This function joins two paths and resolves the "." ".." and "//" refs in them.
 *
 * It returns a pointer to a newly allocated string or NULL if allocation failed.
 */
char *walk_gemini_path(const char *path, const char *append)
{
    size_t path_len = strlen(path), app_len = strlen(append);
    char *rv = calloc(1, path_len + app_len + 1);
    if (rv == NULL) {
        return NULL;
    }
    memcpy(rv, path, path_len);

    // Implementation partially by Quentin Rameau,
    // taken from https://www.openwall.com/lists/musl/2016/11/03/5/1
    {
        char *absolute = rv;
        char *a = rv;
        const char *r = append;

        /* slash terminate absolute if needed */
        a = absolute + path_len - 1;
        if (*a != '/') *(++a) = '/';

        /* resolve . and .. */
        for (; *r; ++r) {
            if (*r == '.') {
                if (r[1] == '/' || !r[1]) continue;
                if (r[1] == '.' && (r[2] == '/' || !r[2])) {
                    while (a > absolute && *--a != '/');
                    continue;
                }
            } else if (*r == '/' && *a == '/') continue;
            *++a = *r;
        }
        /* terminate absolute */
        *++a = 0;
    }

    return rv;
}
