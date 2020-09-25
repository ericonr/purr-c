#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "gemini.h"

#define MAX_NUM_LINKS 1024
#define MAX_LINK_LEN 1024

char *redirect_link = NULL;

static struct gemini_link_node *gimme_node(void)
{
    struct gemini_link_node *node = calloc(1, sizeof *node);
    return node;
}

static bool is_whitespace(char c)
{
    return c == ' ' || c == '\t';
}

static bool is_terminator(char c)
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

            while (is_whitespace(*text) && !is_terminator(*text)) {
                // eat whitespace
                text++;
            }
            int i;
            for (i = 0;
                 !is_whitespace(text[i]) && !is_terminator(text[i]) && i < MAX_LINK_LEN;
                 i++) {
                tail->path[i] = text[i];
            }
            text += i;

            while (is_whitespace(*text) && !is_terminator(*text)) {
                // eat whitespace
                text++;
            }
            for (i = 0;
                 !is_terminator(text[i]) && i < MAX_LINK_LEN;
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

void store_gemini_redirect_link(int s, char *l)
{
    // only store URL if it is a redirect
    if (s == '3') redirect_link = l;
}
