#ifndef __GEMINI_H_
#define __GEMINI_H_

#include <stdio.h>

struct gemini_link_node {
    char path[1024];
    char name[1024];
    int position;
    struct gemini_link_node *next;
};

extern char *redirect_link;

/* gemini.c */
int get_links_from_gmi(const char *, struct gemini_link_node **);
void print_gemini_nodes(struct gemini_link_node *, FILE *);
struct gemini_link_node *get_gemini_node_by_n(struct gemini_link_node *, int);
void store_gemini_redirect_link(int, char *);

#endif // __GEMINI_H_
