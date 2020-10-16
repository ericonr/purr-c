#ifndef __GEMINI_H_
#define __GEMINI_H_

#include <stdio.h>

#define GEMINI_LINK_SIZE 1024
#define GEMINI_NAME_SIZE 1024

struct gemini_link_node {
    struct gemini_link_node *next;
    char path[GEMINI_LINK_SIZE];
    char name[GEMINI_NAME_SIZE];
};

/* gemini.c */
int get_links_from_gmi(const char *, struct gemini_link_node **);
void print_gemini_nodes(struct gemini_link_node *, FILE *);
struct gemini_link_node *get_gemini_node_by_n(struct gemini_link_node *, int);
void store_gemini_redirect_link(int, const char *);
char *get_gemini_redirect_link(void);
void free_gemini_redirect_link(void);
char *walk_gemini_path(const char *, const char *);

#endif // __GEMINI_H_
