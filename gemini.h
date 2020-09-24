#ifndef __GEMINI_H_
#define __GEMINI_H_

struct gemini_link_node {
    char path[1024];
    char name[1024];
    int position;
    struct gemini_link_node *next;
};

/* gemini.c */
int get_links_from_gmi(const char*, struct gemini_link_node **);
struct gemini_link_node *get_gemini_node_by_n(struct gemini_link_node *, int);

#endif // __GEMINI_H_
