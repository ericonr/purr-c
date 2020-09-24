#ifndef __GEMINI_H_
#define __GEMINI_H_

struct gemini_link_node {
    char path[1024];
    char name[1024];
    int position;
    struct gemini_link_node *next;
};

int get_links_from_gmi(const char*, struct gemini_link_node **);

#endif // __GEMINI_H_
