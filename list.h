#ifndef list_h
#define list_h

typedef struct _list {
	struct _list *next;
	void *data;
} list;

#endif

extern list *list_new(void *);
extern unsigned int list_length(list *);
extern void *list_nth(list *, int);
extern list *list_append(list *, void *);
extern list *list_prepend(list *, void *);
extern list *list_remove(list *, void *);
extern void list_free(list *);
