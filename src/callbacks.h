#include <gtk/gtk.h>


void
on_tb_start_clicked                    (GtkToolButton   *toolbutton,
                                        gpointer         user_data);

void
on_tb_stop_clicked                     (GtkToolButton   *toolbutton,
                                        gpointer         user_data);

void
on_new1_activate                       (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_open1_activate                      (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_save1_activate                      (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_save_as1_activate                   (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_quit1_activate                      (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_cut1_activate                       (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_copy1_activate                      (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_paste1_activate                     (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_delete1_activate                    (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_about1_activate                     (GtkMenuItem     *menuitem,
                                        gpointer         user_data);
                                        
                                        
//

void mark_set_callback(GtkTextBuffer *buffer, const GtkTextIter *new_location, GtkTextMark *mark, gpointer data);
void on_model_row_inserted(GtkTreeModel * tree_model, GtkTreePath * path, GtkTreeIter * iter, gpointer user_data);


void * show_hosts(void *l);
