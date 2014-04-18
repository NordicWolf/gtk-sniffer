#include "callbacks.h"

/* Guarda un archivo con los paquetes capturados */
void start_capture(GtkWidget *widget, GtkComboBox *combobox, gpointer data)
{
    int         ltype;
    u_char      *packet;
    pcap_t      *pcap_ptr;
    GtkEntry    *entry;
    GType       type        = GTK_TYPE_COMBO_BOX;

    /* Verifica el tipo widget activo */
    pcap_ptr = new_session(type == GTK_OBJECT_TYPE(source));
    if( pcap_ptr == NULL)
        return;

    /* Determina el tipo de la capa de enlace de datos */
    if( (ltype = pcap_datalink(pcap_ptr)) != DLT_EN10MB)
    {
        fprintf(stderr, "Tipo de enlace %d no soportado.\nEste programa sólo soporta tarjetas Ethernet.\n", ltype);
        return;
    }

    printf ("%s\n", dev_name);

    /* Carga el programa de filtro al dispositivo de captura */
    entry = GTK_ENTRY (gtk_bin_get_child (GTK_BIN (combobox) ));
    if ( !set_filter(pcap_ptr, entry) )
        return;

    /* Comienza con la captura de paquetes */
    pcap_loop(pcap_ptr, count, parse_packet, packet);

    /* Cierra la sesión de captura */
    pcap_close(pcap_ptr);
}

// Guarda los paquetes capturados en un archivo
void save_capture(GtkWidget *widget, gpointer data)
{
    int             i;
    char            *fname      = NULL;
    GtkWidget       *fchooser;
    pcap_dumper_t   *file;

    /* Crea un nuevo diálogo de selección de archivo */
    fchooser    = gtk_file_chooser_dialog_new ( NULL, NULL,
                                                GTK_FILE_CHOOSER_ACTION_SAVE,
                                                GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
                                                GTK_STOCK_OK, GTK_RESPONSE_ACCEPT,
                                                NULL);
    /* Establece el nombre del archivo */
    gtk_file_chooser_set_do_overwrite_confirmation (GTK_FILE_CHOOSER (fchooser), TRUE);
    gtk_file_chooser_set_current_folder (GTK_FILE_CHOOSER (fchooser), ".");
    gtk_file_chooser_set_current_name (GTK_FILE_CHOOSER (fchooser), "test.pcap");

    /* Muestra el widget */
    if (gtk_dialog_run (GTK_DIALOG(fchooser)) == GTK_RESPONSE_ACCEPT)
        fname = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(fchooser));
    else
        return;

    /* Destruye el widget */
    gtk_widget_destroy (fchooser);
    gtk_list_store_clear(packet_store);

    /* Comienza con la captura de paquetes */
    printf("Guardando el archivo: %s ...\n", fname);
/*    if( (file = pcap_dump_open(pcap_ptr, fname)) == NULL )*/
/*    {*/
/*        fprintf(stderr, "Imposible abrir el archivo para escritura.");*/
/*        return;*/
/*    }*/
/*    for (i = 0; i < count; i++)*/
/*    {*/
/*        */
/*    }*/
/*    pcap_dump_close(file);*/
}

/* Crea una nueva sesión de captura */
pcap_t * new_session(gboolean mode)
{
    pcap_t      *pcap_ptr;

    /* Crea una sesión desde un dispositivo de red */
    if( mode )
    {
        bpf_u_int32     maskp;              // Máscara de red
        bpf_u_int32     netip;              // Dirección IP

        /* Verifica que el dispositivo esté conectado a la red */
        if( pcap_lookupnet(dev_name, &netip, &maskp, errbuf) == -1 )
        {
            fprintf(stderr, "ERROR %s\n", errbuf);
            return NULL;
        }

        /* Inicia una sesión en modo promiscuo */
        if ( (pcap_ptr = pcap_open_live(dev_name, BUFSIZ, 1, 1000, errbuf)) == NULL)
        {
            fprintf(stderr, "ERROR %s\n", errbuf);
            return NULL;
        }
    }
    /* Crea una nueva sesión de captura desde un archivo */
    else
    {
        char *fname;

        /* Recupera el nombre del archivo */
        fname = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(source));
        gtk_list_store_clear(packet_store);

        if(fname == NULL)
            return;

        /* Abre y procesa el archivo */
        printf("Abriendo el archivo: %s ...\n", fname);
        pcap_ptr = pcap_open_offline(fname, errbuf);
    }

    return pcap_ptr;
}

/* Procesa los paquetes capturados */
void parse_packet(u_char *arg, const struct pcap_pkthdr *hdr, const u_char *packet)
{
    int         lhdrlen         = 14,       // Tamaño de la cabecera Ethernet
                i, size;
    char        *src_mac,                   // MAC origen
                *dst_mac,                   // MAC destino
                *src, *dst,                 // IP origen, IP destino
                *protocol,                  // Protocolo
                *str_aux;

    struct ether_header *eth_hdr;           // Estructura de datos Ethernet
    struct ip           *ip_hdr;            // Estructura de datos ip
    struct tcphdr       *tcp_hdr;           // Estructura de datos tcp
    struct udphdr       *udp_hdr;           // Estructura de datos udp
    struct icmphdr      *icmp_hdr;          // Estructura de datos icmp
    const u_char        *ptr    = packet;

    str_aux = (char *)malloc(2 * sizeof(char));
    dst_mac = (char *)calloc(17, sizeof(char));
    src_mac = (char *)calloc(17, sizeof(char));

    eth_hdr = (struct ether_header*)ptr;
    ptr = eth_hdr->ether_dhost;

    /* Obtiene las direcciones MAC */
    for (i = ETHER_ADDR_LEN; i > 0; i--)
    {
        sprintf(str_aux, "%02x", *ptr++);
        strcat(dst_mac, str_aux);

        sprintf(str_aux, "%02x", *(ptr+5));
        strcat(src_mac, str_aux);
        if (i > 1)
        {
            strcat(dst_mac, ":");
            strcat(src_mac, ":");
        }
    }

    /* Determina el campo tipo de la cabecera Ethernet */
    switch( ntohs (eth_hdr->ether_type) )
    {
        case ETHERTYPE_IP:
            /* Avanza a la siguiente capa */
            ptr = packet + lhdrlen;
            ip_hdr = (struct ip*)ptr;

            /* Obtiene las direcciones IP  */
            src = (char *)calloc(strlen(inet_ntoa(ip_hdr->ip_src)), sizeof(char));
            dst = (char *)calloc(strlen(inet_ntoa(ip_hdr->ip_dst)), sizeof(char));

            strcpy(src, inet_ntoa(ip_hdr->ip_src)); // IP Origen
            strcpy(dst, inet_ntoa(ip_hdr->ip_dst)); // IP Destino

            /* Avanza a la siguiente capa */
            ptr += 4 * ip_hdr->ip_hl;

            switch( ip_hdr->ip_p )                  // Determina el protocolo
            {
                case IPPROTO_TCP:
                    tcp_hdr = (struct tcphdr *)ptr;
                    protocol = "TCP";
                    break;
                case IPPROTO_UDP:
                    udp_hdr = (struct udphdr *)ptr;
                    protocol = "UDP";
                    break;
                case IPPROTO_ICMP:
                    icmp_hdr = (struct icmphdr *)ptr;
                    protocol = "ICMP";
                    break;
                default:
                    printf ("Protocolo no soportado: %d\n", ip_hdr->ip_p);
                    return;
            }
            break;
        case ETHERTYPE_ARP:
            src = src_mac;
            dst = dst_mac;
            protocol = "ARP";
            break;
        default:
            printf ("Ethertype no soportado %d\n", ntohs (eth_hdr->ether_type));
            return;
    }
    
    /* Agrega la información a la tabla de la interfaz gráfica */
    printf ("%s -> %s\n", src, dst);
    gui_add_rows(hdr->len, src, dst, protocol, packet);
    free(str_aux);
    free(dst);
    free(src);
    free(src_mac);
    free(dst_mac);
}

/* Agrega la información a la tabla de la interfaz gráfica */
void gui_add_rows(int length, char *src, char *dst, char *proto, const u_char *packet)
{
    int             i, size;
    char            *str_out,                   // Guarda la trama del paquete en hexadecimal
                    *str_aux;
    GtkTreeIter     iter;

    size    = 0;
    str_out = (char *)calloc(size, sizeof(char));
    str_aux = (char *)malloc(0);

    /* Genera la cadena con el contenido del paquete */
    printf("Paquete %i recibido...\n", ++pnum);
    for(i = 0; i < length; i++)
    {
        /* Da formato a la salida*/
        if (i < length && i % 16 != 0)
        {
            size += 2;
            str_out = (char *)realloc(str_out, size * sizeof(char));
            strcat(str_out, "  ");
        }
        else
        {
            size += 9;
            str_out = (char *)realloc(str_out, size * sizeof(char));
            str_aux = (char *)realloc(str_aux, 9 * sizeof(char));
            sprintf(str_aux, "\n[%04x]:\t", i);
            strcat(str_out, str_aux);
            str_aux = (char *)realloc(str_aux, 2 * sizeof(char));
        }
        size = strlen(str_out) + 3;
        str_out = (char *)realloc(str_out, size * sizeof(char));
        sprintf(str_aux, "%02x", packet[i]);
        strcat(str_out, str_aux);
    }

    /* Agrega los paquete recibidos a la tabla */
    gtk_list_store_append(packet_store, &iter);
    gtk_list_store_set(packet_store, &iter,
        0, pnum,
        1, length,                      // Tamaño total en bytes
        2, src,                         // IP origen / MAC origen (ARP)
        3, dst,                         // IP destino / MAC destino (ARP)
        4, proto,                       // Protocolo
        5, str_out, -1);                // Trama del paquete

    printf ("%s\n", str_out);

    free(str_aux);
    free(str_out);
}

/* Comienza con la captura de paquetes */
gboolean set_filter(pcap_t *pcap_ptr, GtkEntry *entry)
{
    bpf_u_int32         netip;              // Dirección IP
    char                *str_filter;
    struct bpf_program  fp;                 // Estructura de datos del filtro compilado

    /* Obtiene la expresión del filtro */
    str_filter  = (char *)gtk_entry_get_text(entry);

    /* Compila y aplica los filtros */
    if(pcap_compile(pcap_ptr, &fp, str_filter, 0, netip) == -1)
    {
        fprintf(stderr, "Expresión de filtro inválida '%s': %s\n", str_filter, pcap_geterr(pcap_ptr));
        return FALSE;
    }

    if(pcap_setfilter(pcap_ptr, &fp) == -1)
    {
        fprintf(stderr, "Error al aplicar filtro '%s': %s\n", str_filter, pcap_geterr(pcap_ptr));
        return FALSE;
    }

    printf ("FILTRO: '%s'\n", str_filter);
    return TRUE;
}

/* Inicializa los elementos de la pantalla principal */
void gui_show_window()
{
    GtkWidget               *window;        // Ventana principal
    GtkComboBox             *device;        // Lista los dispositivos de red disponibles
    GtkComboBox             *filter;        // Campo de expresión de filtro
    GtkTreeView             *grid;          // Lista los paquetes cacpturados
    GtkTextBuffer           *textbuffer;
    GtkAdjustment           *adjustment;
    GtkButton               *fchooser;
    GtkBuilder              *builder        = gtk_builder_new();
    PangoFontDescription    *font_desc      = pango_font_description_from_string("Monospace 8");

    /* Recupera los objetos del archivo de la interfaz gráfica */
    gtk_builder_add_from_file (builder, "gui/sniffer_gui.xml", NULL);
    window      = GTK_WIDGET (gtk_builder_get_object (builder, "window"));
    device      = GTK_COMBO_BOX (gtk_builder_get_object (builder, "devicecombobox"));
    grid        = GTK_TREE_VIEW (gtk_builder_get_object (builder, "grid"));
    textview    = GTK_TEXT_VIEW (gtk_builder_get_object (builder, "outputtextview"));
    filter      = GTK_COMBO_BOX (gtk_builder_get_object (builder, "filtercombobox"));
    adjustment  = GTK_ADJUSTMENT (gtk_builder_get_object (builder, "adjustment"));
    textbuffer  = gtk_text_buffer_new(NULL);

    /* Define las listas de dispositivo y de filtro */
    filter_store = gtk_list_store_new(1, G_TYPE_STRING);
    packet_store = gtk_list_store_new(7, G_TYPE_INT, G_TYPE_INT, G_TYPE_STRING, G_TYPE_STRING,
                                         G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);

    /* Cambia la tipografía del texto de salida */
    gtk_widget_modify_font(GTK_WIDGET(textview), font_desc);
    pango_font_description_free(font_desc);

    gui_add_devices(device);                        // Crea la lista de los dispositivo disponibles
    source = GTK_WIDGET(device);                    // Establece el origen de captura por defecto
    gui_set_filters(filter);                        // Crea la lista de los filtros
    gui_set_grid(grid);                             // Construye la lista de los paquetes
    gtk_adjustment_set_value (adjustment, count);   // Establece el valor máximo de paquetes capturados
    gtk_text_view_set_buffer(textview, textbuffer);

    /* Conecta las señales y destruye el objeto builder */
    gtk_builder_connect_signals (builder, NULL);
    g_object_unref (G_OBJECT (builder));

    /* Muestra la ventana principal */
    gtk_widget_show (window);
    gtk_main();
}

/* Limpia los campos de salida */
void gui_clear(GtkWidget *widget, gpointer data)
{
    GtkTextBuffer *textbuffer;

    textbuffer = gtk_text_view_get_buffer(textview);
    gtk_text_buffer_set_text(textbuffer, "", -1);
    gtk_list_store_clear(packet_store);
}

/* Cambia el estado de los controles */
void gui_set_source(GtkToggleButton *togglebutton, GtkWidget *widget, gpointer data)
{
    gboolean    status;

    status = gtk_widget_get_sensitive (widget);
    gtk_widget_set_sensitive(widget, !status);

    if(!status)
        source = widget;
}

/* Muestra la lista de dispositivos disponibles */
void gui_add_devices(GtkComboBox *combobox)
{
    int             i           = 0,
                    dev_index   = -1;
    char            *device;
    GtkTreeIter     iter;
    GtkCellRenderer *cell       = gtk_cell_renderer_text_new();
    GtkListStore    *dev_list   = gtk_list_store_new(1, G_TYPE_STRING);
    pcap_if_t       *alldevsp;

    /* Establece el nombre del objeto */
    gtk_widget_set_name(GTK_WIDGET(combobox), "devices");

    /* Obtiene una lista de los dispositivos disponibles */
    if (pcap_findalldevs (&alldevsp, errbuf) < 0)
    {
        fprintf (stderr, "%s\n", errbuf);
        exit (EXIT_FAILURE);
    }
    /* Agrega el nombre del dispositivo a la lista */
    gtk_combo_box_set_model(combobox, GTK_TREE_MODEL(dev_list));
    while ( alldevsp != NULL )
    {
        /* Obtiene el nombre del dispositivo disponible */
        device = (char *)malloc(strlen(alldevsp->name) * sizeof(char));
        strcpy(device, alldevsp->name);

        /* Se agrega a la lista */
        gtk_list_store_append( dev_list, &iter );
        gtk_list_store_set( dev_list, &iter, 0, alldevsp->name, -1 );
        alldevsp = alldevsp->next;
        dev_index = (strcmp(device, dev_name) == 0) ? i : dev_index; i++;
    }
    gtk_cell_layout_pack_start(GTK_CELL_LAYOUT(combobox), cell, TRUE);
    gtk_cell_layout_set_attributes(GTK_CELL_LAYOUT(combobox), cell, "text", 0, NULL);
    gtk_combo_box_set_active (combobox, dev_index);

    /* Elimina la referencia y libera memoria */
    free(device);
    g_object_unref(G_OBJECT(dev_list));
}

/* Agrega filtros a la lista */
void gui_add_filters(GtkEntry *entry, gpointer data)
{
    GtkTreeIter     iter;
    char            *str_filter;

    /* Guarda la nueva expresión del filtro */
    str_filter = (char *)gtk_entry_get_text(entry);

    /* Agrega la expresión del filtro a la lista */
    gtk_list_store_prepend(filter_store, &iter);
    gtk_list_store_set( filter_store, &iter, 0, str_filter, -1 );
}

/* Construye la tabla de los paquetes recibidos */
void gui_set_grid(GtkTreeView *treeview)
{
    GtkTreeIter iter;
    int                 i;
    char                *titles[5]  = { "No.", "Tamaño", "Origen", "Destino", "Protocolo"};
    GtkCellRenderer     *cell       = gtk_cell_renderer_text_new();
    GtkTreeViewColumn   *column;

    for (i = 0; i < 5; i++)
    {
        column = gtk_tree_view_column_new_with_attributes(titles[i], cell, "text", i, NULL);
        gtk_tree_view_append_column(treeview, column);
    }
    gtk_tree_view_set_model(treeview, GTK_TREE_MODEL(packet_store));
}

/* Establece el filtro seleccionado */
void gui_set_filters(GtkComboBox *combobox)
{
    GtkTreeIter     iter;
    GtkEntry        *entry;
    GtkCellRenderer *cell       = gtk_cell_renderer_text_new();

    /* Agrega señales al objeto GtkEntry */
    entry = GTK_ENTRY (gtk_bin_get_child (GTK_BIN (combobox) ));
    g_signal_connect(G_OBJECT(entry), "activate", G_CALLBACK(gui_add_filters), NULL);

    gtk_combo_box_set_model(combobox, GTK_TREE_MODEL(filter_store));
    gtk_cell_layout_pack_start(GTK_CELL_LAYOUT(combobox), cell, TRUE);
    gtk_cell_layout_set_attributes(GTK_CELL_LAYOUT(combobox), cell, "text", 0, NULL);
    gtk_entry_set_text(entry, flt_expr);
    gui_add_filters(entry, NULL);
}

/* Cambia al dispositivo seleccionado */
void gui_device_change(GtkComboBox *combobox, gpointer data)
{
    GtkTreeIter     iter;
    gchar           *value  = NULL;
    GtkTreeModel    *model;

    if( gtk_combo_box_get_active_iter( combobox, &iter ) )
    {
        // Obtiene el modelo de datos del objeto
        model = gtk_combo_box_get_model( combobox );

        // Cambia el texto del campo de entrada
        gtk_tree_model_get( model, &iter, 0, &value, -1 );

        // Copia el valor del filtro
        dev_name = (char *)realloc(dev_name, strlen(value) * sizeof(char));
        strcpy(dev_name, value);
        printf ("DISP: %s\n", dev_name);
    }
}

/* Cambia al la nueva expresión del filtro */
void gui_filter_change(GtkComboBox *combobox, gpointer data)
{
    gchar           *value  = NULL;
    GtkEntry        *entry;
    GtkTreeIter     iter;
    GtkTreeModel    *model;

    if( gtk_combo_box_get_active_iter( combobox, &iter ) )
    {
        // Obtiene el modelo de datos del objeto
        model = gtk_combo_box_get_model( combobox );

        // Cambia el texto del campo de entrada
        gtk_tree_model_get( model, &iter, 0, &value, -1 );

        entry = GTK_ENTRY (gtk_bin_get_child (GTK_BIN (combobox) ));
        gtk_entry_set_text(entry, value);
    }
}

/* Establece el valor máximo de paquetes a recibir */
void gui_set_count(GtkSpinButton *spinbutton, gpointer data)
{
    count = gtk_spin_button_get_value_as_int (spinbutton);
}

/* Muestra el contenido del paquete en formato hexadecimal */
void gui_display_text(GtkTreeView *treeview, gpointer data)
{
    GtkTreeIter         iter;
    char                *string;
    GtkTreeModel        *model;
    GtkTreeSelection    *selection;
    GtkTextBuffer       *textbuffer;

    selection   = gtk_tree_view_get_selection(treeview);
    model       = gtk_tree_view_get_model(treeview);
    textbuffer  = gtk_text_view_get_buffer(textview);

    if(gtk_tree_selection_get_selected(selection, &model, &iter))
    {
        gtk_tree_model_get(model, &iter, 5, &string, -1);
        gtk_text_buffer_set_text(textbuffer, string, -1);
    }
}

/* Destruye la ventana principal */
void main_quit( GtkWidget *widget, gpointer data)
{
    /* Elimina las referencias de los elementos usados y libera la memoria */
    g_object_unref(G_OBJECT(filter_store));
    g_object_unref(G_OBJECT(packet_store));

    /* Destruye la ventana principal */
    gtk_main_quit();
}
