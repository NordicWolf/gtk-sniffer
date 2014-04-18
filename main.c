#include <gtk/gtk.h>
#include "callbacks.h"

double      count       = -1;       // Máximo de paquetes a capturar
char        *device     = NULL,     // Nombre del dispositivo
            *filter     = NULL;     // Expresión del filtro

/** 
 * Analizador de paquetes de red
 * Uso: %s [-h] [-i ] [-c ]
 **/
int main(int argc, char **argv)
{
    int     opt,
            size    = 0;

    /* Obtiene las opciones de la línea de comandos */
    while ((opt = getopt(argc, argv, "hi:c:o:f:")) != -1)
    {
        switch(opt)
        {
            case 'h':
                printf("Uso: %s [-h] [-i interface] [-c contador]\n", argv[0]);
                exit(EXIT_SUCCESS);
                break;
            case 'i':
                device = optarg;
                break;
            case 'c':
                count = atoi(optarg);
                break;
        }
    }

    /* Guarda el nombre del dispositivo */
    if(device == NULL)
    {
        if( (device = pcap_lookupdev(errbuf)) == NULL )
        {
            fprintf(stderr, "ERROR: %s\n", errbuf);
            return EXIT_FAILURE;
        }
        printf ("No se especificó ningún dispositivo de red. Escuchando desde '%s'\n", device);
    }

    /* Guarda la expresión del filtro */
    filter = (char *)calloc(0, sizeof(char));
    for(opt = optind; opt < argc; opt++)
    {
        size    = (opt < argc-1) ? strlen(argv[opt]) + 1 : strlen(argv[opt]);
        filter  = (char*)realloc(filter, size * sizeof(char) );
        strcat(filter, argv[opt]);

        if (opt < argc-1)
            strcat(filter, " ");
    }

    /* Muestra la interfaz gráfica */
    gtk_init(NULL, NULL);
    gui_init();

    /* Libera la memoria usada por los apuntadores */
    free(filter);
    gdk_threads_enter();
    gtk_main();
    gdk_threads_leave();
    

    return EXIT_SUCCESS;

}
