#include <gtk/gtk.h>
#include "callbacks.h"

double      count       = -1;       // Máximo de paquetes a capturar
char        *dev_name   = NULL,     // Nombre del dispositivo
            *flt_expr   = NULL,     // Expresión del filtro
            *fname_in   = NULL,     // Nombre del archivo de entrada
            *fname_out  = NULL;     // Nombre del archivo de salida

/** 
 * Analizador de paquetes de red
 * Uso: %s [-h] [-i ] [-c ]
 **/
int main(int argc, char **argv)
{
    int     opt,
            size    = 0;
            pnum    = 0;

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
                dev_name = malloc(strlen(optarg) * sizeof(char));
                strcpy (dev_name, optarg);
                break;
            case 'c':
                count = atoi(optarg);
                break;
            case 'f':
                fname_in = malloc(strlen(optarg) * sizeof(char));
                strcpy (fname_in, optarg);
                break;
            case 'o':
                fname_out = malloc(strlen(optarg) * sizeof(char));
                strcpy (fname_out, optarg);
                break;
        }
    }

    /* Guarda el nombre del dispositivo */
    if(dev_name == NULL)
    {
        if( (dev_name = pcap_lookupdev(errbuf)) == NULL )
        {
            fprintf(stderr, "ERROR: %s\n", errbuf);
            return EXIT_FAILURE;
        }
        dev_name = (char *)malloc(strlen(dev_name) * sizeof(char));
        strcpy(dev_name, pcap_lookupdev(errbuf));
        printf ("No se especificó ninguna interfaz de red. Usando %s defecto.\n", dev_name);
    }

    /* Guarda la expresión del filtro */
    flt_expr = (char *)malloc(0);
    strcpy(flt_expr, "");
    for(opt = optind; opt < argc; opt++)
    {
        size        += strlen(argv[opt]) + 1;
        flt_expr    = (char*)realloc(flt_expr, size * sizeof(char) );
        strcat(flt_expr, argv[opt]);
        strcat(flt_expr, " ");
    }
    flt_expr[size - 1] = '\0';

    /* Muestra la interfaz gráfica */
    gtk_init(NULL, NULL);
    gui_show_window();

    /* Libera la memoria usada por los apuntadores */
    free(dev_name);
    free(fname_in);
    free(fname_out);

    return EXIT_SUCCESS;

}
