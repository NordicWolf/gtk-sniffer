#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <gtk/gtk.h>

// ARGUMENTOS
extern double       count;                          // Límite de paquetes
extern char         *device,                        // Nombre del dispositivo
                    *filter;                        // Expresión del filtro

// LIBPCAP
int                 pnum;                           // Número del paquete capturado
char                errbuf[PCAP_ERRBUF_SIZE];       // Búfer de mensaje de error

// GTK
GtkWidget           *source;                        // Widget de origen de datos
GtkTextView         *pkt_textv;                     // Muestra el contenido del paquete capturado
GtkListStore        *filter_store;                  // Almacena los filtros
GtkListStore        *packet_store;                  // Almacena los datos de los paquetes

// Thread
void foo_loop(gpointer);

// Guarda un archivo con los paquetes capturados
void gui_start(GtkWidget *, GtkComboBox *, gpointer);

// Guarda los paquetes capturados en un archivo
void save_capture(GtkWidget *, gpointer data);

// Procesa los paquetes capturados
void parse_packet(u_char *, const struct pcap_pkthdr *, const u_char *);

// Agrega la información a la tabla de la interfaz gráfica
void gui_add_rows(int, char *, char *, char *, const u_char *);

// Crea una nueva sesión de captura
pcap_t * new_session(gboolean);

// Compila y aplica los filtros
gboolean set_filter(pcap_t *, GtkEntry *);

// Inicializa los elementos de la pantalla principal
void gui_init();

// Limpia los campos de salida
void gui_clear(GtkWidget *, gpointer);

// Cambia el estado de los controles
void gui_set_source(GtkToggleButton *, GtkWidget *, gpointer);

// Muestra la lista de dispositivos disponibles
void gui_add_devices(GtkComboBox *);

// Agrega filtros a la lista
void gui_add_filters(GtkEntry *, gpointer);

// Construye la tabla de los paquetes recibidos
void gui_set_grid(GtkTreeView *);

// Cambia el valor del campo de expresión de filtro
void gui_set_filters(GtkComboBox *);

// Cambia al dispositivo seleccionado
void gui_device_change(GtkComboBox *, gpointer);

// Cambia al la nueva expresión del filtro
void gui_filter_change(GtkComboBox *, gpointer);

// Establece el valor máximo de paquetes a recibir
void gui_set_count(GtkSpinButton *, gpointer);

// Muestra el contenido del paquete en formato hexadecimal
void gui_display_text(GtkTreeView *, gpointer);

// Destruye la ventana principal
void main_quit( GtkWidget *, gpointer);
