#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <strings.h>
#include <string.h>

#include <netinet/in.h>
#include <netdb.h>

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <bluetooth/rfcomm.h>

int puerto = 7200;

int str2uuid( const char *uuid_str, uuid_t *uuid ) 
{
    uint32_t uuid_int[4];
    char *endptr;

    if( strlen( uuid_str ) == 36 ) {
        // Parse uuid128 standard format: 12345678-9012-3456-7890-123456789012
        char buf[9] = { 0 };

        if( uuid_str[8] != '-' && uuid_str[13] != '-' &&
            uuid_str[18] != '-'  && uuid_str[23] != '-' ) {
            return 0;
        }
        // first 8-bytes
        strncpy(buf, uuid_str, 8);
        uuid_int[0] = htonl( strtoul( buf, &endptr, 16 ) );
        if( endptr != buf + 8 ) return 0;

        // second 8-bytes
        strncpy(buf, uuid_str+9, 4);
        strncpy(buf+4, uuid_str+14, 4);
        uuid_int[1] = htonl( strtoul( buf, &endptr, 16 ) );
        if( endptr != buf + 8 ) return 0;

        // third 8-bytes
        strncpy(buf, uuid_str+19, 4);
        strncpy(buf+4, uuid_str+24, 4);
        uuid_int[2] = htonl( strtoul( buf, &endptr, 16 ) );
        if( endptr != buf + 8 ) return 0;

        // fourth 8-bytes
        strncpy(buf, uuid_str+28, 8);
        uuid_int[3] = htonl( strtoul( buf, &endptr, 16 ) );
        if( endptr != buf + 8 ) return 0;

        if( uuid != NULL ) sdp_uuid128_create( uuid, uuid_int );
    } else if ( strlen( uuid_str ) == 8 ) {
        // 32-bit reserved UUID
        uint32_t i = strtoul( uuid_str, &endptr, 16 );
        if( endptr != uuid_str + 8 ) return 0;
        if( uuid != NULL ) sdp_uuid32_create( uuid, i );
    } else if( strlen( uuid_str ) == 4 ) {
        // 16-bit reserved UUID
        int i = strtol( uuid_str, &endptr, 16 );
        if( endptr != uuid_str + 4 ) return 0;
        if( uuid != NULL ) sdp_uuid16_create( uuid, i );
    } else {
        return 0;
    }

    return 1;
}

int main(void) {
    char mensaje[27] = "000000000000000000000000000";
    char men[27] = "000000000000000000000000000";
    char buffer[27] = "000000000000000000000000000";

    struct hci_conn_info_req *cr;
    uint8_t encrypt;

    int i, j, err, sock, dev_id = -1, bytes_read, pid;
    
    struct hci_dev_info dev_info;
    inquiry_info *info = NULL;
    int num_rsp, length, flags;
    bdaddr_t ba;
    char addr[19] = { 0 };
    char name[248] = { 0 };
    uuid_t uuid = { 0 };
    uint32_t range = 0x0000ffff;
    sdp_list_t *response_list = NULL, *search_list, *attrid_list;
    int s, loco_channel = -1, status;
    struct sockaddr_rc loc_addr = { 0 };

    int ss, clilen;

    struct sockaddr_in server_addr, msg_to_client_addr;

    ss = socket(AF_INET, SOCK_DGRAM, 0);

    /* se asigna una direccion al socket del servidor*/
    bzero((char *)&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(puerto);
    bind(ss, (struct sockaddr *)&server_addr, sizeof(server_addr));
    clilen = sizeof(msg_to_client_addr);
    
    char *uuid_str="fa87c0d0-afac-11de-8a39-0800200c9a66";

    (void) signal(SIGINT, SIG_DFL);

    dev_id = hci_get_route(NULL);
    if (dev_id < 0) {
        perror("Error al iniciar el adaptador de Bluetooth.");
        exit(1);
    }

    if (hci_devinfo(dev_id, &dev_info) < 0) {
        perror("Error al obtener la información del dispositivos conectarse");
        exit(1);
    }

    sock = hci_open_dev( dev_id );
    if (sock < 0) {
        perror("Error al abrir el socket interno de la tarjeta");
        free(info);
        exit(1);
    }
    
    if( !str2uuid( uuid_str, &uuid ) ) {
        perror("El UUID es inválido");
        free(info);
        exit(1);
    }

    do {
        printf("Escaneando por dispositivos ...\n");
        info = NULL;
        num_rsp = 0;
        flags = 0;
        length = 8;
        num_rsp = hci_inquiry(dev_id, length, num_rsp, NULL, &info, flags);
        if (num_rsp < 0) {
            perror("No se encontraron dispositivos cerca");
            exit(1);
        }

        for (i = 0; i < num_rsp; i++) {
            sdp_session_t *session;
            int retries;
            int foundit;
            ba2str(&(info+i)->bdaddr, addr);
            memset(name, 0, sizeof(name));
            if (hci_read_remote_name(sock, &(info+i)->bdaddr, sizeof(name), 
                    name, 0) < 0)
            strcpy(name, "[Desconocido]");
            printf("Encontrado: %s, %s\n", addr, name);
            
            // connect to the SDP server running on the remote machine
            sdpconnect:
            session = 0; retries = 0;
            while(!session) {
                session = sdp_connect( BDADDR_ANY, &(info+i)->bdaddr, SDP_RETRY_IF_BUSY );
                if(session) break;
                if(errno == EALREADY && retries < 5) {
                    retries++;
                    sleep(1);
                    continue;
                }
                break;
            }
            if ( session == NULL ) {
                perror("No se puede acceder a una conexión con el dispositivo");
                free(info);
                continue;
            }
            search_list = sdp_list_append( 0, &uuid );
            attrid_list = sdp_list_append( 0, &range );
            err = 0;
            err = sdp_service_search_attr_req( session, search_list, SDP_ATTR_REQ_RANGE, attrid_list, &response_list);
            sdp_list_t *r = response_list;
            sdp_record_t *rec;
            // go through each of the service records
            foundit = 0;
            for (; r; r = r->next ) {
                    rec = (sdp_record_t*) r->data;
                    sdp_list_t *proto_list;
                    
                    // get a list of the protocol sequences
                    if( sdp_get_access_protos( rec, &proto_list ) == 0 ) {
                    sdp_list_t *p = proto_list;

                        // go through each protocol sequence
                        for( ; p ; p = p->next ) {
                                sdp_list_t *pds = (sdp_list_t*)p->data;

                                // go through each protocol list of the protocol sequence
                                for( ; pds ; pds = pds->next ) {

                                        // check the protocol attributes
                                        sdp_data_t *d = (sdp_data_t*)pds->data;
                                        int proto = 0;
                                        for( ; d; d = d->next ) {
                                                switch( d->dtd ) { 
                                                        case SDP_UUID16:
                                                        case SDP_UUID32:
                                                        case SDP_UUID128:
                                                                proto = sdp_uuid_to_proto( &d->val.uuid );
                                                                break;
                                                        case SDP_UINT8:
                                                                if( proto == RFCOMM_UUID ) {
                                                                        loco_channel = d->val.int8;
                                                                        foundit = 1;
                                                                }
                                                                break;
                                                }
                                        }
                                }
                                sdp_list_free( (sdp_list_t*)p->data, 0 );
                        }
                        sdp_list_free( proto_list, 0 );

                    }
                    if (loco_channel > 0)
                        break;

            }
            if ( loco_channel > 0 && foundit == 1 ) {
                s = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
                loc_addr.rc_family = AF_BLUETOOTH;
                loc_addr.rc_channel = loco_channel;
                loc_addr.rc_bdaddr = *(&(info+i)->bdaddr);

                status = connect(s, (struct sockaddr *)&loc_addr, sizeof(loc_addr));
                if( status < 0 ) {
                    perror("Error, no se pudo crear conexión");
                }
                printf("Conexión Creada\n");

                pid = fork();
                if(pid == 0){
                    while(1){
                        
                        printf("-Mensaje: %s\n", mensaje);
                        printf("-Esperando..\n");
                        recvfrom(ss, (char *) mensaje, 27*sizeof(char), 0, (struct sockaddr *)&msg_to_client_addr, &clilen);

                        printf("-Mensaje: %s\n", mensaje);
                        /*printf("opc: %d\n", men.opc);
                        printf("latitutd %s\n", men.latitutd);
                        printf("longitud %s\n", men.longitud);*/

                        char cadena[4];
                        char puerto[4];
                        //msg_to_server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
                        memcpy(cadena,&msg_to_client_addr.sin_addr.s_addr,4);
                        //memcpy(puerto,&msg_to_client_addr.sin_port,4);
                        int ii;
                        for(ii=0;ii<4;ii++){ 
                            printf("-%d", cadena[ii]);
                            if(ii!=3){
                                printf(".");
                            }
                        }

                        printf("-\n");
                        printf("%-d ", ntohs(msg_to_client_addr.sin_port));
                        printf("-\n");

			for(int aa=0;aa<5;aa++){
                        bytes_read = write(s, mensaje, 27);
                        printf ("-Wrote %d bytes\n", bytes_read);
                        sleep(1);
			}
                    }

                }else{
                    while(1){
                        //OTRO
                        bytes_read = read(s, buffer, sizeof(buffer));
                        if( bytes_read > 0 ) {
                            printf("*received [%s]\n", buffer);
                        }

                        int numero = 100 * ((int) buffer[1] - 48)+ 10 * ((int) buffer[2] -48) + ((int) buffer[3] -48);
                        printf("*Numero: %d\n", numero);
                        
                        char ip[10];
//                        sprintf(ip, "10.0.0.%d", numero);
                        sprintf(ip, "10.0.0.%d", 123);
                        /* rellena la dirección del servidor */
                        bzero((char *)&msg_to_client_addr, sizeof(msg_to_client_addr));
                        msg_to_client_addr.sin_family = AF_INET;
                        msg_to_client_addr.sin_addr.s_addr = inet_addr(ip);
                        msg_to_client_addr.sin_port = htons(puerto);

                        char cadena[4];
                        memcpy(cadena,&msg_to_client_addr.sin_addr.s_addr,4);
                        for(i=0;i<4;i++){ 
                            printf("*%d", cadena[i]);
                            if(i!=3){
                                printf(".");
                            }
                        }

                        int j=0;
			if(buffer[0]=='3'){
				men[0]='1';
				men[1]='1';
				men[2]='2';
				men[3]='3';
				men[4]='6';
				men[5]='6';
				men[6]='6';
				men[7]=' ';
				men[8]='1';
				men[9]='9';
				men[10]='.';
				men[11]='5';
				men[12]='0';
				men[13]='4';
				men[14]='9';
				men[15]='2';
				men[16]='6';
				men[17]='-';
				men[18]='9';
				men[19]='9';
				men[20]='.';
				men[21]='1';
				men[22]='4';
				men[23]='6';
				men[24]='6';
				men[25]='9';
				men[26]='2';
			}else if(buffer[0]=='4'){
				men[0]='2';
				men[1]='1';
				men[2]='2';
				men[3]='3';
				men[4]='6';
				men[5]='6';
				men[6]='6';
				men[7]=' ';
				men[8]='1';
				men[9]='9';
				men[10]='.';
				men[11]='5';
				men[12]='0';
				men[13]='4';
				men[14]='9';
				men[15]='2';
				men[16]='6';
				men[17]='-';
				men[18]='9';
				men[19]='9';
				men[20]='.';
				men[21]='1';
				men[22]='4';
				men[23]='6';
				men[24]='6';
				men[25]='9';
				men[26]='2';
			}
/*                        for(j=1;j<27;j++){
                            men[j] = buffer[j];
                        }
*/
                        printf("*MENSAJE A ENVIAR%s\n", men);

                        sendto(ss, (char *)men, 27*sizeof(char), 0, (struct sockaddr *) &msg_to_client_addr, sizeof(msg_to_client_addr));
                    }
                }                
                
                close(s);
                sdp_record_free( rec );

            }

            sdp_close(session);
            if (loco_channel > 0) {
                goto sdpconnect;
            }
            
        }
    } while (1);
}
