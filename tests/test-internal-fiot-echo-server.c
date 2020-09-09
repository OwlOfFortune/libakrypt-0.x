/* Пример, иллюстрирующий работу эхо-сервера,
   использующего обмен сообщениями по каналу связи, защищенному с помощью протокола sp fiot.
   В качестве транспорта используется tcp.

   Внимание! Используются не экспортируемые функции.

   test-internal-fiot-echo-server.c
*/
 #include <stdio.h>
 #include <errno.h>
 #include <stdlib.h>
 #include <string.h>

#ifdef LIBAKRYPT_HAVE_UNISTD_H
 #include <unistd.h>
#endif
#ifdef LIBAKRYPT_HAVE_SYSSOCKET_H
 #include <sys/socket.h>
#endif
 #include <ak_fiot.h>


 int main( int argc, char *argv[] )
{
  char ip[16];
  struct fiot ctx;
  socklen_t opt = 0;
  struct sockaddr_in servaddr, cl_addr;
  socklen_t len = sizeof( struct sockaddr_in );
  int error = ak_error_ok, fd = -1, reuse = 1, done = 0;
  ak_socket listenfd = ak_network_undefined_socket;

 /* проверяем, что определен ip адрес сервера и порт */
  if( argc != 3 ) {
    printf("usage: echo-server ip_address port\n");
    return EXIT_SUCCESS;
  }

  /* часть первая: создание сокетов */

  /* инициализируем библиотеку на стороне сервера
     вывод сообщений аудита производится в стандартный поток ошибок */
   if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();
  /* устанавливаем максимальный уровень аудита */
   ak_log_set_level( fiot_log_maximum );

  /* создаем сокет */
   if(( listenfd = ak_network_socket( AF_INET, SOCK_DGRAM, 0 )) == ak_network_undefined_socket )
     return ak_error_message_fmt( -1,  __func__,
                                          "wrong creation of listening socket (%s)", strerror(errno));
   memset( &servaddr, 0, sizeof( struct sockaddr_in ));
   servaddr.sin_family = AF_INET;
   if( ak_network_inet_pton( AF_INET, argv[1], &servaddr.sin_addr.s_addr ) != ak_error_ok )
     return ak_error_message_fmt( -1, __func__, "incorrect assigning server ip %s address (%s)",
                                                                          argv[1], strerror( errno ));
   servaddr.sin_port = htons( atoi( argv[2] ));

  /* разрешаем запускать bind() на используемом адресе */
   ak_network_setsockopt( listenfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof ( reuse ));
   if( ak_network_bind( listenfd,  &servaddr, sizeof( servaddr )) != ak_error_ok )
     return ak_error_message_fmt( -1, __func__,
                                          "wrong binding of listening socket (%s)", strerror(errno));

  /* принимаем соединения */
   opt = sizeof( cl_addr );

   char msg;
   if (ak_network_recvfrom(listenfd, &msg, 1, MSG_PEEK, &cl_addr, &opt) <= 0) {
                ak_network_close(listenfd);
                return ak_error_message(ak_error_read_data, __func__, "wrong first client message receiving");
   }
   
   if (ak_network_connect(listenfd, &cl_addr, opt) != ak_error_ok) {
                ak_network_close(listenfd);
                return ak_error_message(error, __func__, "wrong UDP-connection to client address");
   }
   fd = listenfd;
   
   if( ak_network_inet_ntop( AF_INET, &cl_addr.sin_addr, ip, (socklen_t) sizeof( ip )) == NULL )
     return ak_error_message_fmt( -1, __func__,
                                        "can't determine client's address (%s)", strerror( errno ));
   printf( "echo-server: accepted client from %s:%u\n", ip, cl_addr.sin_port );


  /* часть вторая: аутентификация клиента и выполнение протокола выработки общих ключей */


  /* устанавливаем криптографические параметры взаимодействия и запускаем протокол выработки ключей */
  /* создаем контекст защищенного соединения */
   if(( error = ak_fiot_context_create( &ctx )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect fiot context creation" );

  /* устанавливаем роль */
   if(( error = ak_fiot_context_set_role( &ctx, server_role )) != ak_error_ok ) goto exit;
  /* устанавливаем идентификатор сервера */
   if(( error = ak_fiot_context_set_user_identifier( &ctx, server_role,
                                                       "serverID", 8 )) != ak_error_ok ) goto exit;
  /* устанавливаем сокет для внешнего (шифрующего) интерфейса */
   if(( error = ak_fiot_context_set_interface_descriptor( &ctx,
                                            encryption_interface, fd )) != ak_error_ok ) goto exit;
  /* устанавливаем набор криптографических алгоритмов для обмена зашифрованной информацией */
   if(( error =  ak_fiot_context_set_server_policy( &ctx,
                                            magmaCTRplusGOST3413 )) != ak_error_ok ) goto exit;
  /* теперь выполняем протокол */
   if(( error = ak_fiot_context_keys_generation_protocol( &ctx )) != ak_error_ok ) goto exit;
   printf( "echo-server: client authentication is Ok\n" );


  /* часть третья: получение и возврат сообщений */


   done = 0;
   do {
        size_t length;
        message_t mtype = undefined_message;
        ak_uint8 *data = ak_fiot_context_read_frame( &ctx, &length, &mtype );
        if( data == NULL ) continue;
         else {
                data[length-1] = 0;
                printf( "echo-server: recived [%s]\n", data );
              }
        if( strncmp( (char *)data, "quit", 4 ) == 0 ) done = 1;
        if(( error = ak_fiot_context_write_frame( &ctx,
                                             data, length, encrypted_frame, mtype )) != ak_error_ok )
          ak_error_message( error, __func__, "write error");
        } while( !done );

  exit:
   ak_fiot_context_destroy( &ctx );
   ak_network_close( listenfd );
   ak_libakrypt_destroy();

 return EXIT_SUCCESS;
}
