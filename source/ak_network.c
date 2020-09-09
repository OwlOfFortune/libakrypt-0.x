/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2018 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_network.с                                                                              */
/*  - содержит реализацию функций для работы с сетью.                                              */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_network.h>

#ifdef LIBAKRYPT_HAVE_STRING_H
 #include <string.h>
#endif
#ifdef LIBAKRYPT_HAVE_ERRNO_H
 #include <errno.h>
#endif
#ifdef LIBAKRYPT_HAVE_UNISTD_H
 #include <unistd.h>
#endif

#ifdef LIBAKRYPT_HAVE_WINDOWS_H
/* ----------------------------------------------------------------------------------------------- */
/*! \param sock Сокет, в который происходит запись.
    \param buffer Указатель на записываемые в сокет данные.
    \param size Размер данных в байтах.

    \return Функция возвращает количество записанных в сокет данных. Данное значение может быть
    меньше, чем значение параметра `size`.                                                         */
/* ----------------------------------------------------------------------------------------------- */
 ssize_t ak_network_write_win( ak_socket sock, const void *buffer, size_t size )
{
  return send( sock, buffer, size, MSG_DONTROUTE );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param sock Сокет, из которого происходит чтение.
    \param buffer Указатель на область памяти, в которую помещаются данные.
    \param size Размер считанных данных в байтах.

    \return Функция возвращает количество считанных из сокета данных. Данное значение может быть
    меньше, чем значение параметра `size`.                                                         */
/* ----------------------------------------------------------------------------------------------- */
 ssize_t ak_network_read_win( ak_socket sock, void *buffer, size_t size )
{
 return recv( sock, buffer, size, 0 );
}
#endif

/* ----------------------------------------------------------------------------------------------- */
int ak_network_recvfrom( ak_socket sock, void *buffer, size_t len, int flags, ak_pointer addr, socklen_t *addrLen )
{
    #ifdef _MSC_VER
        char str[128];
    #endif
    int ret = recvfrom(sock, buffer, len, flags, (struct sockaddr *)addr, addrLen);
    if (ret <= 0) {
        #ifdef _MSC_VER
            strerror_s( str, sizeof( str ), WSAGetLastError( ));
            ak_error_message_fmt( ak_error_read_data, __func__, "wrong data receiving [%s]", str );
        #else
            ak_error_message_fmt( ak_error_read_data, __func__,
                    "wrong data receiving [%s]", strerror( errno ));
        #endif
    }
    return ret;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_socket ak_network_socket( int domain, int type, int protocol )
{
 #ifdef _MSC_VER
  char str[128];
 #endif
  ak_socket sock = socket( domain, type, protocol );

  if( sock == ak_network_undefined_socket ) {
 #ifdef _MSC_VER
    strerror_s( str, sizeof( str ), WSAGetLastError( ));
    ak_error_message_fmt( ak_error_open_socket, __func__, "wrong socket creation [%s]", str );
 #else
    ak_error_message_fmt( ak_error_open_socket, __func__,
                                             "wrong socket creation [%s]", strerror( errno ));
 #endif
  }
 return sock;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_network_close( ak_socket sock )
{
  if( sock != ak_network_undefined_socket ) {
   #ifdef _WIN32
     if( closesocket( sock ) == SOCKET_ERROR ) {
       #ifdef _MSC_VER
         char str[128];
         strerror_s( str, sizeof( str ), WSAGetLastError( ));
         return ak_error_message_fmt( ak_error_close_socket, __func__,
                                                                "wrong socket closing [%s]", str );
       #else
         return ak_error_message_fmt( ak_error_close_socket, __func__,
                                                   "wrong socket closing [%s]", strerror( errno ));
       #endif
     }
   #else
     if( close( sock ) == -1 ) return ak_error_message_fmt( ak_error_close_socket, __func__,
                                                   "wrong socket closing [%s]", strerror( errno ));
   #endif
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/* Странным образом ws2_32.dll имеет внутри эти функции, но mingw их не экспортирует.
                                           Возможно для этого есть причина, но она, пока, не ясна. */
/* ----------------------------------------------------------------------------------------------- */
#ifdef _WIN32
 #ifndef _MSC_VER
  WINSOCK_API_LINKAGE int WSAAPI inet_pton( int , const char *, void * );
  WINSOCK_API_LINKAGE const char WSAAPI *inet_ntop( int , const void * , char *, socklen_t );
 #endif
#endif

/* ----------------------------------------------------------------------------------------------- */
 int ak_network_inet_pton( int family, const char *src, void *dst )
{
 #ifndef _MSC_VER
   if( inet_pton( family, src, dst ) != 1 )
     return ak_error_message_fmt( ak_error_wrong_inet_pton, __func__,
                                                 "wrong address creation (%s)", strerror( errno ));
 #else
     if( InetPton( family, src, dst ) != 1 ) {
       char str[128];
       strerror_s( str, sizeof( str ),  WSAGetLastError( ));
       return ak_error_message_fmt( ak_error_wrong_inet_pton, __func__,
                                                              "wrong address creation (%s)", str );
     }
 #endif
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 const char *ak_network_inet_ntop( int family, ak_const_pointer src, char *dst, socklen_t size )
{
   const char *ptr = NULL;
   if(( ptr = inet_ntop( family,
  #ifdef _MSC_VER
   (void *)
  #endif
       src, dst, size )) == NULL ) {
    #ifndef _MSC_VER
       ak_error_message_fmt( ak_error_wrong_inet_ntop, __func__,
                                               "wrong address resolution (%s)", strerror( errno ));
    #else
       char str[128];
       strerror_s( str, sizeof( str ),  WSAGetLastError( ));
       ak_error_message_fmt( ak_error_wrong_inet_ntop, __func__,
                                                            "wrong address resolution (%s)", str );
    #endif
       return ak_null_string;
   }
 return ptr;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_network_connect( ak_socket sock, ak_const_pointer addr, socklen_t len )
{
  if( connect( sock, ( const struct sockaddr * )addr, len ) != 0 ) {
 #ifdef _MSC_VER
    char str[128];
    strerror_s( str, sizeof( str ),  WSAGetLastError( ));
    return ak_error_message_fmt( ak_error_connect_socket, __func__, "connect error (%s)", str );
 #else
    return ak_error_message_fmt( ak_error_connect_socket, __func__,
                                                       "connect error (%s)", strerror( errno ));
 #endif
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_network_bind( ak_socket sock, ak_const_pointer addr, socklen_t len )
{
  if( bind( sock, ( const struct sockaddr * )addr, len ) != 0 ) {
 #ifdef _MSC_VER
    char str[128];
    strerror_s( str, sizeof( str ), WSAGetLastError( ));
    return ak_error_message_fmt( ak_error_bind_socket, __func__, "wrong bind socket [%s]", str );
 #else
    return ak_error_message_fmt( ak_error_bind_socket, __func__,
                                           "wrong bind creation [%s]", strerror( errno ));
 #endif
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_network_listen( ak_socket sock, int cnt )
{
  if( listen( sock, cnt ) != 0 ) {
 #ifdef _MSC_VER
    char str[128];
    strerror_s( str, sizeof( str ), WSAGetLastError( ));
    return ak_error_message_fmt( ak_error_listen_socket, __func__,
                                               "wrong listen for given socket [%s]", str );
 #else
    return ak_error_message_fmt( ak_error_listen_socket, __func__,
                                  "wrong listen for given socket [%s]", strerror( errno ));
 #endif
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_network_accept( ak_socket sock, ak_pointer addr, socklen_t *len )
{
  ak_socket fd = accept( sock, (struct sockaddr *)addr, len );
  if( fd == ak_network_undefined_socket ) {
 #ifdef _MSC_VER
    char str[128];
    strerror_s( str, sizeof( str ), WSAGetLastError( ));
    ak_error_message_fmt( ak_error_accept_socket, __func__, "invalid accept socket [%s]", str );
 #else
    ak_error_message_fmt( ak_error_accept_socket, __func__,
                                               "invalid accept socket [%s]", strerror( errno ));
 #endif
    return ak_network_undefined_socket;
  }
 return fd;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_network_setsockopt( ak_socket sock, int level, int optname,
                                                         ak_const_pointer optval, socklen_t optlen )
{
 #ifdef _MSC_VER
  int ret = setsockopt( sock, level, optname, (char *) optval, optlen );
 #else
  int ret = setsockopt( sock, level, optname, optval, optlen );
 #endif
  if( ret != 0 ) {
 #ifdef _MSC_VER
    char str[128];
    strerror_s( str, sizeof( str ), WSAGetLastError( ));
    return ak_error_message_fmt( ak_error_wrong_setsockopt, __func__,
                                               "wrong setting option for given socket [%s]", str );
 #else
    return ak_error_message_fmt( ak_error_wrong_setsockopt, __func__,
                                  "wrong setting option for given socket [%s]", strerror( errno ));
 #endif
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_network_getpeername( ak_socket sock, ak_pointer addr, socklen_t *len )
{
  if( getpeername( sock, (struct sockaddr *)addr, len ) == -1 ) {
 #ifdef _MSC_VER
    char str[128];
    strerror_s( str, sizeof( str ), WSAGetLastError( ));
    return ak_error_message_fmt( ak_error_wrong_getpeername, __func__,
                                        "wrong getting information about given socket [%s]", str );
 #else
    return ak_error_message_fmt( ak_error_wrong_getpeername, __func__,
                           "wrong getting information about given socket [%s]", strerror( errno ));
 #endif
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                   ak_network.c  */
/* ----------------------------------------------------------------------------------------------- */
