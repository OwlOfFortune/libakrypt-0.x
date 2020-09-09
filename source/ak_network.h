/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2018 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_network.h                                                                              */
/*  - содержит предварительное описание функций для работы с сетью.                                */
/* ----------------------------------------------------------------------------------------------- */
 #ifndef __AK_NETWORK_H__
 #define __AK_NETWORK_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_WINDOWS_H
 #include <winsock2.h>
 #include <ws2tcpip.h>
#endif
#ifdef LIBAKRYPT_HAVE_SYSSOCKET_H
 #include <sys/socket.h>
 #include <arpa/inet.h>
 #include <netinet/in.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_WINDOWS_H
/*! \brief  Определение сокета, не зависящее от типа операционной системы. */
 typedef SOCKET ak_socket;
 #define ak_network_undefined_socket  ((int) INVALID_SOCKET )

#else
/*! \brief  Определение сокета, не зависящее от типа операционной системы. */
 typedef int ak_socket;
 #define ak_network_undefined_socket                (-1)
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \brief  Тип функции низкого уровня для чтения из сокета. */
 typedef ssize_t ( fiot_function_socket_write )( ak_socket , const void *, size_t );
/*! \brief  Тип функции низкого уровня для записи в сокета. */
 typedef ssize_t ( fiot_function_socket_read )( ak_socket , void *, size_t );

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_WINDOWS_H
/*! \brief Используемая по-умолчанию в ОС Windows функция записи данных в сокет. */
 ssize_t ak_network_write_win( ak_socket , const void *, size_t );
 /*! \brief Используемая по-умолчанию в ОС Windows функция чтения данных из сокета. */
 ssize_t ak_network_read_win( ak_socket , void *, size_t );
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция чтения из неприсоединенного UDP-сокета. */
int ak_network_recvfrom( ak_socket, void*, size_t, int, ak_pointer, socklen_t* );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция создания сокета. */
 ak_socket ak_network_socket( int , int , int );
/*! \brief Функция закрытия сокета. */
 int ak_network_close( ak_socket );
/*! \brief Функция устанавливает соединение с сокетом. */
 int ak_network_connect( ak_socket , ak_const_pointer , socklen_t );
/*! \brief Функция связывает сокет с сетевым адресом. */
 int ak_network_bind( ak_socket , ak_const_pointer , socklen_t );
/*! \brief Функция выполняет прослушивание сокета. */
 int ak_network_listen( ak_socket , int );
/*! \brief Функция принимает входящее сообщение. */
 int ak_network_accept( ak_socket , ak_pointer , socklen_t * );

/*! \brief Функция преобразования IPv4 или IPv6 адреса в двоичную форму. */
 int ak_network_inet_pton( int , const char *, void * );
/*! \brief Функция выполняет преобразование двоичного представления адреса в человекочитаемую форму. */
 const char *ak_network_inet_ntop( int , ak_const_pointer , char *, socklen_t );
/*! \brief Функция устанавливает опции для заданного сокета. */
 int ak_network_setsockopt( ak_socket , int , int , ak_const_pointer , socklen_t );
/*! \brief Функция получает информацию о присоединенном сокете. */
 int ak_network_getpeername( ak_socket , ak_pointer , socklen_t * );

#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                   ak_network.h  */
/* ----------------------------------------------------------------------------------------------- */
