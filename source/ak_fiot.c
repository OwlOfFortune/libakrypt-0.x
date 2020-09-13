/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2018 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_fiot.с                                                                                 */
/*  - содержит реализацию функций инициализации и настройки контекста защищенного взаимодействия.  */
/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_STDLIB_H
 #include <stdlib.h>
#else
 #error Library cannot be compiled without stdlib.h header
#endif
#ifdef LIBAKRYPT_HAVE_STRING_H
 #include <string.h>
#else
 #error Library cannot be compiled without string.h header
#endif
#ifdef LIBAKRYPT_HAVE_ERRNO_H
 #include <errno.h>
#endif
#ifdef LIBAKRYPT_HAVE_UNISTD_H
 #include <unistd.h>
#endif
#ifdef LIBAKRYPT_HAVE_SYSSELECT_H
 #include <sys/select.h>
#endif
#ifdef LIBAKRYPT_HAVE_SYSSOCKET_H
 /* заголовок нужен для реализации функции shutdown */
 #include <sys/socket.h>
#endif
#ifdef LIBAKRYPT_HAVE_WINDOWS_H
 #include <winsock2.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_fiot.h>
 #include <ak_buffer.h>
 #include <ak_parameters.h>

/* ----------------------------------------------------------------------------------------------- */
 #define named_restriction_count     (11)
 #define ak_fiot_class     ( base_class )

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Множество всех допустимых ограничений защищенного взаимодействия. */
 const static struct named_restriction {
  /*! \brief Ограничения на значения параметров. */
   struct crypto_restriction restriction;
  /*! \brief Константа,  связанная со множеством значений параметров. */
   key_mechanism_t keymech;
 } crypto_restrictions[ named_restriction_count ] =  {
    { { 16384, 8192, 65535, 255 }, baseKeyMechanismMagma },
    { { 16384, 65536, 65535, 255 }, baseKeyMechanismKuznechik },
    { { 1500, 2048, 65535, 255 }, shortKCMechanismMagma },
    { { 1500, 65536, 65535, 255 },  shortKCMechanismKuznechik },
    { { 16384, 256, 65535, 65535 }, longKCMechanismMagma },
    { { 16384, 4096, 65535, 255 }, longKCMechanismKuznechik },
    { { 1500, 32, 65535, 65535 },  shortKAMechanismMagma },
    { { 1500, 256, 65535, 65535 }, shortKAMechanismKuznechik },
    { { 16384, 4, 65535, 65535 }, longKAMechanismMagma },
    { { 16384, 64, 65535, 65535 }, longKAMechanismKuznechik },
    { { 0, 0, 0, 0 }, undefinedKeyMechanism },
};

/* ----------------------------------------------------------------------------------------------- */
 static key_mechanism_t ak_fiot_get_restrictions_value( ak_crypto_restriction rest,
                                                                     size_t size, block_cipher_t bc )
{
  size_t idx = 0;
  key_mechanism_t km;

 /* теперь мы можем определить ограничения на криптографические параметры */
  if( size > 1500 ) /* получаем константу и потом ищем ее среди заранее готовых */
    km = ( long_frame | ( ak_fiot_class << 2 ) | ( bc << 4 ));
   else km = ( small_frame | ( ak_fiot_class << 2 ) | ( bc << 4 ));
  for( idx = 0; idx < named_restriction_count; idx++ ) {
     if( crypto_restrictions[idx].keymech == km )
       *rest = crypto_restrictions[idx].restriction;
  }
 return km;
}

/* ----------------------------------------------------------------------------------------------- */
/*                    функции для работы с контектами протокола sp fiot                            */
/* ----------------------------------------------------------------------------------------------- */

 ak_socket ak_fiot_context_get_actual_sock ( ak_fiot fctx, interface_t gate )
{
    switch( gate ) {
    case encryption_interface: return fctx->iface_enc;
    case plain_interface: return fctx->iface_plain;
    default: return -1;
    }
}

/* ----------------------------------------------------------------------------------------------- */
 static ssize_t ak_fiot_context_read_tcp ( ak_fiot fctx, interface_t gate, void * buf, size_t length )
{
    ak_socket sock = ak_fiot_context_get_actual_sock(fctx, gate);
#ifdef LIBAKRYPT_HAVE_WINDOWS_H
    /* здесь установлены функции-обертки для стандартных вызовов в Windows */
   return ak_network_read_win(sock, buf, length);
#else
   return read(sock, buf, length);
#endif
}

static ssize_t ak_fiot_context_read_udp ( ak_fiot fctx, interface_t gate, void * buf, size_t length )
{
   ak_socket sock = ak_fiot_context_get_actual_sock(fctx, gate);
   return recvfrom(sock, buf, length, 0, NULL, NULL);
}

 static ssize_t ak_fiot_context_write_tcp ( ak_fiot fctx, interface_t gate, const void * buf, size_t length )
{
    ak_socket sock = ak_fiot_context_get_actual_sock(fctx, gate);
#ifdef LIBAKRYPT_HAVE_WINDOWS_H
    /* здесь установлены функции-обертки для стандартных вызовов в Windows */
   return ak_network_write_win(sock, buf, length);
#else
   return write(sock, buf, length);
#endif  
}

static ssize_t ak_fiot_context_write_udp ( ak_fiot fctx, interface_t gate, const void * buf, size_t length )
{
	if ( !fctx->cl_addr_is_set ) 
		return ak_fiot_context_write_tcp(fctx, gate, buf, length);
	ak_socket sock = ak_fiot_context_get_actual_sock(fctx, gate);
        return sendto(sock, buf, length, 0, (struct sockaddr*) &fctx->cl_addr, sizeof(fctx->cl_addr));
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция инициализирует базовые поля контекста защищенного соединения.
    \param fctx Контекст защищенного соединения протокола sp fiot. Под контекст должна быть
    заранее выделена память.

    \return Функция возвращает \ref ak_error_ok в случае успеха. В противном случае возвращается
    отрицательное целое число, содержащее код ошибки.                                              */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_fiot_context_create_common( ak_fiot fctx )
{
  int error = ak_error_ok;

   if( fctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                           "using null pointer to fiot context" );
  /* устанавливаем максимальный размер буффера для хранения передаваемых/получаемых данных */
   if(( error = ak_buffer_create_size( &fctx->oframe, fiot_frame_size )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect creation of output buffer" );
   if(( error = ak_buffer_create_size( &fctx->inframe, fiot_frame_size )) != ak_error_ok ) {
     ak_buffer_destroy( &fctx->oframe );
     return ak_error_message( error, __func__, "incorrect creation of input buffer" );
   }

  /* смещение зашифровываемых данных от начала фрейма (для базового заголовка). */
    fctx->header_offset = fiot_frame_header_offset;
    ak_buffer_create( &fctx->header_data );

  /* роль участника взаимодействия изначально не определена */
    fctx->role = undefined_role;

  /* текущее состояние контекста зависит от роли участника взаимодействия. */
    fctx->state = undefined_state;

  /* используемый набор криптографических механизмов согласуется в ходе выполнения проткола. */
    fctx->mechanism = not_set_mechanism;

  /* начальные значения счетчиков */
   fctx->in_counter.l = fctx->in_counter.m = fctx->in_counter.n = 0;
   fctx->out_counter.l = fctx->out_counter.m = fctx->out_counter.n = 0;

  /* дескрипторы сокетов */
   fctx->iface_enc = fctx->iface_plain = ak_network_undefined_socket;

   fctx->write = NULL;
   fctx->read = NULL;
   fctx->blom_key = NULL;
   fctx->cl_addr_is_set = 0;

  /* устанавливаем таймаут ожидания входящих пакетов (в секундах) */
   fctx->timeout = 3;

  /* остальные поля: идентификаторы и ключи устанавливаются в ходе выполнения протокола */
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция уничтожает базовые поля контекста защищенного соединения, в частности,
    закрываются открытые дескрипторы интерфейсов и освобождается память, выделенная под буффера.
    \param fctx Контекст защищенного соединения протокола sp fiot.

    \return Функция возвращает \ref ak_error_ok в случае успеха. В противном случае возвращается
    отрицательное целое число, содержащее код ошибки.                                              */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_fiot_context_destroy_common( ak_fiot fctx )
{
   if( fctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                           "using null pointer to fiot context" );
#if 0

  ak_error_message_fmt(0, "", "iface_enc: %d", fctx->iface_enc );
  ak_error_message_fmt(0, "", "iface_plain: %d", fctx->iface_plain );
  ak_error_message_fmt(0, "", "undefined_interface: %d", undefined_interface );
  ak_error_message_fmt(0, "", "ak_network_undefined_socket: %d", ak_network_undefined_socket );


  /* закрываем связанные сокеты */
   if( fctx->iface_enc != undefined_interface ) {
#ifdef LIBAKRYPT_HAVE_SYSSOCKET_H
     shutdown( fctx->iface_enc, SHUT_RDWR );
#else
  #ifdef LIBAKRYPT_HAVE_WINDOWS_H
     shutdown( fctx->iface_enc, SD_BOTH );
  #endif
#endif
     ak_network_close( fctx->iface_enc );
     fctx->iface_enc = undefined_interface;
   }

   if( fctx->iface_plain != undefined_interface ) {
#ifdef LIBAKRYPT_HAVE_SYSSOCKET_H
     shutdown( fctx->iface_plain, SHUT_RDWR );
#else
  #ifdef LIBAKRYPT_HAVE_WINDOWS_H
     shutdown( fctx->iface_plain, SD_BOTH );
  #endif
#endif
     ak_network_close( fctx->iface_plain );
     fctx->iface_plain = undefined_interface;
   }
#endif

 /* очищаем память буфферов */
  ak_skey_context_destroy (fctx->blom_key);
  free(fctx->blom_key);
  ak_buffer_destroy( &fctx->oframe );
  ak_buffer_destroy( &fctx->inframe );
  ak_buffer_destroy( &fctx->header_data );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param fctx Контекст защищенного соединения протокола sp fiot.

    \note В ходе выполнения данной функции часть ключевой информации не инициализируется:
     - контекст предварительно распределенного ключа инициализируется в ходе выполнения функции
     ak_fiot_context_set_initial_crypto_mechanism()
     - контексты ключей шифрования (`fctx->ecfk`, `fctx->esfk`) и ключи
     имитозащиты (`fctx->icfk`, `fctx->isfk`)
     инициализируются в ходе выполнения функции ak_fiot_context_set_secondary_crypto_mechanism().

    \return Функция возвращает ноль в случае успеха. В противном случае возвращается
    отрицательное целое число, содержащее код ошибки.                                              */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_create( ak_fiot fctx )
{
  int error = ak_error_ok;

  /* инициализируем заголовок струкуры */
   memset( fctx, 0, sizeof( struct fiot ));
   if(( error = ak_fiot_context_create_common( fctx )) != ak_error_ok )
     return ak_error_message( error, __func__, "common part of fiot context incorrect creation");

  /* инициализируем буфферы для хранения идентификаторов участников взаимодействия */
   if(( error = ak_buffer_create( &fctx->client_id )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect creation of client ID buffer");
     ak_fiot_context_destroy( fctx );
     return error;
   }
   if(( error = ak_buffer_create( &fctx->server_id )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect creation of server ID buffer");
     ak_fiot_context_destroy( fctx );
     return error;
   }

   /* инициализируем буфферы для хранения идентификаторов ключа аутентификации */
   if(( error = ak_buffer_create( &fctx->epsk_id )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect creation of epsk ID buffer");
     ak_fiot_context_destroy( fctx );
     return error;
   }

  /* инициализируем генераторы */
   if(( error = ak_random_context_create_lcg( &fctx->plain_rnd )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect creation of plain random generator");
     ak_fiot_context_destroy( fctx );
     return error;
   }
#ifdef _WIN32
   if(( error = ak_random_context_create_winrtl( &fctx->crypto_rnd )) != ak_error_ok ) {
#else
   if(( error = ak_random_context_create_urandom( &fctx->crypto_rnd )) != ak_error_ok ) {
#endif
     ak_error_message( error, __func__, "incorrect creation of crypto random generator");
     ak_fiot_context_destroy( fctx );
     return error;
   }

  /* параметры эллиптической кривой по умолчанию (важны для забывчивого клиента) */
   if(( error = ak_fiot_context_set_curve( fctx,
                                tc26_gost3410_2012_256_paramsetA )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect elliptic curve parameters");
     ak_fiot_context_destroy( fctx );
     return error;
   }

  /* инициализируем контекст хеширования сообщений */
   if(( error = ak_mac_context_create_oid( &fctx->comp,
                       ak_oid_context_find_by_name( "streebog512" ))) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect creation of hash function context");
     ak_fiot_context_destroy( fctx );
     return error;
   }

  /* инициализируем контекст контроля целостности незашифрованных сообщений */
   if(( error = ak_mac_context_create_oid( &fctx->epsk,
                       ak_oid_context_find_by_name( "streebog256" ))) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect creation of hash function context");
     ak_fiot_context_destroy( fctx );
     return error;
   }

  /* устанавливаем значения параметров политики взаимоействия по-умолчанию */
   fctx->policy.mechanism = kuznechikCTRplusGOST3413;

  /* криптографические ограничения зависят от используемого алгоритма шифрования информации,
     и должны устанавливаться при выборе криптографических механизмов. */
   fctx->policy.restrictions = crypto_restrictions[1].restriction;

  /* тип ключа аутентификации нам не ясен */
   fctx->epsk_type = undefined_key;

  /* флаги расширений */
   fctx->extensionFlags = 0;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param fctx Контекст защищенного соединения протокола sp fiot.

    \return Функция возвращает ноль в случае успеха. В противном случае возвращается
    отрицательное целое число, содержащее код ошибки.                                              */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_destroy( ak_fiot fctx )
{
  int error = ak_error_ok, pface = undefined_interface, eface = undefined_interface;

 /* уничтожение буфферов с идентификаторами */
  if(( error = ak_buffer_destroy( &fctx->client_id )) != ak_error_ok )
    ak_error_message( error, __func__, "incrorrect destroying of client ID buffer" );
  if(( error = ak_buffer_destroy( &fctx->server_id )) != ak_error_ok )
    ak_error_message( error, __func__, "incrorrect destroying of server ID buffer" );
  if(( error = ak_buffer_destroy( &fctx->epsk_id )) != ak_error_ok )
    ak_error_message( error, __func__, "incrorrect destroying of epsk ID buffer" );

 /* освобождаем генераторы */
  if(( error = ak_random_context_destroy( &fctx->plain_rnd )) != ak_error_ok )
    ak_error_message( error, __func__, "incrorrect destroying of plain random generator" );
  if(( error = ak_random_context_destroy( &fctx->crypto_rnd )) != ak_error_ok )
    ak_error_message( error, __func__, "incrorrect destroying of crypto random generator" );

 /* освобождаем контекст хэширования сообщений */
  if(( error = ak_mac_context_destroy( &fctx->comp )) != ak_error_ok )
    ak_error_message( error, __func__, "incrorrect destroying of hash function context" );

 /* если нужно, уничтожаем ключи аутентификации */
  ak_mac_context_destroy( &fctx->epsk );
  fctx->epsk_type = undefined_key;

 /* освобождаем производную ключевую информацию */
  ak_bckey_context_destroy( &fctx->ecfk );
  ak_bckey_context_destroy( &fctx->esfk );
  ak_mac_context_destroy( &fctx->icfk );
  ak_mac_context_destroy( &fctx->isfk );

 /* освобождаем базовую часть */
  if(( error = ak_fiot_context_destroy_common( fctx )) != ak_error_ok )
    ak_error_message( error, __func__ , "incorrect common part destroying of fiot context" );

 /* обнуляем значения
    если мы хотим потом закрывать интерфейсы самостоятельно, то надо сохранить их значения */
  pface = fctx->iface_plain;
  eface = fctx->iface_enc;
  memset( fctx, 0, sizeof( struct fiot ));
  fctx->iface_enc = eface;
  fctx->iface_plain = pface;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ctx указатель на контекст защищенного взаимодействия
    @return Функция возвращает NULL. В случае возникновения ошибки, ее код может быть получен с
    помощью вызова функции ak_error_get_value().                                                   */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_fiot_context_delete( ak_pointer ctx )
{
  if( ctx != NULL ) {
      ak_fiot_context_destroy(( ak_fiot ) ctx );
      free( ctx );
     } else ak_error_message( ak_error_null_pointer, __func__ ,
                                                           "using null pointer to fiot context" );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \details Функция возвращает значение, которым ограничена длина данных, передаваемых или
    принимаемых из канала связи. Эта величина определяет максимальный размер памяти,
    выделенной при содании контекста, для хранения данных.

    \param fctx Контекст защищенного соединения протокола sp fiot.
    \param fb Тип буффера, для которого запрашивается размер.

    \return Функция возвращает ноль (!) в случае ошибки. При этом устанавливается код ошибки,
    который можно узнать с помощью вызова функции ak_error_get_value().
    В случае успеха возвращается текущее значение длины фрейма, связанного с данным контектстом.   */
/* ----------------------------------------------------------------------------------------------- */
 size_t ak_fiot_context_get_frame_size( ak_fiot fctx, frame_buffer_t fb )
{
  if( fctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to fiot context" );
    return 0;
  }
  switch( fb ) {
    case inframe: return fctx->inframe.size;
    case oframe: return fctx->oframe.size;
  }
  ak_error_message( fiot_error_frame_buffer_type, __func__ , "incorrect frame buffer type" );
  return 0;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \details Функция предназначена для увеличения размера буффера после выполнения протокола
    выработки общих ключей, а также для возможности подстроиться под длины входящих фреймов.

    \param fctx Контекст защищенного соединения протокола sp fiot.
    \param fb Тип буффера, для которого устанавливается размер.
    \param framesize Новая длина фрейма (в октетах). Новая длина должна принимать значения
    в интервале от \ref fiot_min_frame_size до \ref fiot_max_frame_size.

    \note Значение framesize задает максимально возможную длину.
    Это длина фрейма, инкапсуриуемого в канальный протокол, т.е это значение должно быть
    меньше, чем текущее значение MTU. Величина, на которую фрейм должен быть меньше,
    зависит от длины заголовка используемого канального протокола.

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха. В противном случае
    возвращается отрицательное целое число, содержащее код ошибки.                                 */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_set_frame_size( ak_fiot fctx, frame_buffer_t fb, size_t framesize )
{
  int error = ak_error_ok;
  size_t newsize = framesize;

   if( fctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                              "using null pointer to fiot context" );
   if( newsize < fiot_min_frame_size ) newsize = fiot_min_frame_size;
   if( newsize > fiot_max_frame_size ) newsize = fiot_max_frame_size;

   switch( fb ) {
     case inframe:
        if( newsize <= fctx->inframe.size ) return ak_error_ok;
        if(( error = ak_buffer_alloc( &fctx->inframe, newsize )) != ak_error_ok )
          return ak_error_message( error, __func__, "incorrect increasing memory for input buffer" );
        else return ak_error_ok;

     case oframe:
        if( newsize <= fctx->oframe.size ) return ak_error_ok;
        if(( error = ak_buffer_alloc( &fctx->oframe, newsize )) != ak_error_ok )
          return ak_error_message( error, __func__, "incorrect increasing memory for output buffer" );
        else return ak_error_ok;
   }

 return ak_error_message( fiot_error_frame_buffer_type, __func__ , "incorrect frame buffer type" );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \details Одновременно с установкой роли участника защищенного взаимодействия
    инициализируется внутреннее стостояние контекста
     - для клиента устанавливается состояние \ref rts_client_hello
     - для сервера устанавливается состояние \ref wait_client_hello

    \param fctx Контекст защищенного соединения протокола sp fiot.
    \param role Константа, определяющая роль участника защищенного взаимодействия.

    \return В случае успеха, функция возвращает \ref ak_error_ok.
    В случае ошибки возвращается отрицательное целое число, содержащее код ошибки.                 */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_set_role( ak_fiot fctx, role_t role )
{
  if( fctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                           "using null pointer to fiot context" );
  if( role == undefined_role ) return ak_error_message( fiot_error_wrong_role, __func__,
                                                           "using wrong value of protocol role" );
  switch( role ) {
    case client_role: fctx->role = client_role;
                      fctx->state = rts_client_hello;
                      break;
    case server_role: fctx->role = server_role;
                      fctx->state = wait_client_hello;
                      break;
    default: return ak_error_message( fiot_error_wrong_role, __func__,
                                                       "assigning wrong value of protocol role" );
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_set_client( ak_fiot fctx, struct sockaddr_in cl_addr )
{
  if( fctx == NULL ) {
    return ak_error_message( ak_error_null_pointer, __func__, "using null pointer to fiot context" );
  }
  
  fctx->cl_addr_is_set = 1;
  fctx->cl_addr = cl_addr;
  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param fctx Контекст защищенного соединения протокола sp fiot.

    \return Функция возвращает значение роли контекста защищенного взаимодействия.
    В случае ошибки возвращается значение \ref undefinedRole.                                      */
/* ----------------------------------------------------------------------------------------------- */
 role_t ak_fiot_context_get_role( ak_fiot fctx )
{
  if( fctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to fiot context" );
    return undefined_role;
  }

  return fctx->role;
}
 
/* ----------------------------------------------------------------------------------------------- */
 const struct sockaddr_in* ak_fiot_context_get_client( ak_fiot fctx )
{
  if( fctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to fiot context" );
    return NULL;
  }
  
  if ( !fctx->cl_addr_is_set ) {
    ak_error_message( ak_error_null_pointer, __func__, "client address is not set" );
    return NULL;
  }
  
  return &fctx->cl_addr;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_set_blom_key( ak_fiot fctx, ak_uint8 blom_data [32 * 256] )
{
  int error = ak_error_ok;

  if( fctx == NULL ) {
      return ak_error_message( ak_error_null_pointer, __func__, "using null pointer to fiot context" );
  }

  if ( fctx->blom_key != NULL && (error = ak_skey_context_destroy (fctx->blom_key)) != ak_error_ok )
      return error;
  else 
      fctx->blom_key = malloc(sizeof(*fctx->blom_key));

  if ( (error = ak_skey_context_create(fctx->blom_key, 32 * 256, 8) )  != ak_error_ok )
	  return error;
  
  if ( (error = ak_skey_context_set_key(fctx->blom_key, blom_data, 32 * 256, ak_true )) != ak_error_ok )
	 return error;

  return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_set_blom_key_from_skey( ak_fiot fctx, ak_skey skey, bool_t delegate )
{
  int error = ak_error_ok;

  if ( fctx == NULL ) {
    return ak_error_message( ak_error_null_pointer, __func__, "using null pointer to fiot context" );
  }

  if ( skey == fctx->blom_key )
    return ak_error_ok;
  
  if ( fctx->blom_key != NULL ) {
    if ((error = ak_skey_context_destroy (fctx->blom_key)) != ak_error_ok )
      return error;
    free(fctx->blom_key);
  }

  if (delegate == ak_true)
      fctx->blom_key = skey;
  else
      ak_skey_context_create_and_set_skey(fctx->blom_key, skey);
  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param fctx Контекст защищенного соединения протокола sp fiot.

    \return Функция возвращает значение текущее состояние контекста защищенного взаимодействия.
    В случае ошибки возвращается значение \ref undefined_state.                                     */
/* ----------------------------------------------------------------------------------------------- */
 context_state_t ak_fiot_context_get_state( ak_fiot fctx )
{
  if( fctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to fiot context" );
    return undefined_state;
  }
 return fctx->state;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param fctx Контекст защищенного соединения.
    \param role Роль того участника, кому присваивается идентификатор.
    \param in Указатель на данные, являющиеся идентификатором сервера.
    \param size Размер данных, в байтах.

    \return Функция возвращает ноль в случае успеха. В противном случае возвращается
    отрицательное целое число, содержащее код ошибки.                                              */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_set_user_identifier( ak_fiot fctx, role_t role, void *in, const size_t size )
{
  if( fctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using a null pointer to fiot context" );
  if( size < 1 ) return ak_error_message( ak_error_wrong_length, __func__,
                                                       "using an identifier with wrong length" );
  switch( role ) {
    case client_role: return ak_buffer_set_ptr( &fctx->client_id, in, size, ak_true );
    case server_role: return ak_buffer_set_ptr( &fctx->server_id, in, size, ak_true );
    default:
       return ak_error_message( fiot_error_wrong_role, __func__, "using incorrect role of user");
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param fctx Контекст защищенного соединения.
    \param role Роль того участника, для которого получается идентификатор.
    \param out Указатель на область памяти, в которую помещается результат.
    \param maxlen Максимальный размер доступной памяти (в октетах)

    \return  Возвращается количество записанных октетов. В случае возникновения ошибки возвращается
    отрицательное число - код ошибки                                                               */
/* ----------------------------------------------------------------------------------------------- */
 ssize_t ak_fiot_context_get_user_identifier( ak_fiot fctx, role_t role,
                                                                    void *out, const size_t maxlen )
{
  size_t len = 0;
  if( fctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                         "using a null pointer to fiot context" );
  if( out == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                          "using null pointer to output memory" );
  if( maxlen < 1 ) return ak_error_message( ak_error_wrong_length, __func__,
                                                         "using incorrect value of memory size" );
  switch( role ) {
    case client_role:
       memcpy( out, fctx->client_id.data, len = ak_min( maxlen, fctx->client_id.size ));
       return (ssize_t) len;
    case server_role:
       memcpy( out, fctx->server_id.data, len = ak_min( maxlen, fctx->server_id.size ));
       return (ssize_t) len;
    default:
     return ak_error_message( fiot_error_wrong_role, __func__,
                                                       "using a wrong role of user indentifier" );
  }
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param fctx Контекст защищенного соединения.
    \param id Идентификатор эллиптической кривой.

    \return Функция возвращает \ref ak_error_ok в случае успеха. В противном случае возвращается
    отрицательное целое число, содержащее код ошибки.                                              */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_set_curve( ak_fiot fctx, elliptic_curve_t id )
{
  if( fctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using a null pointer to fiot context" );
  switch( id ) {
    case tc26_gost3410_2012_256_paramsetA:
          fctx->curve = ( ak_wcurve )( &id_tc26_gost_3410_2012_256_paramSetA );
          break;
    case tc26_gost3410_2012_512_paramsetA:
          fctx->curve = ( ak_wcurve )( &id_tc26_gost_3410_2012_512_paramSetA );
          break;
    case tc26_gost3410_2012_512_paramsetB:
          fctx->curve = ( ak_wcurve )( &id_tc26_gost_3410_2012_512_paramSetB );
          break;
    case tc26_gost3410_2012_512_paramsetC:
          fctx->curve = ( ak_wcurve )( &id_tc26_gost_3410_2012_512_paramSetC );
          break;

    case rfc4357_gost3410_2001_paramsetA:
          fctx->curve = ( ak_wcurve )( &id_rfc4357_gost_3410_2001_paramSetA );
          break;
    case rfc4357_gost3410_2001_paramsetB:
          fctx->curve = ( ak_wcurve )( &id_rfc4357_gost_3410_2001_paramSetB );
          break;
    case rfc4357_gost3410_2001_paramsetC:
          fctx->curve = ( ak_wcurve )( &id_rfc4357_gost_3410_2001_paramSetC );
          break;
    default: return ak_error_message( fiot_error_unknown_paramset,
                                          __func__, "using unknown paramset for elliptic curve" );
  }
  fctx->curve_id = id;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param fctx Контекст защищенного соединения.
    \return Функция возвращает установленный идентификатор эллиптической кривой.                   */
/* ----------------------------------------------------------------------------------------------- */
 elliptic_curve_t ak_fiot_context_get_curve( ak_fiot fctx )
{
  if( fctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to fiot context" );
    return unknown_paramset;
   }
 return fctx->curve_id;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param fctx Контекст защищенного соединения.
    \param gate Заданный интерфейс контекста защищенного взаимодейтсвия.
    \param descriptor Значение дескриптора открытого сокета (пайпа, файла и .д.),
    связываемое с заданным интерфейсом контекста.

    \return В случае успеха функция возвращает \ref ak_error_ok.
    В случае возникновения ошибки возвращается ее код                                              */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_set_interface_descriptor( ak_fiot fctx, interface_t gate, ak_socket descriptor )
{
  if( fctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using a null pointer to fiot context" );

  int type;
  socklen_t length = sizeof( type );
  getsockopt( descriptor, SOL_SOCKET, SO_TYPE, &type, &length );
  
  fctx->sock_type = type;

  if ( type == SOCK_DGRAM ) {
    fctx->write = ak_fiot_context_write_udp;
    fctx->read  = ak_fiot_context_read_udp; 
  } else {
    fctx->write = ak_fiot_context_write_tcp;
    fctx->read  = ak_fiot_context_read_tcp;
  }
  
  switch( gate ) {
    case encryption_interface: fctx->iface_enc = descriptor; return ak_error_ok;
    case plain_interface: fctx->iface_plain = descriptor; return ak_error_ok;
  default:  return ak_error_message( fiot_error_wrong_interface, __func__,
                                                            "using a wrong value of gate type" );
  }
 return fiot_error_wrong_interface;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param fctx Контекст защищенного соединения.
    \param gate Заданный интерфейс контекста защищенного взаимодейтсвия.
    \return Функция возвращает значение установленного дескриптора.
    В случае возникновения ошибки возвращается ее код                                              */
/* ----------------------------------------------------------------------------------------------- */
 ak_socket ak_fiot_context_get_gate_descriptor( ak_fiot fctx , interface_t gate )
{
  if( fctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using a null pointer to fiot context" );
  switch( gate ) {
    case encryption_interface: return fctx->iface_enc;
    case plain_interface: return fctx->iface_plain;
  default:  return ak_error_message( fiot_error_wrong_interface, __func__,
                                                            "using a wrong value of gate type" );
  }
 return fiot_error_wrong_interface;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \details Функция устанавливает идентификатор симметричного ключа аутентификации.
    В качестве такого ключа могут выступать
    - предварительно распределенный, симметричный ключ аутентификации ePSK,
    - выработанный в ходе предыдущего сеанса связи, симметричный ключ аутентификации iPSK.
    При этом значение ключа не устанавливается, это происходит
    при вызове функции ak_fiot_context_set_initial_crypto_mechanism().

    \param fctx Контекст защищенного соединения.
    \param type Тип ключа, для которого присваивается идентификатор.
    \param in Указатель на область памяти, в которой содержится идентификатор ключа.
    \param size Размер идентификатора в байтах
    \return В случае успеха функция возвращает \ref ak_error_ok. В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_set_psk_identifier( ak_fiot fctx, key_type_t type, void *in, const size_t size )
{
  int error = ak_error_ok;

  if(( in == NULL ) || ( size == 0 )) return ak_error_ok;
  if( fctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to fiot context" );
  switch( type ) {
    case ePSK_key: fctx->epsk_type = ePSK_key; break;
    case iPSK_key: fctx->epsk_type = iPSK_key; break;
    default: return ak_error_message_fmt( fiot_error_wrong_psk_type, __func__,
                                              "unexpected value of preshared key type: %x", type );
  }
  if(( error = ak_buffer_set_ptr( &fctx->epsk_id, in, size, ak_true )) != ak_error_ok )
    return ak_error_message( error, __func__,
                                               "incorrect assigning of preshared key identifier" );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */

static inline void ak_bswap64_4(ak_uint64 val[4])
{
	val[0] = bswap_64(val[0]);
	val[1] = bswap_64(val[1]);
	val[2] = bswap_64(val[2]);
	val[3] = bswap_64(val[3]);
}

/* ----------------------------------------------------------------------------------------------- */
 static void ak_blom_get_common_key(ak_skey blom_key, ak_uint8 remote_id[32], ak_uint8 common_key[32] )
{
  blom_key->unmask(blom_key);

  ak_mpzn256 remote;
  ak_mpzn256 local;
  ak_mpzn256 tmp[2];
  ak_mpzn256 res = ak_mpzn256_zero;
  ak_mpzn256 remote_pow[2] = {{1, 0, 0, 0}};

  memcpy(remote, remote_id, 32);
#ifdef LIBAKRYPT_BIG_ENDIAN
  ak_bswap64_4(remote);
#endif	
  for (int i=0; i<256; ++i) {
    memcpy(local, ((ak_uint8*) blom_key->key.data) + i*32, 32);
#ifdef LIBAKRYPT_BIG_ENDIAN
    ak_bswap64_4(local);
#endif
    ak_mpzn_mul(*tmp, local, *remote_pow, ak_mpzn256_size);
    ak_mpzn_add(res, res, *tmp, ak_mpzn256_size);
    ak_mpzn_mul(*remote_pow, *remote_pow, remote,ak_mpzn256_size);
  }

  blom_key->set_mask(blom_key);
#ifdef LIBAKRYPT_BIG_ENDIAN
  ak_bswap64_4(res);
#endif
  memcpy(common_key, res, 32);
}
/* ----------------------------------------------------------------------------------------------- */
/*! На момент вызова функции должен быть установлен идентификатор предварительно
    распределенного ключа (`epsk_id`) и должен быть создана структура секретного ключа `epsk`.

    \param fctx Контекст защищенного соединения.
    \return В случае успеха функция возвращает \ref ak_error_ok. В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_set_psk_key( ak_fiot fctx )
{
  struct hash ctx;
  ak_uint8 remote_hash[32];
  ak_uint8 common_key[32];
  if ( fctx == NULL )
    return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to fiot context" );

  if ( fctx->blom_key == NULL )
    return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to blom key" );
  if ( !ak_buffer_is_assigned( &fctx->epsk_id ) )
    return ak_error_message( fiot_error_wrong_psk_identifier_using, __func__,
                                                   "using an undefined preshared key identifier" );
   
  ak_hash_context_create_streebog256( &ctx );
  
  if ( fctx->role == client_role ) {
  	ak_hash_context_ptr( &ctx, fctx->server_id.data, fctx->server_id.size, remote_hash );
  } else {
  	ak_hash_context_ptr( &ctx, fctx->epsk_id.data, fctx->epsk_id.size, remote_hash );
  }

  ak_blom_get_common_key(fctx->blom_key, remote_hash, common_key);
  
  ak_hash_context_destroy( &ctx );
  ak_mac_context_set_key( &fctx->epsk, common_key, sizeof( common_key ), ak_true );
  ak_error_message( ak_error_ok, __func__, "Ok" );
  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_set_server_policy( ak_fiot fctx, crypto_mechanism_t mechanism )
{
 /* выполняем необходимые проверки */
  if( fctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to fiot context" );
  if( mechanism == not_set_mechanism ) return ak_error_message( fiot_error_wrong_mechanism,
                                                 __func__, "using an undefined crypto mechanism" );
  if( ak_fiot_get_key_type( mechanism ) != derivative_key )
    return ak_error_message( fiot_error_wrong_mechanism, __func__,
                                           "crypto mechanism have'nt a derivative keys constant" );

  fctx->policy.mechanism = mechanism;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция устанавливает множество криптографических алгоритмов,
    которые будут использованы для передачи незашифрованных сообщений в ходе протокола выработки
    общих ключей.  Для клиента эта функция должна быть вызвана пользователем.
    Для сервера - функция вызывается в ходе выполнения протокола.

    В ходе выполнения функции инициализируется контекст `fctx->epsk` предварительно распределенного
    ключа аутентификации, а ключу присваивается значение, соответствующее установленному ранее
    идентификатору. Если используется аутентификация с помощью сертификатов открытых ключей,
    то контекст `fctx->epsk` используется для бесключевого контроля елостности передаваемых сообщений.

    Окончательные значения криптографических механизмов,
    используемых в ходе защищенного взаимодействия, устанавливаются функцией
    ak_fiot_context_set_secondary_crypto_mechanism().

    \param fctx Контекст защищенного соединения.
    \param mechanism Константа, описывающая множество используемых
    криптографических преборазований.
    \return В случае успеха функция возвращает \ref ak_error_ok. В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_set_initial_crypto_mechanism( ak_fiot fctx, crypto_mechanism_t mechanism )
{
  key_type_t ktype;
  block_cipher_t bcipher;
  int error = ak_error_ok;

 /* выполняем необходимые проверки */
  if( fctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to fiot context" );
  if( mechanism == not_set_mechanism ) return ak_error_message( fiot_error_wrong_mechanism,
                                                 __func__, "using an undefined crypto mechanism" );

 /* первичные проверки на установленные идентификаторы ключей аутентификации */
  if(( ktype = ak_fiot_get_key_type( mechanism )) == derivative_key )
    return ak_error_message( fiot_error_wrong_mechanism, __func__,
                              "using crypto mechanism with unsupported key type: derivative key" );
  if(( ktype == ePSK_key ) || ( ktype == iPSK_key )) {
    if( !ak_buffer_is_assigned( &fctx->epsk_id ))
      return ak_error_message( fiot_error_wrong_psk_identifier_using, __func__,
                                                  "identifier for preshared key is not assigned" );
  }

 /* устанавливаем функцию контроля целостности */
  ak_mac_context_destroy( &fctx->epsk ); /* удаляем функцию по умолчанию */
  switch( ak_fiot_get_integrity_function( mechanism )) {

   /* начинаем с инициализации контекста хеширования
      (используется при аутентификации с использованием сертификатов открытых ключей) */
    case streebog256_function:
      if( ktype != undefined_key )
        return ak_error_message( fiot_error_wrong_psk_identifier_using, __func__,
                                             "unexpected key type for streebog256 hash function" );
      if(( error = ak_mac_context_create_oid( &fctx->epsk,
                                   ak_oid_context_find_by_name( "streebog256" ))) != ak_error_ok )
        return ak_error_message( error, __func__,
                                    "incorrect creation of mac context for streebog256 function" );
      break;

    case streebog512_function:
      if( ktype != undefined_key )
        return ak_error_message( fiot_error_wrong_psk_identifier_using, __func__,
                                             "unexpected key type for streebog256 hash function" );
      if(( error = ak_mac_context_create_oid( &fctx->epsk,
                                   ak_oid_context_find_by_name( "streebog512" ))) != ak_error_ok )
        return ak_error_message( error, __func__,
                                    "incorrect creation of mac context for streebog512 function" );
      break;

   /* теперь рассматриваем случаи с использованием симметричного ключа */
    case hmacStreebog256_function:
      if(( error = ak_mac_context_create_oid( &fctx->epsk,
                              ak_oid_context_find_by_name( "hmac-streebog256" ))) != ak_error_ok )
        return ak_error_message( error, __func__,
                               "incorrect creation of mac context for hmac-streebog256 function" );
      if(( error = ak_fiot_context_set_psk_key( fctx )) != ak_error_ok )
        return ak_error_message( error, __func__,
                                   "incorrect assigning key value for hmac-streebog256 function" );
      break;

    case hmacStreebog512_function:
      if(( error = ak_mac_context_create_oid( &fctx->epsk,
                              ak_oid_context_find_by_name( "hmac-streebog512" ))) != ak_error_ok )
        return ak_error_message( error, __func__,
                               "incorrect creation of mac context for hmac-streebog512 function" );
      if(( error = ak_fiot_context_set_psk_key( fctx )) != ak_error_ok )
        return ak_error_message( error, __func__,
                                   "incorrect assigning key value for hmac-streebog512 function" );
      break;

    case imgost3413_function:
      switch( bcipher = ak_fiot_get_block_cipher( mechanism )) {
        case magma_cipher:
          if(( error = ak_mac_context_create_oid( &fctx->epsk,
                                    ak_oid_context_find_by_name( "omac-magma" ))) != ak_error_ok )
            return ak_error_message( error, __func__,
                                     "incorrect creation of mac context for omac-magma function" );
          break;
        case kuznechik_cipher:
          if(( error = ak_mac_context_create_oid( &fctx->epsk,
                                ak_oid_context_find_by_name( "omac-kuznechik" ))) != ak_error_ok )
            return ak_error_message( error, __func__,
                                 "incorrect creation of mac context for omac-kuznechik function" );
          break;

        default: return ak_error_message_fmt( fiot_error_wrong_cipher_type, __func__,
                             "using crypto mechanism with unsupported block cipher: %x", bcipher );
      }
      if(( error = ak_fiot_context_set_psk_key( fctx )) != ak_error_ok )
        return ak_error_message( error, __func__,
                                     "incorrect assigning key value for gost34.13-2015 function" );
      break;

    default: return ak_error_message( fiot_error_wrong_integrity_algorithm, __func__,
                                                         "using an undefined integrity function" );
  }
  fctx->mechanism = mechanism;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует ключевые контексты, используемые клиентом и сервером для
    передачи зашифрованной и имитозащищенной информации.
    После инициализации ключевые значения не присваиваются - это делают отдельные функции
    выработки ключевой информации.

    \param fctx Контекст защищенного соединения.
    \param mechanism Константа, описывающая множество используемых
    криптографических преборазований.
    \return В случае успеха функция возвращает \ref ak_error_ok. В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_set_secondary_crypto_mechanism( ak_fiot fctx, crypto_mechanism_t mechanism )
{
  block_cipher_t bc;
  key_mechanism_t km;
  int error = ak_error_ok;

 /* выполняем необходимые проверки */
  if( fctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to fiot context" );
  if( mechanism == not_set_mechanism ) return ak_error_message( fiot_error_wrong_mechanism,
                                                 __func__, "using an undefined crypto mechanism" );
  if( ak_fiot_get_key_type( mechanism ) != derivative_key )
    return ak_error_message( fiot_error_wrong_mechanism,
                                    __func__, "using a mechanism with wrong type of secret keys" );

  switch( bc = ak_fiot_get_block_cipher( mechanism )) {
    case magma_cipher:
       if(( error = ak_bckey_context_create_magma( &fctx->esfk )) != ak_error_ok )
         return ak_error_message( error, __func__,
                                          "incorrect context creation for server encryption key" );
       if(( error = ak_bckey_context_create_magma( &fctx->ecfk )) != ak_error_ok )
         return ak_error_message( error, __func__,
                                          "incorrect context creation for client encryption key" );
      break;

    case kuznechik_cipher:
       if(( error = ak_bckey_context_create_kuznechik( &fctx->esfk )) != ak_error_ok )
         return ak_error_message( error, __func__,
                                           "incorrect context creation of server encryption key" );
       if(( error = ak_bckey_context_create_kuznechik( &fctx->ecfk )) != ak_error_ok )
         return ak_error_message( error, __func__,
                                           "incorrect context creation of client encryption key" );
      break;

    default: return ak_error_message( fiot_error_wrong_cipher_type, __func__,
                                                "using crypto mechanism with wrong block cipher" );
  }

  switch( ak_fiot_get_integrity_function( mechanism )) {
   case hmacStreebog256_function:
      if(( error = ak_mac_context_create_oid( &fctx->isfk,
                                   ak_oid_context_find_by_name( "streebog256" ))) != ak_error_ok )
        return ak_error_message( error, __func__,
                                            "incorrect context creation of server integrity key" );
      if(( error = ak_mac_context_create_oid( &fctx->icfk,
                                   ak_oid_context_find_by_name( "streebog256" ))) != ak_error_ok )
        return ak_error_message( error, __func__,
                                            "incorrect context creation of client integrity key" );
     break;

   case hmacStreebog512_function:
      if(( error = ak_mac_context_create_oid( &fctx->isfk,
                                   ak_oid_context_find_by_name( "streebog512" ))) != ak_error_ok )
        return ak_error_message( error, __func__,
                                            "incorrect context creation of server integrity key" );
      if(( error = ak_mac_context_create_oid( &fctx->icfk,
                                   ak_oid_context_find_by_name( "streebog512" ))) != ak_error_ok )
        return ak_error_message( error, __func__,
                                            "incorrect context creation of client integrity key" );
     break;

   case imgost3413_function:
      if( bc == magma_cipher ) {
        if(( error = ak_mac_context_create_oid( &fctx->isfk,
                                    ak_oid_context_find_by_name( "omac-magma" ))) != ak_error_ok )
          return ak_error_message( error, __func__,
                                            "incorrect context creation of server integrity key" );
        if(( error = ak_mac_context_create_oid( &fctx->icfk,
                                    ak_oid_context_find_by_name( "omac-magma" ))) != ak_error_ok )
          return ak_error_message( error, __func__,
                                            "incorrect context creation of client integrity key" );
      } else {
        if(( error = ak_mac_context_create_oid( &fctx->isfk,
                                ak_oid_context_find_by_name( "omac-kuznechik" ))) != ak_error_ok )
          return ak_error_message( error, __func__,
                                            "incorrect context creation of server integrity key" );
        if(( error = ak_mac_context_create_oid( &fctx->icfk,
                                ak_oid_context_find_by_name( "omac-kuznechik" ))) != ak_error_ok )
          return ak_error_message( error, __func__,
                                            "incorrect context creation of client integrity key" );
      }
     break;

   default: return ak_error_message( fiot_error_wrong_integrity_algorithm, __func__,
                                         "using crypto mechanism with wrong integrity function" );
  }

 /* присваиваем значение константы */
  fctx->mechanism = mechanism;

 /* теперь мы можем установить ограничения на криптографические параметры */
  km = ak_fiot_get_restrictions_value( &fctx->policy.restrictions, fctx->oframe.size, bc );
  if( ak_log_get_level() >= fiot_log_standard )
    ak_error_message_fmt( error, __func__,
                         "assigned mechanism 0x%x with restiction constant 0x%0x", mechanism, km );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*               Общие функции, не зависящие от конктерного контекста протокола                    */
/* ----------------------------------------------------------------------------------------------- */

/* ----------------------------------------------------------------------------------------------- */
/*! \param mechanism Значение константы, описывающей набор допустимых/используемых
    криптографических алгоритмов.
    \return Функция возвращает идентификатор алгоритма блочного шифрования.                        */
/* ----------------------------------------------------------------------------------------------- */
 block_cipher_t ak_fiot_get_block_cipher( const crypto_mechanism_t mechanism )
{
  block_cipher_t value = mechanism&0xF;

   if(( value == 0 ) || ( value > null_cipher )) return undefined_cipher;
  return value;
}

/* ----------------------------------------------------------------------------------------------- */
 block_cipher_encryption_t ak_fiot_get_block_cipher_encryption( const crypto_mechanism_t mechanism )
{
  block_cipher_encryption_t value = ( mechanism >> 8 )&0xF;

  if(( value == 0 ) || ( value > aead_encryption )) return undefined_encryption;
 return value;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param mechanism Значение константы, описывающей набор допустимых/используемых
    криптографических алгоритмов.
    \return Функция возвращает идентификатор алгоритма выработки имитовставки.                     */
/* ----------------------------------------------------------------------------------------------- */
 integrity_function_t ak_fiot_get_integrity_function( const crypto_mechanism_t mechanism )
{
  integrity_function_t value = ( mechanism >> 4 )&0xF;

  if(( value == 0 ) || ( value > imgost3413_function )) return undefined_integrity_function;
 return value;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param mechanism Значение константы, описывающей набор допустимых/используемых
    криптографических алгоритмов.
    \return Функция возвращает тип используемого ключа.                                            */
/* ----------------------------------------------------------------------------------------------- */
 key_type_t ak_fiot_get_key_type( const crypto_mechanism_t mechanism )
{
  key_type_t value = ( mechanism >> 12 )&0x3;

  if(( value == 0 ) || ( value > iPSK_key )) return undefined_key;
 return value;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param id Значение константы, описывающей набор папаметров эллиптической кривой.
    \return Функция возвращает размер x-координаты точки кривой (в байтах).                        */
/* ----------------------------------------------------------------------------------------------- */
 size_t ak_fiot_get_point_size( const elliptic_curve_t id )
{
  switch( id ) {
    case tc26_gost3410_2012_256_paramsetA:
    case rfc4357_gost3410_2001_paramsetA:
    case rfc4357_gost3410_2001_paramsetB:
    case rfc4357_gost3410_2001_paramsetC: return 32;

    case tc26_gost3410_2012_512_paramsetA:
    case tc26_gost3410_2012_512_paramsetB:
    case tc26_gost3410_2012_512_paramsetC: return 64;

    default: return 0;
  }
}

/* ----------------------------------------------------------------------------------------------- */
 const char *ak_fiot_get_message_name( message_t mtype )
{
  switch( mtype ) {
    case undefined_message: return "undefined message";
    case client_hello: return "clientHello message";
    case server_hello: return "serverHello message";
    case verify_message: return "verify message";
    case application_data: return "applicationData message";
    case alert_message: return "alert message";
    case generate_psk: return "generatePSK message";
    case extension_request_certificate: return "requestCertificate extension";
    case extension_certificate: return "certificate extension";
    case extension_set_certificate: return "setCertificate extension";
    case extension_inform_certificate: return "informCertificate extension";
    case extension_request_identifer: return "requestIdentifier extension";
    case extension_key_mechanism: return "keyMachanism extension";
  }
  ak_error_message( fiot_error_message_type, __func__, "using incorrect message type" );
 return ak_null_string;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example test-internal-fiot-context.c                                                          */
/*! \example test-internal-fiot-echo-client.c                                                      */
/*! \example test-internal-fiot-echo-server.c                                                      */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_fiot.c  */
/* ----------------------------------------------------------------------------------------------- */
