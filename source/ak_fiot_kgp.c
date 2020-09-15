/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2018 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_fiot_kgp.с                                                                             */
/*  - содержит функции, используемые при реализации протокола выработки общих ключей               */
/*     (Key Generation Protocol)                                                                    */
/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_STRING_H
 #include <string.h>
#else
 #error Library cannot be compiled without string.h header
#endif

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_fiot.h>

/* ----------------------------------------------------------------------------------------------- */
 #define requestIdentifierExtensionFlag   ( 0x02uLL )

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция формирует сообщение clientHello и отправляет его в канал связи.
    \details Формирование сообщения происходит во внутреннем буффере контекста,
    предназначенном для отправки сообщений. Отправка сообщения происходит с помощью функции
    ak_fiot_context_write_frame().

    \param fctx Контекст защищенного соединения протокола sp fiot.
    \param extcount Количество расширений, который должны быть посланы после сообщения ClientHello
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха.
    Иначе, возвращается код ошибки.                                                                */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_fiot_context_write_client_hello( ak_fiot fctx, size_t *extcount )
{
  struct wpoint wp;
  int error = ak_error_ok;
  size_t meslen = 0, border = fiot_min_frame_size, csize = 0;
  ak_uint8 *message =  (( ak_uint8 * )fctx->oframe.data ) + fctx->header_offset + 3;

  /* формируем сериализованное представление сообщения clientHello */
  /* 1. криптографический механизм */
   message[meslen++] = ( ak_uint8 )( fctx->mechanism >> 8 )%256;
   message[meslen++] = ( ak_uint8 )( fctx->mechanism )%256;
   border -= 2;

  /* 2. симметричный ключ аутентификации (если определен) */
   if( ak_buffer_is_assigned( &fctx->epsk_id )) {
     ak_uint8 tmp = ( ak_uint8 )fctx->epsk_id.size;
     if( border > ( size_t )( tmp + 3 )) {
       message[meslen++] = ( ak_uint8 )is_present;
       message[meslen++] = ( ak_uint8 )fctx->epsk_type;
       message[meslen++] = tmp;
       memcpy( message+meslen, fctx->epsk_id.data, tmp );
       meslen += tmp;
       border -= ( tmp + 3 );
     } else return ak_error_message_fmt( ak_error_wrong_length, __func__,
                         "using preshared key identifier with very large length (%u bytes)", tmp );
   } else { message[meslen++] = not_present; border--; }

  /* 3. случайные данные */
   if( border < 32 ) return ak_error_message( ak_error_overflow, __func__,
                                                           "insufficient memory for random data" );
   if(( error = ak_random_context_random( &fctx->plain_rnd, message+meslen, 32 )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect generation of random data" );
    else { meslen += 32; border -= 32; }

  /* 4. идентификатор кривой и случайная точка */
   if( border < 1 + 2*( csize = fctx->curve->size*sizeof( ak_uint64 )))
     return ak_error_message( ak_error_overflow, __func__,
                                                  "insufficient memory for elliptic curve point" );
   message[meslen++] = ( ak_uint8 )fctx->curve_id;
   if(( error = ak_random_context_random( &fctx->crypto_rnd,
                                           fctx->secret, sizeof( fctx->secret ))) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect generation of random data" );

   ak_wpoint_pow( &wp, &fctx->curve->point, fctx->secret, fctx->curve->size, fctx->curve );
   ak_wpoint_reduce( &wp, fctx->curve );

  /* копируем координаты точки, жестко записывая их в little endian представлении */
   if(( error = ak_mpzn_to_little_endian( wp.x, fctx->curve->size,
                                               message+meslen, csize, ak_false )) != ak_error_ok )
     return ak_error_message( error, __func__,
                             "incorrect serialization a x-coordinate of elliptic curves's point" );
   meslen += csize;
   if(( error = ak_mpzn_to_little_endian( wp.y, fctx->curve->size,
                                               message+meslen, csize, ak_false )) != ak_error_ok )
     return ak_error_message( error, __func__,
                             "incorrect serialization a y-coordinate of elliptic curves's point" );
   meslen += csize;

  /* 5. указываем количество расширений */
   *extcount = 0;
  /* 1. в режиме использования PSK всегда запрашиваем чужой идентификатор и,
         по возможности, высылаем собственный идентификатор */
   if( ak_buffer_is_assigned( &fctx->epsk_id )) (*extcount)++;
   message[meslen++] = ( ak_uint8 ) *extcount;

  /* подхеширование собранных данных */
   if(( error = ak_mac_context_update( &fctx->comp, message, meslen )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect updating of hash function context" );

  /* отправляем собранное сообщение в канал связи */
   if(( error = ak_fiot_context_write_frame( fctx, message, meslen,
                                                     plain_frame, client_hello )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect writing a clientHello message" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция считывает сообщение clientHello и производит настройку параметров
    контекста сервера.
    \param fctx Контекст защищенного соединения протокола sp fiot.
    \param extcount Количество ожидаемых далее расширений.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха.
    Иначе, возвращается код ошибки.                                                                */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_fiot_context_read_client_hello( ak_fiot fctx, size_t *extcount )
{
  key_type_t kt;
  block_cipher_t bc;
  frame_type_t ftype;
  int error = ak_error_ok;
  integrity_function_t itype;
  crypto_mechanism_t mechanism;
  size_t offset = 0, framelen = 0, meslen = 0, esize = 0, ilen = 0;
  ak_uint8 *frame = NULL, *message = NULL, zero[5] = { 0, 0, 0, 0, 0 }, out[64];

 /* считываем данные */
  if(( frame = ak_fiot_context_read_frame_ptr( fctx, &offset, &framelen, &ftype )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__,
                                                      "incorrect reading of clientHello message" );

 /* начинаем разбор принятого фрейма и настройку криптографических параметров */
  if( ftype != plain_frame )
    return ak_error_message_fmt( fiot_error_frame_type, __func__,
                                "recieving buffer with unexpected frame type (%d)",  (int) ftype );
  if( frame[offset++] != ( ak_uint8 )client_hello )
    return ak_error_message_fmt( fiot_error_frame_format, __func__,
                       "recieving frame with unexpected message type (%d)",  (int) frame[offset] );
  if( memcmp( frame+3, zero, 5 ) != 0 )
    return ak_error_message( fiot_error_frame_number, __func__,
                                          "recieving frame with unexpected value of frame number");

  /* получаем настоящую длину сообщения */
   meslen = (ak_uint32)( frame[ offset++] ) << 8;
   meslen += frame[ offset++ ];
   if( meslen > framelen ) return ak_error_message_fmt( fiot_error_wrong_send_length, __func__,
                                  "recieving frame with unexpected length of clientHello message");
  /* получаем начало сериализованного представления сообщения clientHello */
   message = frame + offset;

  /* здесь начинается разбор криптографических параметров, полученных от клиента */
   mechanism = frame[offset]*256 + frame[offset + 1]; offset += 2;

    /* проверяем допустимость типа ключа */
     if(( kt = ak_fiot_get_key_type( mechanism ) ) == derivative_key ) {
       ak_fiot_context_write_alert_message( fctx, unsupportedCryptoMechanism, NULL, 0 );
       return ak_error_message_fmt( fiot_error_wrong_cipher_type, __func__,
                              "recieving clientHello message with unsupported key type (%u)", kt );
     }
    /* проверяем допустимость алгоритма вычисления имитовставки */
     if(( itype = ak_fiot_get_integrity_function( mechanism )) == undefined_integrity_function ) {
       ak_fiot_context_write_alert_message( fctx, unsupportedCryptoMechanism, NULL, 0 );
       return ak_error_message_fmt( fiot_error_wrong_cipher_type, __func__,
                 "recieving clientHello message with unsupported integrity function (%u)", itype );
     }
    /* проверяем допустимость алгоритма блочного шифрования */
     if(( bc = ak_fiot_get_block_cipher( mechanism )) == undefined_cipher ) {
       ak_fiot_context_write_alert_message( fctx, unsupportedCryptoMechanism, NULL, 0 );
       return ak_error_message_fmt( fiot_error_wrong_cipher_type, __func__,
                           "recieving clientHello message with unsupported cipher type (%u)", bc );
     }

  /* устанавливаем идентификатор psk (если есть) */
   if( frame[offset] == is_present ) {
     if(( error = ak_fiot_context_set_psk_identifier( fctx,
                              frame[offset+1], frame+offset+3, frame[offset+2] )) != ak_error_ok )
       return ak_error_message( fiot_error_wrong_cipher_type, __func__,
                              "recieving clientHello message incorrect preshared key identifier" );
      offset += ( 3 + frame[offset+2] );

   } else {
      if( frame[offset] != not_present ) {
        return ak_error_message_fmt( fiot_error_wrong_cipher_type, __func__,
          "recieving clientHello message with unsupported preshare key flag (%u)", frame[offset] );
      }
      offset++;
   }

  /* теперь мы можем проверить целостность полученного фрейма,
     применяя к контексту сервера полученные из канала связи механизмы */
   if(( error = ak_fiot_context_set_initial_crypto_mechanism( fctx, mechanism )) != ak_error_ok ) {
     ak_fiot_context_write_alert_message( fctx, unsupportedCryptoMechanism, NULL, 0 );
     return ak_error_message( fiot_error_wrong_cipher_type, __func__,
                               "recieving clientHello message with unsupported crypto mechanism" );
   }

  /* проверяем контрольную сумму */
   ilen = fctx->epsk.hsize; /* длина имитовставки */
   ak_mac_context_ptr( &fctx->epsk, frame, framelen - ilen - 2, out );
   if( memcmp( frame + framelen - ilen, out, ilen ) != 0 ) {
     ak_fiot_context_write_alert_message( fctx, wrongIntegrityCode, NULL, 0 );
     return ak_error_message( ak_error_not_equal_data, __func__,
                                       "recieving clientHello message with wrong integrity code" );
   }

  /* продолжаем разбор сообщения: пропускаем случайное число */
   offset += 32;

  /* устанавливаем эллиптическую кривую */
   if((( error = ak_fiot_context_set_curve( fctx, frame[offset] )) != ak_error_ok) ||
      (( esize = ak_fiot_get_point_size( frame[offset] )) == 0 )) {
     ak_fiot_context_write_alert_message( fctx, unsupportedEllipticCurveID, NULL, 0 );
     return ak_error_message_fmt( ak_error_curve_not_supported, __func__,
           "recieving clientHello message with unsupported elliptic curve (0x%x)", frame[offset] );
   }
   offset += 1;

  /* сохраняем точку кривой */
   if(( error = ak_mpzn_set_little_endian( fctx->point.x, fctx->curve->size,
                                               frame+offset, esize, ak_false )) != ak_error_ok ) {
     ak_fiot_context_write_alert_message( fctx, wrongEllipticCurvePoint, NULL, 0 );
     return ak_error_message( error, __func__,
               "recieving clientHello message with wrong x-coordinate of elliptic curve's point" );
   }
   offset += esize;
   if(( error = ak_mpzn_set_little_endian( fctx->point.y, fctx->curve->size,
                                               frame+offset, esize, ak_false )) != ak_error_ok ) {
     ak_fiot_context_write_alert_message( fctx, wrongEllipticCurvePoint, NULL, 0 );
     return ak_error_message( error, __func__,
               "recieving clientHello message with wrong y-coordinate of elliptic curve's point" );
   }
   offset += esize;

   memcpy( fctx->point.z, fctx->curve->point.z, esize );    /* устанавливаем также z-координату */
   if( !ak_wpoint_is_ok( &fctx->point, fctx->curve )) { /* проверяем, что точка лежит на кривой */
     ak_fiot_context_write_alert_message( fctx, wrongEllipticCurvePoint, NULL, 0 );
     return ak_error_message( ak_error_curve_point, __func__,
                              "recieving clientHello message with wrong point of elliptic curve" );
   }

  /* устанавливаем ожидаемое количество расширений */
   *extcount = frame[offset];

  /* подхешируем */
   if(( error = ak_mac_context_update( &fctx->comp, message, meslen )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect updating of hash function context" );

  /* сообщение аудита */
   if( ak_log_get_level() >= fiot_log_standard )
     ak_error_message( ak_error_ok, __func__, "clientHello message accepted" );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция формирует сообщение serverHello и отправляет его в канал связи.
    \details Формирование сообщения происходит во внутреннем буффере контекста,
    предназначенном для отправки сообщений. Отправка сообщения происходит с помощью функции
    ak_fiot_context_write_frame().

    \param fctx Контекст защищенного соединения протокола sp fiot.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха.
    Иначе, возвращается код ошибки.                                                                */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_fiot_context_write_server_hello( ak_fiot fctx, size_t *extcount )
{
  struct wpoint wp;
  int error = ak_error_ok;
  size_t meslen = 0, border = fiot_min_frame_size, csize = 0;
  ak_uint8 *message =  (( ak_uint8 * )fctx->oframe.data ) + fctx->header_offset + 3;

  /* формируем сериализованное представление сообщения serverHello */
  /* 1. криптографический механизм, который будет использован при обмене зашифрованными сообщениями */
   message[meslen++] = ( ak_uint8 )( fctx->policy.mechanism >> 8 )%256;
   message[meslen++] = ( ak_uint8 )( fctx->policy.mechanism )%256;
   border -= 2;

  /* 2. случайные данные */
   if( border < 32 ) return ak_error_message( ak_error_overflow, __func__,
                                                           "insufficient memory for random data" );
   if(( error = ak_random_context_random( &fctx->plain_rnd, message+meslen, 32 )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect generation of random data" );
    else { meslen += 32; border -= 32; }

  /* 3. идентификатор кривой и случайная точка */
   if( border < 1 + 2*( csize = fctx->curve->size*sizeof( ak_uint64 )))
     return ak_error_message( ak_error_overflow, __func__,
                                                  "insufficient memory for elliptic curve point" );
   message[meslen++] = ( ak_uint8 )fctx->curve_id;
   if(( error = ak_random_context_random( &fctx->crypto_rnd,
                                           fctx->secret, sizeof( fctx->secret ))) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect generation of random data" );

  /* так как в контексте уже содержится точка, полученная от клиента,
     то используем временную переменную wp */
   ak_wpoint_pow( &wp, &fctx->curve->point, fctx->secret, fctx->curve->size, fctx->curve );
   ak_wpoint_reduce( &wp, fctx->curve );

  /* копируем координаты точки, жестко записывая их в little endian представлении */
   if(( error = ak_mpzn_to_little_endian( wp.x, fctx->curve->size,
                                               message+meslen, csize, ak_false )) != ak_error_ok )
     return ak_error_message( error, __func__,
                             "incorrect serialization a x-coordinate of elliptic curves's point" );
   meslen += csize;
   if(( error = ak_mpzn_to_little_endian( wp.y, fctx->curve->size,
                                               message+meslen, csize, ak_false )) != ak_error_ok )
     return ak_error_message( error, __func__,
                             "incorrect serialization a y-coordinate of elliptic curves's point" );
   meslen += csize;

  /* 4. указываем количество расширений */
   *extcount = 0;
   /* если был запрос на идентификатор, мы должны ответить */
    if( fctx->extensionFlags&requestIdentifierExtensionFlag ) (*extcount)++;
   message[meslen++] = ( ak_uint8 )*extcount;

  /* подхеширование собранных данных */
   if(( error = ak_mac_context_update( &fctx->comp, message, meslen )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect updating of hash function context" );

  /* отправляем собранное сообщение в канал связи */
   if(( error = ak_fiot_context_write_frame( fctx, message, meslen,
                                                     plain_frame, server_hello )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect writing a serverHello message" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \details Функция вырабатывает ключевую информацию, используемую для шифрования сообщений,
    передаваемых в ходе протокола выработки общих ключей в зашифрованном виде
    от сервера к клиенту.

    В ходе выполнения функции, также, изменяются значения счетчиков фреймов для контекста сервера.

    \param fctx Контекст защищенного соединения протокола sp fiot.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха.
    Иначе, возвращается код ошибки.                                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_create_shts_keys( ak_fiot fctx )
{
  struct mac hctx;
  ak_uint8 out[64];
  struct hmac hmac_ctx;
  int error = ak_error_ok;
  ak_mpzn512 cofactor = ak_mpzn512_one;

 /*! \note удалить позже */
  char str[512];

 /* в начале формируем общую точку Q на эллиптической кривой */
  ak_wpoint_pow( &fctx->point, &fctx->point, fctx->secret, fctx->curve->size, fctx->curve );
  if( fctx->curve->cofactor != 1 ) { /* здесь мы неявно используем тот факт,
                                                   что кофактор не больше 4х */
    cofactor[0] = fctx->curve->cofactor;
    ak_wpoint_pow( &fctx->point, &fctx->point, cofactor, 1, fctx->curve );
  }
  ak_wpoint_reduce( &fctx->point, fctx->curve );

 /* приводим x-координату к последовательности октетов в little endian */
  if(( error = ak_mpzn_to_little_endian( fctx->point.x, fctx->curve->size,
            fctx->point.x, fctx->curve->size*sizeof( ak_uint64 ), ak_false )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect calculation of secret value" );

 /*! \note удалить позже */
  ak_error_message( 0, __func__, "");
  ak_ptr_to_hexstr_static( fctx->point.x, fctx->curve->size*sizeof( ak_uint64 ),
                                                                str, sizeof( str ), ak_false );
  ak_error_message_fmt( 0, "", "Q.x: %s", str );
  /* преобразовывать у-координату не обязательно)) */
  if(( error = ak_mpzn_to_little_endian( fctx->point.y, fctx->curve->size,
            fctx->point.y, fctx->curve->size*sizeof( ak_uint64 ), ak_false )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect calculation of secret value" );
  ak_ptr_to_hexstr_static( fctx->point.y, fctx->curve->size*sizeof( ak_uint64 ),
                                                                str, sizeof( str ), ak_false );
  ak_error_message_fmt( 0, "", "Q.y: %s", str );

 /* формируем временный ключ K = Streebog_{512}( R1 = xQ||ePSK* ) */
  if(( error = ak_mac_context_create_oid( &hctx,
                               ak_oid_context_find_by_name( "streebog512" ))) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect creation of hash function context" );

  if(( error = ak_mac_context_update( &hctx,
                       fctx->point.x, fctx->curve->size*sizeof( ak_uint64 ))) != ak_error_ok ) {
    ak_mac_context_destroy( &hctx );
    return ak_error_message( error, __func__, "incorrect hashing of elliptic curve's point" );
  }

  if( ak_mac_context_is_key_settable( &fctx->epsk )) {
    if(( error = ak_mac_context_update_mac_context_key( &hctx, &fctx->epsk )) != ak_error_ok ) {
      ak_mac_context_destroy( &hctx );
      return ak_error_message( error, __func__, "incorrect hashing of preshared secret key" );
    }
  }

  ak_mac_context_finalize( &hctx, NULL, 0, fctx->secret );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_mac_context_destroy( &hctx );
    return ak_error_message( error, __func__, "incorrect calculation of secret key k" );
  }
  ak_mac_context_destroy( &hctx );

 /*! \note удалить позже */
  ak_ptr_to_hexstr_static( fctx->secret, sizeof( fctx->secret ), str, sizeof( str ), ak_false );
  ak_error_message_fmt( 0, "", "  K: %s", str );

 /* формируем ключевые значения для передачи данных от сервера к клиенту */
  ak_mac_context_finalize( &fctx->comp, NULL, 0, out );
  if(( error = ak_error_get_value()) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong calculation of H1 value" );

  if(( error = ak_hmac_context_create_streebog512( &hmac_ctx )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect creation of hmac context" );
  if(( error = ak_hmac_context_set_key( &hmac_ctx,
                               fctx->secret, sizeof( fctx->secret ), ak_true )) != ak_error_ok ) {
    ak_hmac_context_destroy( &hmac_ctx );
    return ak_error_message( error, __func__, "incorrect assigning of secret key value" );
  }
  ak_hmac_context_ptr( &hmac_ctx, out, sizeof( out ), fctx->server_ts );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_hmac_context_destroy( &hmac_ctx );
    return ak_error_message( error, __func__,
                                      "incorrect calculation of server handshake traffic secret" );
  }
  ak_hmac_context_destroy( &hmac_ctx );

 /* присваиваем ключевые значения */
  if(( error = ak_bckey_context_set_key( &fctx->esfk,
                                                  fctx->server_ts, 32, ak_true )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect assigning of encryption SHTS key" );
  if(( error = ak_mac_context_set_key( &fctx->isfk,
                                               fctx->server_ts+32, 32, ak_true )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect assigning of integrity SHTS key" );

 /* ключи установлены => меняем значения счетчиков */
  if( fctx->role == server_role ) {
    fctx->out_counter.l = 0; /* начинаем с нуля */
    fctx->out_counter.m = 1; /* начинаем передачу шфированной информации */
    fctx->out_counter.n = 0; /* основная ключевая информация CATS и SATS еще не создана */
  }

 /*! \note удалить позже */
  ak_error_message_fmt( 0, __func__, "cipher: %s", fctx->esfk.key.oid->name );
  ak_error_message_fmt( 0, __func__, "integrity engine: %d", fctx->isfk.engine );

  ak_ptr_to_hexstr_static( fctx->server_ts, 32, str, sizeof( str ), ak_false );
  ak_error_message_fmt( 0, "", "eSHTS: %s", str );
  ak_ptr_to_hexstr_static( fctx->server_ts+32, 32, str, sizeof( str ), ak_false );
  ak_error_message_fmt( 0, "", "iSHTS: %s", str );

  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \details Функция вырабатывает ключевую информацию, используемую для шифрования сообщений,
    передаваемых в ходе протокола выработки общих ключей в зашифрованном виде
    от клиента к серверу.

    В ходе выполнения функции, также, изменяются значения счетчиков фреймов для контекста клиента.

    \param fctx Контекст защищенного соединения протокола sp fiot.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха.
    Иначе, возвращается код ошибки.                                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_create_chts_keys( ak_fiot fctx )
{
  ak_uint8 out[64];
  struct hmac hmac_ctx;
  int error = ak_error_ok;

 /*! \note удалить позже */
  char str[512];

 /* формируем ключевые значения для передачи данных от сервера к клиенту */
  ak_mac_context_finalize( &fctx->comp, NULL, 0, out );
  if(( error = ak_error_get_value()) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong calculation of H1 value" );

  if(( error = ak_hmac_context_create_streebog512( &hmac_ctx )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect creation of hmac context" );
  if(( error = ak_hmac_context_set_key( &hmac_ctx,
                               fctx->secret, sizeof( fctx->secret ), ak_true )) != ak_error_ok ) {
    ak_hmac_context_destroy( &hmac_ctx );
    return ak_error_message( error, __func__, "incorrect assigning of secret key value" );
  }
  ak_hmac_context_ptr( &hmac_ctx, out, sizeof( out ), fctx->client_ts );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_hmac_context_destroy( &hmac_ctx );
    return ak_error_message( error, __func__,
                                      "incorrect calculation of server handshake traffic secret" );
  }
  ak_hmac_context_destroy( &hmac_ctx );

 /* присваиваем ключевые значения */
  if(( error = ak_bckey_context_set_key( &fctx->ecfk,
                                                  fctx->client_ts, 32, ak_true )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect assigning of encryption CHTS key" );
  if(( error = ak_mac_context_set_key( &fctx->icfk,
                                               fctx->client_ts+32, 32, ak_true )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect assigning of integrity CHTS key" );

 /* ключи установлены => меняем значения счетчиков */
  if( fctx->role == client_role ) {
    fctx->out_counter.l = 0; /* начинаем с нуля */
    fctx->out_counter.m = 1; /* начинаем передачу шфированной информации */
    fctx->out_counter.n = 0; /* основная ключевая информация CATS и SATS еще не создана */
  }

 /*! \note удалить позже */
  ak_error_message( 0, __func__, "" );
  ak_ptr_to_hexstr_static( fctx->client_ts, 32, str, sizeof( str ), ak_false );
  ak_error_message_fmt( 0, "", "eCHTS: %s", str );
  ak_ptr_to_hexstr_static( fctx->client_ts+32, 32, str, sizeof( str ), ak_false );
  ak_error_message_fmt( 0, "", "iCHTS: %s", str );

  ak_error_message_fmt( 0, __func__, "cipher: %s", fctx->ecfk.key.oid->name );
  ak_error_message_fmt( 0, __func__, "integrity engine: %d", fctx->icfk.engine );

  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция разбирает сообщение AlertMessage и возвращает содержащийся в нем код ошибки.

    \param message Сообщение AlertMessage.
    \param Длина сообщения AlertMessage в байтах.
    \param Имя функции, которое выводится в систему аудита.
    \return Функция возвращает код ошибки, содержащейся в сообщении AlertMessage.                  */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_fiot_context_translate_alert( ak_uint8 *message, size_t meslen, const char *func )
{
  char errstr[256];
  int error = -( message[0]*256 + message[1] );

 /* тип алгоритма: message[2] и message[3] */
  if( message[4] == is_present ) {
     memset( errstr, 0, sizeof( errstr ));
     memcpy( errstr, message + 5, ak_min( 250, meslen - 5 ));
     return ak_error_message_fmt( error, func, "recived alert message [%s]", errstr );
   }
 return ak_error_message( error, func, "recived alert message" );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция считывает сообщение serverHello и производит настройку параметров
    контекста клиента.
    \param fctx Контекст защищенного соединения протокола sp fiot.
    \param extcount Количество ожидаемых далее расширений.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха.
    В случае возникновения ошибки возвращается ее код.                                             */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_fiot_context_read_server_hello( ak_fiot fctx, size_t *extcount )
{
  message_t mtype;
  frame_type_t ftype;
  int error = ak_error_ok;
  ak_uint8 *frame, *message, out[64];
  size_t offset = 0, framelen = 0, meslen = 0, esize = 0, ilen = 0;
  crypto_mechanism_t mechanism;

 /* считываем данные */
  if(( frame = ak_fiot_context_read_frame_ptr( fctx, &offset, &framelen, &ftype )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__,
                                                      "incorrect reading of serverHello message" );
 /* начинаем разбор принятого фрейма и настройку криптографических параметров */
  if( ftype != plain_frame )
    return ak_error_message_fmt( fiot_error_frame_type, __func__,
                                  "recieved buffer has unexpected frame type (%d)",  (int) ftype );

 /* длина и само полученное сообщение */
  mtype = frame[offset++];
  meslen = frame[offset]*256 + frame[offset+1]; offset += 2;
  message = frame + offset;

 /* проверяем то, что получили */
  switch( mtype ) {
    case alert_message:

       return ak_fiot_context_translate_alert( message, meslen, __func__ );
    case server_hello:
      break;

    default: return ak_error_message_fmt( fiot_error_frame_format, __func__,
                                   "recieving frame with unexpected message type (0x%x)",  mtype );
  }

 /* проверяем контрольную сумму полученного фрейма */
  ilen = fctx->epsk.hsize; /* длина имитовставки */
  ak_mac_context_ptr( &fctx->epsk, frame, framelen - ilen - 2, out );
  if( memcmp( frame + framelen - ilen, out, ilen ) != 0 ) {
     ak_fiot_context_write_alert_message( fctx, wrongIntegrityCode, NULL, 0 );
     return ak_error_message( ak_error_not_equal_data, __func__,
                                       "recieving serverHello message with wrong integrity code" );
  }

 /* теперь собственно разборка serverHello */
  mechanism = frame[offset]*256 + frame[offset+1]; offset += 2;

 /* пропускаем random */
  offset += 32;

 /* сравниваем кривые */
  if(( frame[offset] != fctx->curve_id ) ||
      (( esize = ak_fiot_get_point_size( frame[offset] )) == 0 )) {
     ak_fiot_context_write_alert_message( fctx, unsupportedEllipticCurveID, NULL, 0 );
     return ak_error_message_fmt( ak_error_curve_not_supported, __func__,
           "recieving serverHello message with unsupported elliptic curve (0x%x)", frame[offset] );
  }
  offset += 1;

 /* проверяем и сохраняем полученную точку */
  if(( error = ak_mpzn_set_little_endian( fctx->point.x, fctx->curve->size,
                                              frame+offset, esize, ak_false )) != ak_error_ok ) {
    ak_fiot_context_write_alert_message( fctx, wrongEllipticCurvePoint, NULL, 0 );
    return ak_error_message( error, __func__,
              "recieving clientHello message with wrong x-coordinate of elliptic curve's point" );
  }
  offset += esize;
  if(( error = ak_mpzn_set_little_endian( fctx->point.y, fctx->curve->size,
                                              frame+offset, esize, ak_false )) != ak_error_ok ) {
    ak_fiot_context_write_alert_message( fctx, wrongEllipticCurvePoint, NULL, 0 );
    return ak_error_message( error, __func__,
              "recieving clientHello message with wrong y-coordinate of elliptic curve's point" );
  }
  offset += esize;

  memcpy( fctx->point.z, fctx->curve->point.z, esize ); /* устанавливаем также z-координату */
  if( !ak_wpoint_is_ok( &fctx->point, fctx->curve )) {
    ak_fiot_context_write_alert_message( fctx, wrongEllipticCurvePoint, NULL, 0 );
    return ak_error_message( ak_error_curve_point, __func__,
                              "recieving serverHello message with wrong point of elliptic curve" );
   }

 /* устанавливаем ожидаемое количество расширений */
  *extcount = frame[offset];

 /* подхешируем */
  if(( error = ak_mac_context_update( &fctx->comp, message, meslen )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect updating of hash function context" );

 /* устанавливаем криптографические механизмы, полученные от сервера */
  if(( error = ak_fiot_context_set_secondary_crypto_mechanism( fctx, mechanism )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect initialization of secret keys " );

 /* сообщение аудита */
  if( ak_log_get_level() >= fiot_log_standard )
    ak_error_message( ak_error_ok, __func__, "serverHello message accepted" );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция создает расширение RequestIdentifierExtension и отправляет его в канал связи.
    \details

    \param fctx Контекст защищенного соединения протокола sp fiot.
    \param rq Значение поля `request`.
    \param is_identifier_send Флаг, при истинном значении которого, в расширение помещается
    идентификатор абонента. При ложном значении, поле `identifier` остается неопределенным.
    \param ftype Тип фрейма, содержащего расширение (зашифрованный или открытый).
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха.
    В случае возникновения ошибки возвращается ее код.                                             */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_fiot_context_write_request_identifier_extension( ak_fiot fctx,
                                       request_t rq, bool_t is_identifier_send, frame_type_t ftype )
{
  size_t meslen = 0;
  int error = ak_error_ok;
  ak_uint8 *message =  (( ak_uint8 * )fctx->oframe.data ) + fctx->header_offset + 3;

 /* формируем сериализованное представление сообщения RequestIdentifierExtension */
  message[meslen++] = ( ak_uint8 )rq;
  if( is_identifier_send ) {
    /* получено указание на отправку идентифкатора абонета */
     size_t userlen = 0;
     ak_pointer userbuf = NULL;
     switch( fctx->role ) {
      case client_role:  userbuf = fctx->client_id.data; userlen = fctx->client_id.size; break;
      case server_role:  userbuf = fctx->server_id.data; userlen = fctx->server_id.size; break;
      default : return ak_error_message( fiot_error_wrong_role, __func__,
                                                        "using fiot context with undefined role" );
     }
    /* проверяем что данные доступны */
     if( userbuf == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                         "using null pointer to user identifier" );
     if( fctx->oframe.size < userlen + fctx->header_offset + 70 )
                                                     /* константа 70 сформирована следующим образом:
                                                        3 байта  - заголовок сообщения
                                                        1 байт   - значение поля request
                                                        64 байта - максимально допустимый размер контрольной суммы
                                                        2 байта  - боезапас на черный день */
       return ak_error_message( ak_error_wrong_length, __func__,
                                                         "using identifier with very large size" );
     memcpy( message + meslen, userbuf, userlen );
     meslen += userlen;
  }

 /* подхеширование собранных данных */
  if(( error = ak_mac_context_update( &fctx->comp, message, meslen )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect updating of hash function context" );

 /* отправляем собранное сообщение в канал связи */
  if(( error = ak_fiot_context_write_frame( fctx, message, meslen,
                                            ftype, extension_request_identifer )) != ak_error_ok )
    return ak_error_message( error, __func__,
                                       "incorrect writing a requestIdentfierMechanism extension" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_fiot_context_read_extension( ak_fiot fctx )
{
  message_t mtype;
  size_t length = 0;
  ak_uint8 *data = NULL;
  int error = ak_error_ok;
  frame_type_t ftype;

  if(( data = ak_fiot_context_read_frame( fctx, &length, &mtype, &ftype )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__, "incorrect reading an extension" );

 /* проверяем то, что получили */
  switch( mtype ) {
    case alert_message:
      return ak_fiot_context_translate_alert( data, length, __func__ );

    case extension_request_identifer:
       if( !length ) return ak_error_message( ak_error_zero_length, __func__,
                                        "recieving requestIdentifier extension with zero length" );
     /* проверяем, требуется ли ответное расширение с идентификатором */
       if( data[0] == is_requested )
         fctx->extensionFlags = ( fctx->extensionFlags & (~requestIdentifierExtensionFlag )) |
                                                                    requestIdentifierExtensionFlag;
        else if( data[0] != not_requested )
               return ak_error_message( fiot_error_wrong_request_value, __func__,
                            "recieving requestIdentifier extension with incorrect request value" );
      /* проверяем, получили ли мы значение идентификатора */
       if( length > 1 ) {
         ak_buffer id = NULL;
         switch( fctx->role ) {
           case server_role: id = &fctx->client_id; break;
           case client_role: id = &fctx->server_id; break;
           default: return ak_error_message( fiot_error_wrong_role, __func__,
                                                            "using fiot context with wrong role" );
         }
         if( !ak_buffer_is_assigned( id )) { /* идентификатор ранее не определялся */
           if(( error = ak_buffer_set_ptr( id, //&fctx->client_id,
                                                     data+1, length-1, ak_true )) != ak_error_ok )
             return ak_error_message( error, __func__, "incorrect assigning a buffer value" );
         } else /* нам уже задано какое-то значение */
            if(( id->size != length-1 ) ||
               ( ak_ptr_is_equal( id->data, data+1,
                                           ak_min( id->size, length-1 )) != ak_true ))
                 return ak_error_message( fiot_error_wrong_identifier, __func__,
                                                   "recieving an unexpected value of identifier" );
       }
      break;

    case extension_request_certificate:
    case extension_certificate:
    case extension_set_certificate:
    case extension_inform_certificate:
    case extension_key_mechanism:
      return ak_error_message_fmt( fiot_error_frame_format, __func__,
                                    "recieving an unexpected extension (%s)",
                                                                 ak_fiot_get_message_name( mtype));

    default: return ak_error_message_fmt( fiot_error_frame_format, __func__,
                                    "recieving frame with unexpected message type (%s)",
                                                                 ak_fiot_get_message_name( mtype));
  }

  /* подхеширование полученных данных */
   if(( error = ak_mac_context_update( &fctx->comp, data, length )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect updating of hash function context" );

  /* сообщение аудита */
   if( ak_log_get_level() >= fiot_log_standard )
     ak_error_message_fmt( ak_error_ok, __func__, "%s accepted", ak_fiot_get_message_name( mtype ));
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция создает сообщение verifyMessage и отправляет его в канал связи.
    \details Может вызываться как на стороне клиента, так и на стороне сервера.

    \param fctx Контекст защищенного соединения протокола sp fiot.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха.
    В случае возникновения ошибки возвращается ее код.                                             */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_fiot_context_write_verify( ak_fiot fctx )
{
  int error = ak_error_ok;
  size_t meslen = 0;
  ak_uint8 *message =  (( ak_uint8 * )fctx->oframe.data ) + fctx->header_offset + 3, out[64];

 /*! \note здесь удалить */
  char str[512];

  /* формируем сериализованное представление сообщения verifyMessage */
   if( ak_mac_context_is_key_settable( &fctx->epsk )) {
     message[meslen++] = is_present;
     message[meslen++] = 16;

     ak_mac_context_finalize( &fctx->comp, NULL, 0, out );
     if(( error = ak_error_get_value()) != ak_error_ok )
       return ak_error_message( error, __func__, "incorrect hashing of concatenated message" );
     memcpy( message+meslen, out, 16 );
     meslen+= 16;
     message[meslen++] = not_present;
   } else {

      return ak_error_message( ak_error_undefined_function, __func__,
        "realization of digital sign in verify message in not supported, sorry" );

   }

 /*! \note здесь удалить */
  ak_ptr_to_hexstr_static( message, meslen, str, sizeof( str ), ak_false );
  ak_error_message_fmt( 0, __func__, "verify: %s (!)", str );

  /* подхеширование собранных данных */
   if(( error = ak_mac_context_update( &fctx->comp, message, meslen )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect updating of hash function context" );

  /* отправляем собранное сообщение в канал связи */
   if(( error = ak_fiot_context_write_frame( fctx, message, meslen,
                                           encrypted_frame, verify_message )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect writing a verify message" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция считывает из канала связи и проверяет сообщение verifyMessage.
    \details Может вызываться как на стороне клиента, так и на стороне сервера.

    \param fctx Контекст защищенного соединения протокола sp fiot.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае, если сообщение проверено и
    корректно. В случае возникновения ошибки возвращается ее код.                                  */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_fiot_context_read_verify( ak_fiot fctx )
{
  message_t mtype;
  size_t length = 0;
  frame_type_t ftype;
  int error = ak_error_ok;
  ak_uint8 *data = NULL, out[64];


  if(( data = ak_fiot_context_read_frame( fctx, &length, &mtype, &ftype )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__,
                                                           "incorrect reading of verify message" );
 /* проверяем то, что получили */
  switch( mtype ) {
    case alert_message:
       return ak_fiot_context_translate_alert( data, length, __func__ );
    case verify_message:
      break;
    default: return ak_error_message_fmt( fiot_error_frame_format, __func__,
                                      "recieving frame with unexpected message type (%s)",
                                                                ak_fiot_get_message_name( mtype ));
  }

 /* проверяем контрольную сумму */
   if( ak_mac_context_is_key_settable( &fctx->epsk )) {
     if( length != 19 ) return ak_error_message_fmt( ak_error_wrong_length, __func__,
                               "unxpected length of verify message (%u)", ( unsigned int) length );
     if( data[0] != is_present )
       return ak_error_message_fmt( fiot_error_frame_format, __func__,
                                               "unxpected value of present flag (0x%x)", data[0] );
     if( data[1] != 16 )
       return ak_error_message_fmt( ak_error_wrong_length, __func__,
                                            "unxpected length of integrity code (0x%x)", data[1] );
     /* теперь собственно контрольная сумма */
     ak_mac_context_finalize( &fctx->comp, NULL, 0, out );
     if(( error = ak_error_get_value()) != ak_error_ok )
       return ak_error_message( error, __func__, "incorrect hashing of concatenated message" );
     if( memcmp( out, data+2, 16 ) != 0 ) {
       ak_fiot_context_write_alert_message( fctx, wrongIntegrityCode, NULL, 0 );
       return ak_error_message( ak_error_not_equal_data, __func__,
                                                            "unexpected value of integrity code" );
     }
     if( data[18] != not_present )
       return ak_error_message_fmt( fiot_error_frame_format, __func__,
                        "unxpected value of present flag for digital signature (0x%x)", data[18] );
   } else {

      return ak_error_message( ak_error_undefined_function, __func__,
        "realization of digital sign in verify message in not supported, sorry" );

   }

  /* подхеширование полученных данных */
   if(( error = ak_mac_context_update( &fctx->comp, data, length )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect updating of hash function context" );

  /* сообщение аудита */
   if( ak_log_get_level() >= fiot_log_standard )
     ak_error_message( ak_error_ok, __func__, "verify message accepted" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция проверяет настройки контекста защищенного взаимодействия
    перед началом выполнения протокола выработки общих ключей.

    \param fctx Контекст защищенного соединения протокола sp fiot.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха.
    В случае возникновения ошибки возвращается ее код.                                             */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_fiot_context_check_is_ready( ak_fiot fctx )
{
  key_type_t kt = undefined_key;

  switch( fctx->role ) {
   case client_role:
         /* перед стартом протокола клиент должен знать,
            какие алгоритмы будут им использованы для создания сообщения ClientHello */
           if( fctx->mechanism == not_set_mechanism )
             return ak_error_message( fiot_error_wrong_mechanism, __func__,
                                                  "fiot context has undefined crypto mechanism" );
          /* при старте протокола допускаются только три типа ключей:
              - неопределенные (с использованием функции хеширования),
              - предварительные симметричные,
              - симметричные, выработанные в ходе другой сессии протокола
                (производные ключи должны использоваться для передачи шифрованной информации) */
           if(( kt = ak_fiot_get_key_type( fctx->mechanism )) == derivative_key )
             return ak_error_message_fmt( fiot_error_wrong_mechanism, __func__,
                                "using a constant with unsupported key type (key type: %x)", kt );

          /* перед началом протокола контекст клиента должен находиться в состоянии rts_client_hello */
           if( fctx->state != rts_client_hello )
             return ak_error_message_fmt( fiot_error_wrong_state, __func__,
                                     "fiot context has undefined state value (%d)", fctx->state );
           break;

   case server_role:
         /* перед стартом протокола сервер должен определиться,
            какие алгоритмы будут им использованы для передачи зашифрованной информации */
           if( fctx->mechanism == not_set_mechanism ) fctx->mechanism = kuznechikCTRplusGOST3413;

          /* перед началом протокола контекст сервера должен находиться в состоянии wait_client_hello */
           if( fctx->state != wait_client_hello )
             return ak_error_message_fmt( fiot_error_wrong_state, __func__,
                                     "fiot context has undefined state value (%d)", fctx->state );
           break;

   default : return ak_error_message( fiot_error_wrong_role, __func__,
                                                       "using fiot context with undefined role" );
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \details Функция определяет значения переменных SATS и CATS, которые используется для выработки
    производных ключей шифрования и имитозащиты в ходе защищенного обмена сообщениями.

    В ходе выполнения функции, также, изменяются значения счетчиков фреймов для контекстов
    клиента и сервера.

    \param fctx Контекст защищенного соединения протокола sp fiot.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха.
    В случае возникновения ошибки возвращается ее код.                                             */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_create_ats_keys( ak_fiot fctx )
{
  struct mac ctx;
  ak_uint8 a0[64], an[64]; /* временные переменные */
  int error = ak_error_ok;

 /*! \note удалить позже */
  char str[512];
  ak_error_message( 0, __func__, "");
  ak_ptr_to_hexstr_static( fctx->point.x, fctx->curve->size*sizeof( ak_uint64 ),
                                                                str, sizeof( str ), ak_false );
  ak_error_message_fmt( 0, "", "Q.x:  %s", str );
  ak_ptr_to_hexstr_static( fctx->point.y, fctx->curve->size*sizeof( ak_uint64 ),
                                                                str, sizeof( str ), ak_false );
  ak_error_message_fmt( 0, "", "Q.y:  %s", str );

  ak_ptr_to_hexstr_static( fctx->client_id.data, fctx->client_id.size, str, sizeof( str ), ak_false );
  ak_error_message_fmt( 0, "", "clientID: %s", str );
  ak_ptr_to_hexstr_static( fctx->server_id.data, fctx->server_id.size, str, sizeof( str ), ak_false );
  ak_error_message_fmt( 0, "", "serverID: %s", str );

 /* вычисляем значение долговременного ключа T = HMAC_{512}( x(Q), R2 =  )формируем сообщение R2 */
  if(( error = ak_mac_context_create_oid( &ctx,
                               ak_oid_context_find_by_name( "hmac-streebog512" ))) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect creation of hmac context" );

  if(( error = ak_mac_context_set_key( &ctx, fctx->point.x,
                   fctx->curve->size*sizeof( ak_uint64 ), ak_true )) != ak_error_ok ) goto labexit;

  /* добавляем ID_s (идентификатор сервера) */
  if(( error = ak_mac_context_update( &ctx, fctx->server_id.data,
                                             fctx->server_id.size )) != ak_error_ok ) goto labexit;
  /* если определен, добавляем ID_c (идентификатор клиента) */
  if( ak_buffer_is_assigned( &fctx->client_id ))
    if(( error = ak_mac_context_update( &ctx, fctx->client_id.data,
                                             fctx->client_id.size )) != ak_error_ok ) goto labexit;
  /* если определен, добавляем значение предварительно распределенного ключа */
  if( ak_mac_context_is_key_settable( &fctx->epsk ))
    if(( error = ak_mac_context_update_mac_context_key( &ctx,
                                                      &fctx->epsk )) != ak_error_ok ) goto labexit;
  ak_mac_context_finalize( &ctx, NULL, 0, fctx->secret );
  if(( error = ak_error_get_value()) != ak_error_ok ) goto labexit;

 /*! \note удалить позже */
  ak_ptr_to_hexstr_static( fctx->secret, sizeof( fctx->secret ), str, sizeof( str ), ak_false );
  ak_error_message_fmt( 0, "", "   T: %s", str );

  if(( error = ak_mac_context_set_key( &ctx,
                   fctx->secret, sizeof( fctx->secret ), ak_true ))  != ak_error_ok ) goto labexit;
  ak_mac_context_clean( &ctx );

 /* вычисляем A0, A1 и A2 */
  ak_mac_context_finalize( &fctx->comp, NULL, 0, a0 );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation of A0 variable" );
    goto labexit;
  }

 /* вычисляем A1 и CATS */
  ak_mac_context_clean( &ctx);
  ak_mac_context_finalize( &ctx, a0, sizeof( a0 ), an );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation of A1 variable" );
    goto labexit;
  }

  ak_mac_context_clean( &ctx);
  if(( error = ak_mac_context_update( &ctx, an, sizeof( an ))) != ak_error_ok ) goto labexit;
  ak_mac_context_finalize( &ctx, a0, sizeof( a0 ), fctx->client_ts );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation of CATS shared secret" );
    goto labexit;
  }

 /* вычисляем A2 и SATS */
  ak_mac_context_clean( &ctx);
  ak_mac_context_finalize( &ctx, an, sizeof( an ), an );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation of A2 variable" );
    goto labexit;
  }

  ak_mac_context_clean( &ctx);
  if(( error = ak_mac_context_update( &ctx, an, sizeof( an ))) != ak_error_ok ) goto labexit;
  ak_mac_context_finalize( &ctx, a0, sizeof( a0 ), fctx->server_ts );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation of SATS shared secret" );
    goto labexit;
  }

 /*! \note удалить позже */
  ak_ptr_to_hexstr_static( fctx->client_ts, 64, str, sizeof( str ), ak_false );
  ak_error_message_fmt( 0, "", "CATS: %s", str );
  ak_ptr_to_hexstr_static( fctx->server_ts, 64, str, sizeof( str ), ak_false );
  ak_error_message_fmt( 0, "", "SATS: %s", str );

 /* ключи созданы => меняем значения счетчиков */
  fctx->in_counter.l = fctx->out_counter.l = 0;     /* начинаем с нуля */
  fctx->in_counter.m = fctx->out_counter.m = 0;     /* начинаем с нуля */
    /* ключевая информация CATS и SATS и производные ключи уже созданы */
  fctx->in_counter.n = fctx->out_counter.n = 1;

 /* вырабатываем производные ключи (их значения зависят от значений счетчиков) */
  if(( error = ak_fiot_context_create_next_derivative_keys( fctx, direct_out )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect calculation of output derivative keys" );
  if(( error = ak_fiot_context_create_next_derivative_keys( fctx, direct_in )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect calculation of input derivative keys" );

 /* уничтожаем контекст */
 labexit:
  ak_ptr_wipe( a0, sizeof( a0 ), &fctx->plain_rnd, ak_true );
  ak_ptr_wipe( an, sizeof( an ), &fctx->plain_rnd, ak_true );
  ak_mac_context_destroy( &ctx );
  if( error != ak_error_ok ) ak_error_message( error, __func__,
                              "incorrect calculation of SATA and CATS shared secret information" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Это основная процедура, в которой описываются все возможные состояния контекста
    защищенного взаимодействия как для клиента, так и для сервера.

    \param fctx Контекст защищенного соединения протокола sp fiot.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха.
    В случае возникновения ошибки возвращается ее код.                                             */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_keys_generation_protocol( ak_fiot fctx )
{
  size_t i, extcount = 0;
  int error = ak_error_ok;

 /* запуск функции проверки состояния контекста:  */
  if(( error = ak_fiot_context_check_is_ready( fctx )) != ak_error_ok )
    return ak_error_message( error, __func__, "fiot context has incorrect parameters" );

 /* теперь основной цикл, реализующий протокол выработки общих ключей */
  do{
      switch( fctx->state ) {
       /* реализуем возможные состояния клиента */
        case rts_client_hello:
           if(( error = ak_fiot_context_write_client_hello( fctx, &extcount )) != ak_error_ok )
             return ak_error_message( error, __func__, "incorrect sending clientHello message" );
           fctx->state = rts_client_extension;
          break;


       /* клиент отправляет расширения
        * выбор того, что отправляем аналогичен процедуре из clientHello */
        case rts_client_extension:
          /* 1. в режиме использования PSK всегда запрашиваем чужой идентификатор и,
                по возможности, высылаем собственный идентификатор */
          if( ak_buffer_is_assigned( &fctx->epsk_id )) {
            if(( error = ak_fiot_context_write_request_identifier_extension( fctx, is_requested,
                        ak_buffer_is_assigned( &fctx->client_id ), plain_frame )) != ak_error_ok )
                                  /* поскольку мы запрашиваем идентификатор сервера,
                                     то при приеме расширений от сервера мы обязаны его получить */
              return ak_error_message( error, __func__,
                                                 "incorrect sending requestIdentifier extension" );
            extcount--;
          }
          if( extcount == 0 ) fctx->state = wait_server_hello;
            else return ak_error_message( ak_error_undefined_value, __func__,
              "count of sended extensions not equal to value, containing in clientHello message" );
          break;


        case wait_server_hello:
           if(( error = ak_fiot_context_read_server_hello( fctx, &extcount )) != ak_error_ok )
             return ak_error_message( error, __func__, "incorrect reading serverHello message" );
          /* вырабатываем ключи, используемые для шифрования сообщений, отправляемых сервером клиенту */
           if(( error = ak_fiot_context_create_shts_keys( fctx )) != ak_error_ok )
             return ak_error_message( error, __func__,
                                         "incorrect creation of handshake traffic secret keys" );
           fctx->state = wait_server_extension;
          break;


        case wait_server_extension:
           for( i = 0; i < extcount; i++ ) {
             if(( error = ak_fiot_context_read_extension( fctx )) != ak_error_ok )
               return ak_error_message( error, __func__, "incorrect reading an extension" );
           }
           fctx->state = wait_server_verify;
          break;


        case wait_server_verify:
           if(( error = ak_fiot_context_read_verify( fctx )) != ak_error_ok )
             return ak_error_message( error, __func__, "incorrect reading verify message" );
          /* вырабатываем ключи, используемые для шифрования сообщений, отправляемых клиентом серверу */
           if(( error = ak_fiot_context_create_chts_keys( fctx )) != ak_error_ok )
             return ak_error_message( error, __func__,
                                         "incorrect creation of handshake traffic secret keys" );
           fctx->state = rts_client_extension2;
          break;


        case rts_client_extension2:
         /* отвечаем на запрос сервера об отправке идентификатора клиента */
          if( fctx->extensionFlags&requestIdentifierExtensionFlag ) {
            if( !ak_buffer_is_assigned( &fctx->client_id ))
              return ak_error_message( fiot_error_wrong_identifier, __func__,
                                                             "running client without identifier" );
            if(( error = ak_fiot_context_write_request_identifier_extension( fctx, not_requested,
                                                      ak_true, encrypted_frame )) != ak_error_ok )
              return ak_error_message( error, __func__,
                                                 "incorrect sending requestIdentifier extension" );
            fctx->extensionFlags = fctx->extensionFlags&( ~requestIdentifierExtensionFlag );
          }
          fctx->state = rts_client_verify;
          break;


        case rts_client_verify:
           if(( error = ak_fiot_context_write_verify( fctx )) != ak_error_ok )
             return ak_error_message( error, __func__, "incorrect sending serverVerify message" );
           fctx->state = wait_server_application_data;
          break;


       /* реализуем возможные состояния сервера */
        case wait_client_hello:
           if(( error = ak_fiot_context_read_client_hello( fctx, &extcount )) != ak_error_ok )
             return ak_error_message( error, __func__, "incorrect reading clientHello message" );
           fctx->state = wait_client_extension;
          break;


        case wait_client_extension:
           for( i = 0; i < extcount; i++ ) {
             if(( error = ak_fiot_context_read_extension( fctx )) != ak_error_ok )
               return ak_error_message( error, __func__, "incorrect reading an extension" );
           }
           fctx->state = rts_server_hello;
          break;


        case rts_server_hello:
          /* отправляем сообщение */
           if(( error = ak_fiot_context_write_server_hello( fctx, &extcount )) != ak_error_ok )
             return ak_error_message( error, __func__, "incorrect sending serverHello message" );
           if(( error = ak_fiot_context_set_secondary_crypto_mechanism( fctx,
                                                      fctx->policy.mechanism )) != ak_error_ok )
             return ak_error_message( error, __func__, "incorrect creation of secret keys" );
          /* вырабатываем ключи, используемые для шифрования сообщений, отправляемых сервером клиенту */
           if(( error = ak_fiot_context_create_shts_keys( fctx )) != ak_error_ok )
             return ak_error_message( error, __func__,
                                         "incorrect creation of handshake traffic secret keys" );
           fctx->state = rts_server_extension;
          break;


        case rts_server_extension:
         /* отвечаем на запрос клиента об отправке идентификатора сервера */
          if( fctx->extensionFlags&requestIdentifierExtensionFlag ) {
            request_t request = is_requested;
            if( !ak_buffer_is_assigned( &fctx->server_id ))
              return ak_error_message( fiot_error_wrong_identifier, __func__,
                                                             "running server without identifier" );
            if( ak_buffer_is_assigned( &fctx->client_id )) {
              request = not_requested;
              fctx->extensionFlags = fctx->extensionFlags&( ~requestIdentifierExtensionFlag );
            }
            if(( error = ak_fiot_context_write_request_identifier_extension( fctx, request,
                                                      ak_true, encrypted_frame )) != ak_error_ok )
              return ak_error_message( error, __func__,
                                                 "incorrect sending requestIdentifier extension" );
            extcount--;
          }

          if( extcount == 0 ) fctx->state = rts_server_verify;
            else return ak_error_message( ak_error_undefined_value, __func__,
              "count of sended extensions not equal to value, containing in serverHello message" );
          break;


        case rts_server_verify:
           if(( error = ak_fiot_context_write_verify( fctx )) != ak_error_ok )
             return ak_error_message( error, __func__, "incorrect sending serverVerify message" );
          /* вырабатываем ключи, используемые для шифрования сообщений, отправляемых клиентом серверу */
           if(( error = ak_fiot_context_create_chts_keys( fctx )) != ak_error_ok )
             return ak_error_message( error, __func__,
                                         "incorrect creation of handshake traffic secret keys" );
           fctx->state = wait_client_extension2;
          break;


        case wait_client_extension2:
           if( fctx->extensionFlags&requestIdentifierExtensionFlag ) {
             if(( error = ak_fiot_context_read_extension( fctx )) != ak_error_ok )
               return ak_error_message( error, __func__, "incorrect reading an extension" );
             fctx->extensionFlags = fctx->extensionFlags&( ~requestIdentifierExtensionFlag );
           }
           fctx->state = wait_client_verify;
          break;


        case wait_client_verify:
           if(( error = ak_fiot_context_read_verify( fctx )) != ak_error_ok )
             return ak_error_message( error, __func__, "incorrect reading verify message" );
           fctx->state = wait_client_application_data;
          break;


        default: /* нежданное состояние абонента */
          return ak_error_message( error, __func__, "unsupported internal state of fiot context" );
      }
  } while(( fctx->state != wait_client_application_data ) &&
                ( fctx->state != wait_server_application_data ));

 /* перед завершением протокола вырабатываем общую ключевую информацию */
 return ak_fiot_context_create_ats_keys( fctx );
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                  ak_fiot_kgp.c  */
/* ----------------------------------------------------------------------------------------------- */
