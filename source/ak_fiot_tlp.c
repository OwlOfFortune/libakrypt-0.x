/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2018 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_fiot_tlp.с                                                                             */
/*  - содержит функции, реализующие транспортный протокол (Transport Layer Protocol)               */
/*     защищенного криптографического взаимодействия.                                              */
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
#ifdef LIBAKRYPT_HAVE_SYSSELECT_H
 #include <sys/select.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_fiot.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \param fctx Контекст защищенного соединения протокола sp fiot.
    \param direct Тип ключей, которые будут изменены. Значение \ref direct_out говорит о том, что
    будут изменены ключи для шифрования и имитозащиты исходящих фреймов информации, значение \ref direct_in -
    о том, что будут изменены ключи для расшифрования и проверки имитовставки входящих вреймов.

    \note Точное значение того, какие ключи будут изменены, зависит от роли абонента.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха.
    Иначе, возвращается код ошибки.                                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_create_next_derivative_keys( ak_fiot fctx , direct_t direct )
{
  char *ds = NULL;
  ak_mac ikey = NULL;
  size_t m = 0, n = 0;
  ak_bckey ekey = NULL;
  int error = ak_error_ok;
  ak_uint64 ivec[4];
  ak_uint8 i = 0, key[32], key2[32], *ats = NULL;
  ak_uint8 dconst[32] = {
   0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
   0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F };

 /*! \note удалить позже */
  char str[512];

 /* определяемся с указателями на модифицируемые ключи */
  switch( direct ) {
    case direct_out:
        ds = "outcomming";
        m = fctx->out_counter.m;
        n = fctx->out_counter.n;
        if( fctx->role == client_role ) {
          ekey = &fctx->ecfk; ikey = &fctx->icfk; ats = fctx->client_ts;
         }  else {
             ekey = &fctx->esfk; ikey = &fctx->isfk; ats = fctx->server_ts;
            }
      break;
    case direct_in:
        ds = "incomming";
        m = fctx->in_counter.m;
        n = fctx->in_counter.n;
        if( fctx->role == client_role ) {
          ikey = &fctx->isfk; ekey = &fctx->esfk; ats = fctx->server_ts;
         }  else {
             ikey = &fctx->icfk; ekey = &fctx->ecfk; ats = fctx->client_ts;
            }
      break;
  }

 /* формируем константу для зашифрования - данная последовательность зависит значения счетчика m */
  if( ekey->bsize == 8 )
    for( i = 0; i < 4; i++ ) {
      #ifndef LIBAKRYPT_LITTLE_ENDIAN
        ivec[i] = bswap_64( 0xFFFFFFFF00000000LL + ( 4*m + i ));
      #else
        ivec[i] = 0xFFFFFFFF00000000LL + ( 4*m + i );
      #endif
    }
   else {
      #ifndef LIBAKRYPT_LITTLE_ENDIAN
        ivec[0] = bswap_64( 2*m );
        ivec[2] = bswap_64( 2*m + 1 );
      #else
        ivec[0] = 2*m;
        ivec[2] = 2*m + 1;
      #endif
        ivec[1] = ivec[3] = 0xFFFFFFFFFFFFFFFFLL;
   }

  /*! \note удалить позже */
   ak_ptr_to_hexstr_static( ivec, 32, str, 512, ak_false );
   ak_error_message_fmt( 0, __func__, "ivec: %s", str );


 /* формируем значение ключа шифрования eC(S)FK */
  if( m == 0 ) memcpy( key, ats, 32 );
    else {
      if(( error = ak_bckey_context_encrypt_ecb( ekey,
                                                    dconst, key, sizeof( key ))) != ak_error_ok ) {
        ak_error_message_fmt( error, __func__,
                          "incorrect generation %s encryption key for indices [%u,%u]", ds, m, n );
        goto labexit;
      }
    } /* теперь в переменной key находится нужное значение */

  /* устанавливаем значение ключа C(S)K_n */
   if(( error = ak_bckey_context_set_key( ekey, ats+32, 32, ak_true )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect setting temporary integrity key" );
     goto labexit;
   }
  /* зашифровываем константу и вычисляем значение iC(S)FK */
   if(( error = ak_bckey_context_encrypt_ecb( ekey, ivec, key2, sizeof( key2 ))) != ak_error_ok ) {
     ak_error_message_fmt( error, __func__,
                          "incorrect generation %s integrity key for indices [%u,%u]", ds, m, n );
     goto labexit;
   }

  /*! \note удалить позже */
  ak_ptr_to_hexstr_static( key, 32, str, 512, ak_false );
  ak_error_message_fmt( 0, __func__, "eC(S)FK: %s [%s]", str, ds );
  ak_ptr_to_hexstr_static( key2, 32, str, 512, ak_false );
  ak_error_message_fmt( 0, __func__, "iC(S)FK: %s [%s]", str, ds );

  /* устанавливаем значение ключа eC(S)FK */
   if(( error = ak_bckey_context_set_key( ekey, key, sizeof( key ), ak_true )) != ak_error_ok ) {
     ak_error_message_fmt( error, __func__,
                        "incorrect assigning of %s encryption key for indices [%u,%u]", ds, m, n );
     goto labexit;
   }
  /* устанавливаем значение ключа iC(S)FK */
   if(( error = ak_mac_context_set_key( ikey, key2, sizeof( key2 ), ak_true )) != ak_error_ok ) {
     ak_error_message_fmt( error, __func__,
                        "incorrect assigning of %s integrity key for indices [%u,%u]", ds, m, n );
     goto labexit;
   }

 labexit:
  /* очищаем память, в которой находились выработанные ключи */
   ak_ptr_wipe( key, 32, &ekey->key.generator, ak_true );
   ak_ptr_wipe( key2, 32, &ekey->key.generator, ak_true );

  if(( error == ak_error_ok ) && ( ak_log_get_level() >= ak_log_standard ))
    ak_error_message_fmt( ak_error_ok, __func__,
                                    "generation of %s keys for indices [%u,%u] is Ok", ds, m, n );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param fctx Контекст защищенного соединения протокола sp fiot.
    \param direct Тип ключевой информации, которая будет изменена.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха.
    Иначе, возвращается код ошибки.                                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_create_next_ats_keys( ak_fiot fctx , direct_t direct )
{
  struct mac ctx;
  char *ds = NULL;
  struct hmac hctx;
  size_t n = 0, nsize = 0;
  int error = ak_error_ok;
  ak_uint8 *ats = NULL, nlen[3] = { 0, 0, 0 };

 /*! \note удалить позже */
  char str[512];


 /* определяемся с указателями на модифицируемые ключи */
  switch( direct ) {
    case direct_out:
        ds = "outcomming";
        n = fctx->out_counter.n;
        if( fctx->role == client_role ) ats = fctx->client_ts;
          else ats = fctx->server_ts;
      break;
    case direct_in:
        ds = "incomming";
        n = fctx->in_counter.n;
        if( fctx->role == client_role ) ats = fctx->server_ts;
         else ats = fctx->client_ts;
      break;
  }

  if(( error = ak_hmac_context_create_streebog512( &hctx )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect creation of hmac context" );
  if(( error = ak_mac_context_create_hmac( &ctx, &hctx )) != ak_error_ok ) {
    ak_hmac_context_destroy( &hctx );
    return ak_error_message( error, __func__, "incorrect creation of mac context" );
  }
  if(( error != ak_mac_context_set_key( &ctx,
                               fctx->secret, sizeof( fctx->secret ), ak_true )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__, "incorrect assigning %s secret key value", ds );
    goto labexit;
  }

 /* теперь собственно вырабатываем значение ключа */
  if( n > 255 ) {
    nlen[0] = ( ak_uint8 )((n >> 8)%256 );
    nlen[1] = ( ak_uint8 )( n%256 );
    nsize = 2;
  } else {
      nlen[0] = ( ak_uint8 )( n%256 );
      nsize = 1;
    }
  if(( error = ak_mac_context_update( &ctx, ats, 64 )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect updating mac context with n value" );
    goto labexit;
  }
  ak_mac_context_finalize( &ctx, nlen, nsize, ats );
  if(( error = ak_error_get_value( )) != ak_error_ok )
    ak_error_message( error, __func__,
                              "incorrect finalizing mac context with application traffic secret" );
  labexit:
   ak_hmac_context_destroy( &hctx );
   ak_mac_context_destroy( &ctx );

  /*! \note удалить позже */
   ak_ptr_to_hexstr_static( ats, 64, str, 512, ak_false );
   ak_error_message_fmt( 0, __func__, "\nATS: %s [%s]", str, ds );

  if(( error == ak_error_ok ) && ( ak_log_get_level() >= ak_log_standard ))
    ak_error_message_fmt( ak_error_ok, __func__,
                         "generation of %s application traffic secret for index %u is Ok", ds, n );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Изменение текущего значения счетчиков.
    \details Функция увеличивает значения счетчиков и проверяет их значения на соответствие
    текущим ограничениям. Если значения счетчиков выходят за допустимые значения -
    вырабатываются новые ключевые значения.

    \param fctx Контекст защищенного соединения протокола sp fiot.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха.
    Иначе, возвращается код ошибки.                                                                */
/* ----------------------------------------------------------------------------------------------- */
 static inline int ak_fiot_context_increment_counters( ak_fiot fctx )
{
  int error = ak_error_ok;

  if(( ++fctx->out_counter.l ) >= fctx->policy.restrictions.maxFrameCount ) {
    fctx->out_counter.l = 0;
    if(( ++fctx->out_counter.m ) >= fctx->policy.restrictions.maxFrameKeysCount ) {

      fctx->out_counter.m = 0;
      if( ++fctx->out_counter.n > fctx->policy.restrictions.maxApplicationSecretCount ) {
        /* здесь мы должны заблокировать взаимодействие и перейти к процедуре выработки нового
           сеанса криптографического взаимодействия */

      } else {
         /* здесь мы должны выработать новое значение ключевой информации SATS и CAST,
            а также инициализировать зависящие от них ключи eC(S)FK и iC(S)FK */
          if(( error = ak_fiot_context_create_next_ats_keys( fctx, direct_out )) != ak_error_ok  )
            return ak_error_message( error, __func__, "wrong CATS и SATS keys generation" );
          if(( error = ak_fiot_context_create_next_derivative_keys( fctx,
                                                                    direct_out )) != ak_error_ok )
            return ak_error_message( error, __func__, "wrong derivative keys increment" );
        }
    } else {
       /* здесь мы должны выработать новую пару производных ключей eC(S)FK и iC(S)FK */
        if(( error = ak_fiot_context_create_next_derivative_keys( fctx,
                                                                    direct_out )) != ak_error_ok )
          return ak_error_message( error, __func__, "wrong derivative keys increment" );
      }
  }
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция сериализует значения счетчиков в заголовок фрейма.
    \param fctx Контекст защищенного соединения протокола sp fiot.
    \param oframe Область памяти, в которую помещаются значения счетчиков.
    \return Функция не возвращает значений.                                                        */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_fiot_context_write_counters( ak_fiot fctx, ak_uint8 *oframe )
{
   oframe[0] = ( ak_uint8 )(( fctx->out_counter.n )%256 );
   oframe[1] = ( ak_uint8 )((( fctx->out_counter.m ) >> 8)%256 );
   oframe[2] = ( ak_uint8 )(( fctx->out_counter.m )%256 );
   oframe[3] = ( ak_uint8 )((( fctx->out_counter.l ) >> 8)%256 );
   oframe[4] = ( ak_uint8 )(( fctx->out_counter.l )%256 );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция получает значения счетчиков из заголовока фрейма. При необхоимости
    производится выработка производных ключей.
    \param fctx Контекст защищенного соединения протокола sp fiot.
    \param frame Область памяти, из которой считываются значения счетчиков.

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха.
    Иначе, возвращается код ошибки.                                                                */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_fiot_context_read_counters( ak_fiot fctx, ak_uint8 *inframe )
{
  int error = ak_error_ok;
  size_t n = inframe[0], m = inframe[1]*256 + inframe[2], l = inframe[3]*256 + inframe[4];

  if( n > 0 ) { /* преобразование ключевой информации производится только для прикладного протокола */
    if( n > fctx->in_counter.n ) {
      fctx->in_counter.l = l;
      fctx->in_counter.m = m;
      fctx->in_counter.n = n;
     /* здесь мы должны выработать новое значение ключевой информации SATS и CAST,
        а также инициализировать зависящие от них ключи eC(S)FK и iC(S)FK */
      if(( error = ak_fiot_context_create_next_ats_keys( fctx, direct_in )) != ak_error_ok  )
        return ak_error_message( error, __func__, "wrong CATS и SATS keys generation" );
      if(( error = ak_fiot_context_create_next_derivative_keys( fctx, direct_in )) != ak_error_ok )
        return ak_error_message( error, __func__, "wrong derivative keys increment" );
      return ak_error_ok;
    } else {
        if( m > fctx->in_counter.m ) {
          fctx->in_counter.l = l;
          fctx->in_counter.m = m;
         /* здесь мы должны выработать новую пару производных ключей eC(S)FK и iC(S)FK */
          if(( error = ak_fiot_context_create_next_derivative_keys( fctx, direct_in )) != ak_error_ok )
            return ak_error_message( error, __func__, "wrong derivative keys increment" );
          return ak_error_ok;
        }
    }
  }
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \details Эта функция самого нижнего уровня - она в явном виде получает отправляемые в канал
    данные, формирует сообщение, если необходимо - дополнение, вычисляет имитовставку и
    зашифровывает сообщение.

    В заголовок сообщения могут быть помещены дополнительные данные.
    Размер таких данных определяется величиной `fctx->header_offset - 8`, где 8 это длина
    стандартного заголовка.
    Сами данные должны располагаться в буффере `fctx->header_data` и устанавливаться до вызова
    данной функции. В случае, если данные в `fctx->header_data` не определены, то
    длина заголовка полагается равной 8.

    \param fctx Контекст защищенного соединения протокола sp fiot.
    Контекст должен быть предварительно создан, а ключевые значения инициализированы.
    \param data Данные, которые помещаются во фрейм и отправляются в канал связи через интрефейс,
    обеспечивающий шифрование информации.
    \param datalen Размер отправляемых данных в байтах.
    \param ftype Тип формируемого фрейма данных
    (данные передаются в зашифрованном или открытом виде)
    \param mtype Тип передаваемых данных

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха.
    Иначе, возвращается код ошибки.                                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_write_frame( ak_fiot fctx,
                             ak_pointer data, size_t datalen, frame_type_t ftype, message_t mtype )
{
   ak_mac ikey = NULL;
   ak_bckey ekey = NULL;
   int error = ak_error_ok;
   ak_uint8 *oframe = NULL;
   size_t ilen = 0, olen = 0, framelen = 0, offset = 0;

  /* выполняем минимальные проверки */
   if( fctx->iface_enc == undefined_interface ) return fiot_error_wrong_interface;
   if( datalen < 1 ) return ak_error_zero_length; /* мы отправляем хотя бы один байт информации */

  /* определяем размер имитовставки */
   if( ftype == plain_frame ) ikey = &fctx->epsk;
    else {
          switch( fctx->role ) {
           /* пишем своими ключами, читаем чужими */
            case client_role: ikey = &fctx->icfk; ekey = &fctx->ecfk; break;
            case server_role: ikey = &fctx->isfk; ekey = &fctx->esfk; break;
            default: return fiot_error_wrong_role;
          }
         }
   ilen = ikey->hsize;
  /* определяем минимальный размер сообщения
      framelen - полная длина фрейма,
      olen - длина фрейма без дополнения */
   olen = framelen = fctx->header_offset /* заголовок */
                   + 3 /* истинная длина сообщения + его тип */
                   + datalen /* собственно данные */
                   + 2 /* признак наличия имитовставки + ее длина */
                   + ilen; /* имитовставка */
  /* проверяем, что минимальный разме фрейма удовлетворяет допустимым ограничениям на размер */
   if( framelen > fctx->oframe.size ) return fiot_error_wrong_send_length;

  /* увеличиваем длину фрейма за счет паддинга */
  /*! \note Сейчас при реализации дополнения фрейма используется политика по-умолчанию,
     при которой общая длина фрейма должна быть кратной 16 байтам, если этого сделать
     нельзя, то мы откатываемся назад. Необходимо реализовать все возможные политики в
     соответствии с методическими рекомендациями. */
   if( framelen%16 != 0 ) {
     framelen = ( 1+ ( framelen>>4 )) <<4;
     if( framelen > fctx->oframe.size ) framelen = olen;
   }
  /* теперь собираем фрейм по кусочкам */
   oframe = fctx->oframe.data;

  /* тип фрейма и размер заголовка */
   oframe[0] = ( ak_uint8 )(( fctx->header_offset << 2 ) + ftype );

  /* размер фрейма */
   oframe[1] = ( ak_uint8 )(( framelen >> 8 )%256 );
   oframe[2] = ( ak_uint8 )( framelen%256 );

  /* сериализуем номер фрейма */
   ak_fiot_context_write_counters( fctx, oframe + 3 );

  /* если fctx->header_offset > 8, то добавляем дополнительные данные в заголовок пакета
     данные передаются в открытом виде и занимают область
     с fctx->oframe[8] ... по fctx->ofram[ fctx->header_offset - 1 ] */
   if( fctx->header_offset > 8 ) {
     if( ak_buffer_is_assigned( &fctx->header_data ))
       memcpy( oframe+8, fctx->header_data.data, fctx->header_offset - 8 );
      else memset( oframe+8, 0, fctx->header_offset - 8 );
   }

  /* тип и размер сообщения */
   offset = fctx->header_offset;
   oframe[ offset++ ] = ( ak_uint8 ) mtype;
   oframe[ offset++ ] = ( ak_uint8 )(( datalen >> 8 )%256 );
   oframe[ offset++ ] = ( ak_uint8 )( datalen%256 );

  /* копируем данные, если указатели на области памяти не совпадают */
   if( data != oframe + offset ) memcpy( oframe + offset, data, datalen );

  /* паддинг и контрольная сумма */
   if(( olen = framelen - olen ) > 0 ) fctx->plain_rnd.random( &fctx->plain_rnd,
                                             oframe + offset + datalen, (ssize_t) olen );
  /* по-умолчанию, мы всегда добавляем во фрейм контрольную сумму */
   oframe[ framelen - 2 - ilen ] = ( ak_uint8 ) is_present;
   oframe[ framelen - 1 - ilen ] = ( ak_uint8 ) ilen;

   olen = framelen - ilen - 2;
   if( ftype == plain_frame )
     ak_mac_context_ptr( ikey, oframe, olen, oframe + framelen - ilen );
   else { /* это все только для ctr+omac, mgm впереди ))) */
           ak_mac_context_ptr( ikey, oframe, olen, oframe + framelen - ilen );
           olen -= fctx->header_offset;

          /*! \todo здесь надо аккуратно определить iv для режима aead */
           if( ekey->bsize == 16 )
             ak_bckey_context_ctr( ekey, oframe + fctx->header_offset,
                                             oframe + fctx->header_offset, olen, oframe, 8 );
            else ak_bckey_context_ctr( ekey, oframe + fctx->header_offset,
                                           oframe + fctx->header_offset, olen, oframe+4, 4 );
        }

  /* контрольный вывод */
    ak_fiot_context_log_frame( fctx->oframe.data, framelen, __func__ );
  /* запись данных */
   if( fctx->write( fctx->iface_enc, fctx->oframe.data, framelen ) != ( ssize_t ) framelen )
    ak_error_set_value( error = ak_error_write_data );

  /* изменяем значения счетчиков и ключей после отправки фрейма в канал связи */
  return ak_fiot_context_increment_counters( fctx );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция интерпретирует входящие данные, на которые указывает `data`, как единый массив октетов
    с известной длиной. Массив разбивается на фрагменты, длина которых не превосходит максимально
    возможной длины отправляемого фрейма. Максимально возможная длина отправляемого фрейма
    определяется значением `fctx->oframe_size`, которое может изменяться пользователем.

    После разбиения, все фрагменты, последовательно, отправляются в канал связи
    с помощью функции ak_fiot_context_write_frame().
    Все передаваемые данные помещаются во фреймы типа application data и зашифровываются.

    \param fctx Контекст защищенного соединения протокола sp fiot.
    Контекст должен быть предварительно создан, а ключевые значения инициализированы.
    \param data Данные, которые помещаются во фрейм и отправляются в канал.
    \param datalen Размер отправляемых данных в байтах.

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха.
    Иначе, возвращается код ошибки.                                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_write_application_data( ak_fiot fctx, ak_pointer data, size_t datalen )
{
  int error = ak_error_ok;
  ak_uint8 *dataptr = data;
  size_t meslen = 0, ilen = 0;

  if( fctx == NULL ) ak_error_message( ak_error_null_pointer, __func__,
                                                           "using null pointer to fiot context" );
  ilen = ( fctx->role == client_role ) ? fctx->icfk.hsize : fctx->isfk.hsize;
  meslen = fctx->oframe.size - fctx->header_offset - 3 - 2 - ilen;

  while( datalen > 0 ) {
    ilen = ak_min( meslen, datalen ); /* получаем длину отправляемого фрагмента */
    if(( error = ak_fiot_context_write_frame( fctx,
                             dataptr, ilen, encrypted_frame, application_data )) != ak_error_ok )
      return ak_error_message( error, __func__, "write application data error" );
    dataptr += ilen; datalen -= ilen;
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_write_alert_message( ak_fiot fctx, alert_t alert, char *errstr, size_t size )
{
  size_t datalen = 0;
  ak_uint8 data[256];
  int error = ak_error_ok;

  if( fctx == NULL ) ak_error_message( ak_error_null_pointer, __func__,
                                                           "using null pointer to fiot context" );
 /* формируем сериализованное представление сообщения об ошибке */
  memset( data, 0, sizeof( data ));
  data[0] = ( ak_uint8 )(( alert >> 8 )%256 );
  data[1] = ( ak_uint8 )( alert%256 );

  if(( errstr == NULL ) || ( size == 0 )) {
    data[4] = not_present;
    datalen = 5; /* длина alertMessage */
  } else {
     data[4] = is_present;
     memcpy( data+5, errstr, ak_min( 250, size ));
     datalen = 5 + ak_min( 250, size );
    }

 /* формируем криптографические механизмы контроля целостности
    и отправляем сообщение */
  if(( fctx->state != wait_client_application_data ) &&
       ( fctx->state != wait_server_application_data )) {
     data[2] = ( ak_uint8 )(( streebog256 >> 8 )%256 );
     data[3] = ( ak_uint8 )( streebog256%256 );
     if(( error = ak_fiot_context_write_frame( fctx, data, datalen,
                                                      plain_frame, alert_message)) != ak_error_ok )
      return ak_error_message( error, __func__, "write alert message error" );
  } else {
     data[2] = data[3] = 0;
     if(( error = ak_fiot_context_write_frame( fctx, data, datalen,
                                                  encrypted_frame, alert_message)) != ak_error_ok )
      return ak_error_message( error, __func__, "write alert message error" );
    }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция ожидает данные в течение заданного временного интервала.
    По истечении времени, если данные не получены, возвращается ошибка.

    \param fctx Контекст защищенного соединения.
    \param gate Интерфейс, на котором ожидаются данные.
    \param buffer Указатель на область памяти, в которую помещаются полученные данные
    \param length Размер области памяти в байтах.
    \return Функция возвращает количество полученных данных.                                       */
/* ----------------------------------------------------------------------------------------------- */
 ssize_t ak_fiot_context_read_ptr_timeout( ak_fiot fctx, interface_t gate,
                                                                  ak_pointer buffer, size_t length )
{
    int fd = -1;
#ifdef LIBAKRYPT_HAVE_SYSSELECT_H
    fd_set fdset;
    struct timeval tv;
#endif
    if( gate == encryption_interface ) fd = fctx->iface_enc;
      else fd = fctx->iface_plain;

#ifdef LIBAKRYPT_HAVE_SYSSELECT_H
    tv.tv_usec = 0; tv.tv_sec = fctx->timeout;

    FD_ZERO( &fdset );
    FD_SET( fd, &fdset );
    if( select( fd+1, &fdset, NULL, NULL, &tv ) <= 0 )
      return ak_error_set_value( ak_error_read_data_timeout );
#endif

 return fctx->read( fd, buffer, length );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Эта функция рассматривается как вспомогательная и не должна вызываться
    пользователем самостоятельно.

    \param fctx Контекст защищенного соединения.
    \param off Указатель на переменную, в которую помещается смещение данных от начала фрейма
    (длина заголовка).
    \param flen Длина считанного фрейма (в байтах).
    \param ft Тип считанного фрейма: зашифрованный или открытый.

    \return Функция возвращает указатель на начало массива, в котором размещен считанный фрейм.
    В случае ошибки возвращается NULL.                                                             */
/* ----------------------------------------------------------------------------------------------- */
 ak_uint8 *ak_fiot_context_read_frame_ptr( ak_fiot fctx,
                                                       size_t *off, size_t *flen, frame_type_t *ft )
{
   frame_type_t ftype;
   ak_uint8 *frame = NULL;
   int error = ak_error_ok;
   size_t offset = 0, framelen = 0;
   ssize_t bytesReceived;

  /* необходимые проверки */
   if( fctx->iface_enc == undefined_interface ) {
     ak_error_set_value( fiot_error_wrong_interface );
     return NULL;
   }
   if(( fctx->inframe.data == NULL ) || ( fctx->inframe.size == 0 )) {
     ak_error_set_value( ak_error_wrong_buffer );
     return NULL;
   }

  /* в начале пытаемся получить из канала связи три байта, содержащие тип фрейма и его длину */
   memset( frame = fctx->inframe.data, 0, fctx->inframe.size );
   if (fctx->sock_type == SOCK_STREAM) {
        /* Если транспортный протокол - TCP, то мы можем считывать фрейм по частям, и сначала
         * считать длину фрейма, чтобы затем без ошибок считать данные нужного размера */

        /* в начале пытаемся получить из канала связи три байта, содержащие тип фрейма и его длину */
        if (ak_fiot_context_read_ptr_timeout(fctx,
                                             encryption_interface, fctx->inframe.data, 3) != 3) {
            ak_error_set_value(ak_error_read_data_timeout);
            return NULL;
        }
   } else {
        /* В случае UDP необходимо считать весь фрейм целиком
         * за одно чтение, надеясь, что его размер не больше текущего
         * размера входного буфера */
        bytesReceived = ak_fiot_context_read_ptr_timeout(fctx,
                                       encryption_interface, fctx->inframe.data, fctx->inframe.size);
        if (bytesReceived <= 0) {
            ak_error_set_value(ak_error_read_data_timeout);
            return NULL;
        }
   }
   
  /* проверяем, что тип полученного фрейма корректен */
   ftype = frame[0]&0x3;
   if(( ftype != plain_frame ) && ( ftype != encrypted_frame )) {
     ak_error_set_value( fiot_error_frame_type );
     return NULL;
   }

  /* определяем длину заголовка */
   offset = frame[0]>>2;

  /* проверяем, что длина полученного фрейма корректна */
   framelen = frame[2] + frame[1]*256;
   if(( framelen > fiot_max_frame_size ) || ( framelen < offset + 14 )) {
                              /* константа 14 формируется следующим образом:
                                 тип сообщения - 1 октет
                                 истинная длина сообщения - 2 октета
                                 как минимум - 1 октет сообщения (сообщения всегда не пусты)
                                 флаг наличия имитовставки + ее длина - 2 октета
                                 миниумум 8 октетов имитовставки */
     if( ak_log_get_level() >= fiot_log_standard )
       ak_error_message( fiot_error_frame_size, __func__, "recieved frame with incorrect length" );
      else ak_error_set_value( fiot_error_frame_size );
     return NULL;
   }
  /* при необходимости, увеличиваем объем внутреннего буффера */
   if( framelen > fctx->inframe.size ) {
     if(( error = ak_fiot_context_set_frame_size( fctx, inframe, framelen )) != ak_error_ok ) {
       ak_error_set_value( error );
       return NULL;
     }

     /* В случае UDP, размер фрейма, больший чем размер буфера, означает, что была
         * утеряна часть данных. Сообщаем о неуспешном завершении. Заметим, что приемный буфер
         * был также увеличен, чтобы избежать подобных ошибок для следующих пакетов */
     if (fctx->sock_type == SOCK_DGRAM) {
       ak_error_message(fiot_frame_size, __func__, "reading UDP-frame with too large length");
       return NULL;
     }
   }

  /* Для UDP осталось проверить, что был считан весь фрейм */
   if (fctx->sock_type == SOCK_DGRAM) {
        if (bytesReceived != framelen) {
            ak_error_set_value(ak_error_read_data);
            return NULL;
        }
    } else {
        /* Для TCP теперь получаем из канала основное тело пакета */
        if (ak_fiot_context_read_ptr_timeout(fctx, encryption_interface,
                                             frame + 3, framelen - 3) != (ssize_t) framelen - 3)
            return NULL;
    }

  /* получаем значения счетчиков из номера фрейма, при необходимости, изменяем значения ключей */
   if(( error = ak_fiot_context_read_counters( fctx, frame+3 )) != ak_error_ok ) {
     if( ak_log_get_level() >= fiot_log_standard )
       ak_error_message( error, __func__, "incorrect counters for given frame" );
      else ak_error_set_value( error );
     return NULL;
   }

  /* устанавливаем значения */
   *off = offset;
   *flen = framelen;
   *ft = ftype;

 return frame;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция получает данные из канала связи, рашифровывает их, проверяет целостность
    помещает полученные данные во временный буффер.

    \param fctx Контекст защищенного соединения протокола sp fiot.
    Контекст должен быть предварительно создан, а ключевые значения инициализированы.
    \param length Переменная, в которую помещается длина полученного сообщения.
    \param mtype Переменная, в которую помещается тип полученного сообщения

    \return В случае успешного приема функция возвращает указатель на область памяти,
    в которой находятся полученные данные. В случае неудачи, возвращается `NULL`,
    а также устанавливается код ошибки, который может быть определен с помощью
    вызова функции ak_error_get_value().                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_uint8 *ak_fiot_context_read_frame( ak_fiot fctx, size_t *length, message_t *mtype )
{
   int i;
   ak_uint8 out[64]; /* максимальная длина имитовставки - длина хэшкода для Стрибога 512 */
   frame_type_t ftype;
   ak_mac ikey = NULL;
   ak_bckey ekey = NULL;
   ak_uint8 *frame = NULL;
   size_t ilen = 4, offset = 0, framelen = 0;

  /* считываем фрейм */
   if(( frame = ak_fiot_context_read_frame_ptr( fctx, &offset, &framelen, &ftype )) == NULL )
     return NULL;

  /* теперь процесс проверки данных
     начинаем с уcтановки ключей и проверки длины имитовставки */
   if( ftype == plain_frame ) ikey = &fctx->epsk;
    else {
          switch( fctx->role ) {
           /* пишем своими ключами, читаем чужими */
            case client_role: ikey = &fctx->isfk; ekey = &fctx->esfk; break;
            case server_role: ikey = &fctx->icfk; ekey = &fctx->ecfk; break;
            default:
                 ak_error_set_value( fiot_error_wrong_role );
                 return NULL;
          }
         }

  /* в начале, пытаемся определить размер имитовставки (без использования контекста протокола ) */
   for( i = 0; i < 6; i++ ) {
      size_t idx = framelen-1-ilen;
      if( idx < 1 ) { ilen = 256; break; }
      if( idx > framelen-1 ) { ilen = 256; break; }
      if(( frame[idx] == ilen ) && ( frame[idx-1] == is_present )) break;
      ilen <<= 1;
   }
   if( ilen > 128 ) { /* значение имитовставки слишком большое */
     ak_error_set_value( fiot_error_frame_format );
     return NULL;
   }
   if( ilen != ikey->hsize ) { /* длина имитовставки полученного фрейма не совпадает
                                           с длиной имитовставки для установленного ключа */
     ak_error_set_value( fiot_error_wrong_mechanism );
     return NULL;
   }

 /* расшифровываем и проверяем контрольную сумму (aead не работает) */
   if( ftype == encrypted_frame ) {
    /*! \todo здесь надо аккуратно определить iv для режима aead */
     if( ekey->bsize == 16 )
       ak_bckey_context_ctr( ekey, frame + offset,
                                  frame + offset, framelen - offset - ilen - 2, frame, 8 );
      else ak_bckey_context_ctr( ekey, frame + offset,
                              frame + offset, framelen - offset - ilen - 2, frame + 4, 4 );
   }
   ak_mac_context_ptr( ikey, frame, framelen - ilen - 2, out );
   if( memcmp( frame + framelen - ilen, out, ilen ) != 0 ) {
     ak_error_set_value( ak_error_not_equal_data );
     return NULL;
   }

 /* теперь помещаем значения полей */
   *mtype = ( message_t ) frame[ offset++ ];
   *length = frame[ offset++ ]*256;
   *length += frame[ offset++ ];

 return frame + offset;
}

/* ----------------------------------------------------------------------------------------------- */
/*             далее идет группа функций, реализующих аудит передаваемых фреймов                   */
/* ----------------------------------------------------------------------------------------------- */


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует вывод произвольного буффера с данными.
    \param data Указатель на данные
    \param length Длина данных в байтах
    \param level Уровень сдвига (количество табуляций, предваряющих выводимые данные).

    \return Функия возвращает количество выведенных данных.                                        */
/* ----------------------------------------------------------------------------------------------- */
 static size_t ak_fiot_context_log_ptr( ak_uint8 *data, size_t length, const unsigned int level )
{
  char buffer[1024];
  size_t i, j, blocks = length >> 4;
  size_t tail = length - (blocks << 4), offset = 0;

  for( i = 0; i < blocks; i++ ) {
     memset( buffer, 0, sizeof( buffer ));
     memset( buffer, ' ', offset = 8*level );
     for( j = 0; j < 16; j++ ) {
        ak_snprintf( buffer+offset, 8, "%02X ", (unsigned char)data[16*i+j] );
        offset += 3;
     }
     ak_error_message( ak_error_ok, "", buffer );
  }
  if( tail ) {
    memset( buffer, 0, sizeof( buffer ));
    memset( buffer, ' ', offset = 8*level );
    for( j = 0; j < tail; j++ ) {
       ak_snprintf( buffer+offset, 8, "%02X ", (unsigned char)data[16*i+j] );
       offset += 3;
    }
    ak_error_message( ak_error_ok, "", buffer );
 }
 return length;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует вывод сообщения clientHello
   \param mes Указатель на область памяти.
   \param meslen Длина сообщения (в байтах).
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха.
    Иначе, возвращается код ошибки.                                                                */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_fiot_context_log_client_hello( ak_uint8 *mes, size_t meslen )
{
  size_t offset, esize;
  ak_error_message_fmt( ak_error_ok, "", "body [%lu octets]", meslen );
  ak_error_message_fmt( ak_error_ok, "", "        %02X [%s]", mes[0],
                                                               ak_fiot_get_message_name( mes[0] ));
  ak_error_message_fmt( ak_error_ok, "", "        %02X %02X [length: %u octets]",
                                                               mes[1], mes[2], mes[1]*256+mes[2] );
  ak_error_message_fmt( ak_error_ok, "", "    crypto mechanism [0x%x]", mes[3]*256+mes[4] );
  ak_error_message_fmt( ak_error_ok, "", "        %02X %02X", mes[3], mes[4] );
  ak_error_message( ak_error_ok, "", "    psk" );
  if( mes[5] == not_present ) {
    ak_error_message_fmt( ak_error_ok, "", "        %02X [psk not presented]", mes[5] );
    offset = 6;
  } else {
    if( mes[5] != is_present ) {
      ak_fiot_context_log_ptr( mes+5, meslen-5, 1 );
      return ak_error_message_fmt( fiot_error_frame_format, __func__,
                                                           "preshared key present flag is broken");
    }
    ak_error_message_fmt( ak_error_ok, "", "        %02X [is presented]", mes[5] );
    ak_error_message_fmt( ak_error_ok, "", "        %02X [type: %u]", mes[6], mes[6] );
    ak_error_message_fmt( ak_error_ok, "", "        %02X [length: %u octets]",
                                                                                  mes[7], mes[7] );
    ak_error_message( ak_error_ok, "", "    identifier" );
    ak_fiot_context_log_ptr( mes+8, mes[7], 1 );
    offset = 8 + mes[7];
  }
  ak_error_message( ak_error_ok, "", "    random" );
  ak_fiot_context_log_ptr( mes+offset, 32, 1 ); offset += 32;
  ak_error_message( ak_error_ok, "", "    curve identifier" );
  ak_error_message_fmt( ak_error_ok, "", "        %02X", mes[offset] );
  if(( esize = ak_fiot_get_point_size( mes[offset] )) == 0 ) {
    ak_fiot_context_log_ptr( mes+offset+1, meslen-offset-1, 1 );
      return ak_error_message_fmt( fiot_error_frame_format, __func__,
                                                            "elliptic curve identifier is broken");
  }
  offset++;
  ak_error_message( ak_error_ok, "", "    point.x" );
  ak_fiot_context_log_ptr( mes+offset, esize, 1 ); offset += esize;
  ak_error_message( ak_error_ok, "", "    point.y" );
  ak_fiot_context_log_ptr( mes+offset, esize, 1 ); offset += esize;
  ak_error_message( ak_error_ok, "", "    count of extensions" );
  ak_error_message_fmt( ak_error_ok, "", "        %02X", mes[offset++] );
  if( offset < meslen ) {
    ak_error_message( ak_error_ok, "", "    padding" );
    ak_fiot_context_log_ptr( mes+offset, meslen-offset, 1 );
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_fiot_context_log_server_hello( ak_uint8 *mes, size_t meslen )
{
  size_t offset = 5, esize;
  ak_error_message_fmt( ak_error_ok, "", "body [%lu octets]", meslen );
  ak_error_message_fmt( ak_error_ok, "", "        %02X [%s]", mes[0],
                                                              ak_fiot_get_message_name( mes [0] ));
  ak_error_message_fmt( ak_error_ok, "", "        %02X %02X [length: %u octets]",
                                                               mes[1], mes[2], mes[1]*256+mes[2] );
  ak_error_message_fmt( ak_error_ok, "", "    crypto mechanism [0x%x]", mes[3]*256+mes[4] );
  ak_error_message_fmt( ak_error_ok, "", "        %02X %02X", mes[3], mes[4] );
  ak_error_message( ak_error_ok, "", "    random" );
  ak_fiot_context_log_ptr( mes+offset, 32, 1 ); offset += 32;
  ak_error_message( ak_error_ok, "", "    curve identifier" );
  ak_error_message_fmt( ak_error_ok, "", "        %02X", mes[offset] );
  if(( esize = ak_fiot_get_point_size( mes[offset] )) == 0 ) {
    ak_fiot_context_log_ptr( mes+offset+1, meslen-offset-1, 1 );
      return ak_error_message_fmt( fiot_error_frame_format, __func__,
                                                            "elliptic curve identifier is broken");
  }
  offset++;
  ak_error_message( ak_error_ok, "", "    point.x" );
  ak_fiot_context_log_ptr( mes+offset, esize, 1 ); offset += esize;
  ak_error_message( ak_error_ok, "", "    point.y" );
  ak_fiot_context_log_ptr( mes+offset, esize, 1 ); offset += esize;
  ak_error_message( ak_error_ok, "", "    count of extensions" );
  ak_error_message_fmt( ak_error_ok, "", "        %02X", mes[offset++] );
  if( offset < meslen ) {
    ak_error_message( ak_error_ok, "", "    padding" );
    ak_fiot_context_log_ptr( mes+offset, meslen-offset, 1 );
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_fiot_context_log_alert( ak_uint8 *mes, size_t meslen )
{
  size_t offset = 0, len = 0;
  ak_error_message_fmt( ak_error_ok, "", "body [%lu octets]", meslen );
  ak_error_message_fmt( ak_error_ok, "", "        %02X [%s]", mes[0],
                                                               ak_fiot_get_message_name( mes[0] ));
  ak_error_message_fmt( ak_error_ok, "", "        %02X %02X [length: %u octets]",
                                                         mes[1], mes[2], len = mes[1]*256+mes[2] );
  ak_error_message( ak_error_ok, "", "    error code" );
  ak_error_message_fmt( ak_error_ok, "", "        %02X %02X", mes[3], mes[4] );
  ak_error_message( ak_error_ok, "", "    algorithm" );
  ak_error_message_fmt( ak_error_ok, "", "        %02X %02X [0x%x]", mes[5], mes[6],
                                                                               mes[5]*256+mes[6] );
  ak_error_message( ak_error_ok, "", "    message" );
  if( mes[7] == not_present ) {
    ak_error_message_fmt( ak_error_ok, "", "        %02X [not presented]", mes[7] );
    offset = 8;
  } else {
    char errstr[256];
    if( mes[7] != is_present ) {
      ak_fiot_context_log_ptr( mes+8, len-5, 1 );
      return ak_error_message_fmt( fiot_error_frame_format, __func__,
                                                           "alert message present flag is broken");
    }
    memcpy( errstr, mes+8, len-5 ); errstr[len-5] = 0;
    ak_error_message_fmt( ak_error_ok, "", "        %02X [is presented: %s]", mes[7], errstr );
    ak_fiot_context_log_ptr( mes+8, len-5, 1 );
    offset = 3+len;
  }
  if( offset < meslen ) {
    ak_error_message( ak_error_ok, "", "    padding" );
    ak_fiot_context_log_ptr( mes+offset, meslen-offset, 1 );
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_fiot_context_log_request_identifier_extension( ak_uint8 *mes, size_t meslen )
{
  size_t offset = 0, len = 0;
  ak_error_message_fmt( ak_error_ok, "", "body [%lu octets]", meslen );
  ak_error_message_fmt( ak_error_ok, "", "        %02X [%s]", mes[0],
                                                               ak_fiot_get_message_name( mes[0] ));
  ak_error_message_fmt( ak_error_ok, "", "        %02X %02X [length: %u octets]",
                                                         mes[1], mes[2], len = mes[1]*256+mes[2] );
  ak_error_message( ak_error_ok, "", "    request" );
  switch( mes[3] ) {
    case is_requested:
       ak_error_message_fmt( ak_error_ok, "", "        %02X [is requested]", mes[3] ); break;
    case not_requested:
       ak_error_message_fmt( ak_error_ok, "", "        %02X [not requested]", mes[3] ); break;
    default:
       ak_error_message_fmt( ak_error_ok, "", "        %02X [unexpected value]", mes[3] );
       return ak_error_message( fiot_error_frame_format, __func__, "frame is broken (unexpected request)" );
  }
  if( len != 1 ) {
    if( len-1 > meslen )
      return ak_error_message( fiot_error_frame_format, __func__, "frame is broken (incorrect extension length)" );

    ak_error_message( ak_error_ok, "", "    identifier" );
    ak_fiot_context_log_ptr( mes+4, len-1, 1 );
  }
  offset = len+3;
  if( offset < meslen ) {
    ak_error_message( ak_error_ok, "", "    padding" );
    ak_fiot_context_log_ptr( mes+offset, meslen-offset, 1 );
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \details Функция не только выводит содержимое фрейма с помощью действующего механизма аудита,
    но и выполняет проверку корректности переданного ей фрейма. Функция пытается декомпозировать
    полученную последовательность октетов в качестве правильно сформированного фрейма. При этом
    криптографические проверки не производятся.

    \param frame Указатель на последовательность октетов, содержащую сериализованное
           представление фрейма.
    \param framelen Длина последовательности октетов.
    \return В случае удачной декомпозиции фрейма функция возвращает \ref ak_error_ok.
    В противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_log_frame( ak_uint8 *frame, size_t framelen, const char *function )
{
   char buffer[1024];
   size_t offset = 0;
   ak_uint8 *message = NULL;
   int error = ak_error_ok;
   unsigned int i, ilen = 4;

  /* необходимые проверки */
   if( frame == NULL )
     return ak_error_message( ak_error_null_pointer, "", "using null pointer to frame" );

   if( ak_log_get_level() >= fiot_log_standard ) {
    /* выводим общую информацию для уровней fiot_log_standard и выше */
     ak_error_message( ak_error_ok, function, "" );
     ak_error_message_fmt( ak_error_ok, "",  "%ld octets", framelen );
     ak_fiot_context_log_ptr( frame, framelen, 1 );
     if( framelen <= 8 ) return ak_error_message_fmt( ak_error_wrong_length, __func__,
                                                  "insufficient length of frame", framelen );
   }
   if( ak_log_get_level() < fiot_log_maximum ) return ak_error_ok;

  /* для уровня fiot_log_maximum производим детальный разбор и вывод передаваемых фреймов */

   ak_error_message_fmt( ak_error_ok, "",  "header [%u octets]", offset = frame[0]>>2 );
   if(( offset < 8 ) || ( offset > framelen ))
     return ak_error_message( ak_error_wrong_length, "", "incorrect value of frame offset" );
   switch( frame[0]&0x3 ) {
    case plain_frame:
      ak_snprintf( buffer, 1024, "        %02X [tag: %s]", frame[0], "plain frame" );
      break;
    case encrypted_frame:
      ak_snprintf( buffer, 1024, "        %02X [tag: %s]", frame[0], "encrypted frame" );
      break;
    default:
      error = fiot_error_frame_type;
      ak_snprintf( buffer, 1024, "        %02X [tag: %s]", frame[0], "unexpected frame type" );
      break;
   }
   ak_error_message( error, "",  buffer );
   ak_error_message_fmt( error, "",
                             "        %02X %02X [length: %u octets]", frame[1], frame[2], framelen );
   ak_error_message_fmt( error, "",
     "        %02X %02X %02X %02X %02X [number]", frame[3], frame[4], frame[5], frame[6], frame[7] );
   if( offset > 8 ) ak_fiot_context_log_ptr( frame+8, offset-8, 1 );
   if( error != ak_error_ok ) return ak_error_message( error, __func__,
                                                             "frame is broken (unexpected header)" );

  /* пытаемся определить значение имитовставки без использования контекста протокола
    (реализуется поиск по массиву данных с целью найти маркер наличия имитовставки и ее длину ) */
   for( i = 0; i < 6; i++ ) {
      size_t idx = framelen-1-ilen;
      if( idx < 1 ) { ilen = 256; break; }
      if( idx > framelen-1 ) { ilen = 256; break; }
      if((( unsigned int )frame[idx] == ilen ) && ( frame[idx-1] == is_present )) break;
      ilen <<= 1;
   }
   if( ilen > 128 ) return ak_error_message_fmt( fiot_error_frame_format, __func__,
                                            "frame is broken (wrong integrity tag size: %u)", ilen );

  /* выводим зашифрованную часть */
   if(( frame[0]&0x3 ) == encrypted_frame ) {
     ak_error_message_fmt( ak_error_ok, "", "body [%lu octets, encrypted]", framelen-ilen-2-offset );
     ak_fiot_context_log_ptr( frame+offset, framelen-ilen-2-offset, 1 );
   } else {
            switch( frame[offset] )
           {
             case client_hello:
                ak_fiot_context_log_client_hello( frame+offset, framelen-ilen-2-offset );
               break;

             case server_hello:
                ak_fiot_context_log_server_hello( frame+offset, framelen-ilen-2-offset );
               break;

             case alert_message:
                ak_fiot_context_log_alert( frame+offset, framelen-ilen-2-offset );
               break;

             case extension_request_identifer:
                ak_fiot_context_log_request_identifier_extension( frame+offset, framelen-ilen-2-offset );
                break;

             default:
                ak_error_message_fmt( ak_error_ok, "", "body [%lu octets, plain]",
                                                                            framelen-ilen-2-offset );
                ak_fiot_context_log_ptr( frame+offset, framelen-ilen-2-offset, 1 );
           }
          }

  /* теперь выводим значение имитовставки */
   if( !ilen ) return ak_error_message( fiot_error_frame_format, __func__,
                                           "frame is broken (undefined length of integrity tag)" );
   ak_error_message_fmt( ak_error_ok, "", "icode [%lu octets]", ilen+2 );
   if( frame[framelen-1] == not_present )
     return ak_error_message( ak_error_ok, __func__, "frame is broken (integrity tag is'nt present)" );

   message = frame + framelen - 2 - ilen;
    switch( message[0] )
   {
     case is_present:
        ak_error_message_fmt( ak_error_ok, "", "        %02X [tag: present]", message[0] );
        ak_error_message_fmt( ak_error_ok, "", "        %02X [length: %lu octets]",
                                                                  message[1], message[1] );
        ak_fiot_context_log_ptr( message+2, message[1], 1 );
        break;
     case not_present:
        ak_error_message_fmt( ak_error_ok, "", "        %02X [tag: not present]", message[0] );
        break;
   }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                  ak_fiot_tlp.c  */
/* ----------------------------------------------------------------------------------------------- */
