package com.example.androidsignongdemo.client.example.base

import com.example.androidsignongdemo.util.Constants
import com.example.androidsignongdemo.util.ContainerAdapter
import com.example.androidsignongdemo.util.KeyStoreType
import com.example.androidsignongdemo.util.Logger
import ru.CryptoPro.JCSP.JCSP
import ru.CryptoPro.ssl.Provider
import ru.CryptoPro.ssl.util.TLSContext
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStream
import java.io.InputStreamReader
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager

/**
 * Служебный класс TLSData предназначен для
 * реализации примеров соединения по TLS.
 *
 * 30/05/2013
 *
 */
abstract class TLSData
/**
 * Конструктор.
 *
 * @param adapter Настройки примера.
 */
protected constructor(adapter: ContainerAdapter?) : EncryptDecryptData(adapter!!) {
    /*
    * Создание SSL контекста.
    *
    * @param trustManagers Менеджеры хранилища доверенных
    * сертификатов. Для получения одного менеджера должен
    * быть передан массив по крайней мере из одного элемента,
    * в него будет помещен выбранный менеджер сертификатов.
    * Может быть null.
    * @return готовый SSL контекст.
    * @throws Exception.
    */
    /*
    * Создание SSL контекста.
    *
    * @return готовый SSL контекст.
    * @throws Exception.
    */
    @Throws(Exception::class)
    protected fun createSSLContext(trustManagers: Array<TrustManager?>? = null): SSLContext {
        containerAdapter!!.printConnectionInfo()
        Logger.log("Creating SSL context...")

        //
        // Для чтения(!) доверенного хранилища доступна
        // реализация CertStore из Java CSP. В ее случае
        // можно не использовать пароль.
        //
        val keyStoreType: String = KeyStoreType.currentType()
        Logger.log(
            "Initiating key store. Loading containers. " +
                    "Default container type: " + keyStoreType
        )

        //
        // @see {@link ru.CryptoPro.ACSPClientApp.client.example.base#TLSData}
        // @see {@link ru.CryptoPro.ACSPInClientApp.examples#HttpsExample}
        // @see {@link ru.CryptoPro.ssl.util#TLSContext}
        //
        // В данном примере используется только функции из "белого" списка
        // из класса TLSContext и в случае применения двухсторонней
        // аутентификации (2СА) при инициализации TLS задается явный алиаса
        // ключа keyAlias!
        //
        // В случае 2СА оптимальный вариант - всегда задавать алиас ключа,
        // т.к. это позволяет указать точно, какой контейнер использовать,
        // избегнув, возможно, долгого перечисления контейнеров.
        //
        // Есть 2 способа работы:
        // 1. "белый список" с функциями из класса TLSContext - для случаев
        // 1СА и 2СА. Использует динамически создаваемый SSL контекст классов
        // javax.net.ssl.*;
        // 2. стандартный (прежний) Java SSE, использующий классы javax.net.ssl.*
        // для динамического создания контекста или System.setProperty с передачей
        // параметров аутентификации с помощью свойств javax.net.ssl.* и формированием
        // дефолтного (static) контекста, или без передачи параметров одновременно
        // с созданием SSL контекста.
        //
        // Важно!
        // Рекомендуется использовать:
        // вариант 1 - функции "белого" списка, где создается динамический контекст;
        // или вариант 2 с динамическим созданием контекста;
        // избегать HttpsURLConnection.
        //
        // Важно!
        // Смешанное использование 1 и 2 вариантов крайне не рекомендуется: нужно
        // применять либо только первый подход, либо только второй. Также не
        // рекомендуется смешивать использование дефолтного (static) контекста и
        // динамического. Смешанное использование происходит, например, когда
        // применяется SSlContext к HttpsURLConnection, т.к. последний внутри
        // создает дефолтныый (static) конекст.
        //
        // В первом случае SSLContext будет получен из функций "белого" списка. В
        // случае 2СА пароль к контейнеру в сами функции "белого" списка не передается,
        // т.к. он будет запрошен в ходе подбора контейнеров в специальном окне CSP.
        // Алиас нужно передавать всегда, иначе пароль будет запрошен для всех найденных
        // контейнеров.
        //
        // Во втором случае (стандартный Java SSE) при 2СА поведение осталось тем
        // же, что и раньше, то есть можно и дальше передать пароль в функцию init:
        // <KeyManagerFactory>.init(KeyStore, password);
        // в виде password, или
        // System.setProperty("javax.net.ssl.keyStorePassword", keyPassword);
        // в случае HttpsURLConnection, но появилась особенность из-за п.1: если
        // пароль никак не передали (null), то будет отображено окно ввода пароля CSP
        // для каждого(!) контейнера, который может быть получен с помощью KeyStore,
        // переданного в KeyManagerFactory. Таким образом, в случае передачи пустого
        // пароля (null) также настоятельно рекомендуется передавать в KeyStore хотя
        // бы алиас с помощью класса StoreInputStream в случае 2СА в конструкции вида:
        // keyStore.load(new StoreInputStream(keyAlias), null); // задаем keyAlias
        // <KeyManagerFactory>.init(keyStore, password);
        //
        // Если же используется вариант с передачей параметров javax.net.ssl.* через
        // System.setProperty, то в случае 2СА рекомендуется передавать алиас с помощью:
        // System.setProperty("javax.net.ssl.keyStore", keyAlias);
        // и обязательно пароль:
        // System.setProperty("javax.net.ssl.keyStorePassword", keyPassword);
        //
        //------------------------------------------------------------------------------------------
        // Важно!
        // Известно, что настройки вида System.setProperty со свойствами типа
        // javax.net.ssl.* (далее, просто System.setProperty) обычно используются
        // для разовой настройки дефолтного (static) контекста SSLContext, который
        // часто используют реализации TLS вроде HttpsURLConnection и т.д. в тех
        // случаях, когда для них не задали явно иной SSLSocketFactory из SSLContext.
        // Такой дефолтный (static) контекст будет создан один раз и далее может
        // быть использован.
        //
        // Что такое дефолтный (static) контекст? Это SSL контекст, создаваемый
        // из system-параметров - тех, что задаются в System.setProperty(javax.net.ssl).
        // Если таких параметров нет, то дефолтный (static) контекст использует некие
        // дефолтные значения, например, HDIMAGE для типа хранилища и null для пароля.
        //
        // Важно!
        // В случае, если пароль на контейнер не задан, пароль будет запрошен в окне
        // CSP.
        //
        // Есть несколько способов создать защищенный контекст:
        //
        // + динамически, с помощью явных KeyManagerFactory, TrustManagerFactory,
        // KeyStore, SSLContext и т.п.
        // + статически, с помощью свойств вида System.setProperty и вызова вида
        // SSLContext.getDefault().
        //
        // Самый простой и рекомендуемый способ: создавать контекст динамически(!)
        // (например, такой подход применяется в функциях "белого" списка класса
        // TLSContext, без пароля).
        // Менее очевидный и слабо контролируемый способ: HttpsURLConnection +
        // свойства System.setProperty. Создается один контекст на весь процесс.
        // Гораздо сложнее: способ HttpsURLConnection + динамический контекст.
        //
        // Дело в том, что у класса HttpsURLConnection есть особенность: хотя ему
        // можно передать factory из динамического контекста, объект HttpsURLConnection
        // все равно создаст дефолтный (static) контекст, полагаясь на свойства
        // вида System.setProperty, которых их может не быть, например, если был
        // создан динамический контекст и передан в HttpsURLConnection. Это создает
        // некоторые проблемы.
        //
        // Первый и второй способы создания контекста не рассматриваются, т.к. первый
        // очевидным образом настраивает контекст, а второй всегда требует свойства:
        //
        // System.setProperty("javax.net.ssl.keyStorePassword", keyPassword); // как минимум, есть этот параметр
        // System.setProperty("javax.net.ssl.keyStore", keyAlias); // может не быть
        //
        // Такому дефолтному (static) контексту обычно известно о пароле (как минимум)
        // и даже об алиасе ключа. Эти настройки задаются разово и распространяются
        // на весь процесс. Согласно keyPassword начинается перебор всех подходящих
        // контейнеров, а если задан keyAlias - то еще и по алиасу, что служит
        // дополнительным фильтром и ощутимо сокращает число отобранных контейнеров,
        // а также время перебора.
        //
        // Чем плох способ HttpsURLConnection + динамический контекст?
        //
        // В случае динамического контекста свойства System.setProperty закономерно
        // не задаются, они излишни, ведь создан и передан динамический контекст,
        // однако HttpsURLConnection все же пытается создать дефолтный (static)
        // контекст, не располагая абсолютно никакими свойствами, что может привести
        // к неконтролируемому появлению окон ввода пароля, который не был задан
        // в качестве фильтра для контейнеров.
        //
        // Поэтому лучше всего избегать использования HttpsURLConnection +
        // динамический контекст, а лучше и самого HttpsURLConnection!
        // Вместо него рекомендуется использовать apache http client, ok http и др.
        // с явным созданием SSLContext без дефолтного (static) контекста и
        // свойства для него.
        //
        // Что делать, если HttpsURLConnection все-таки используется/нужен?
        //
        // В этой ситуации, если создается динамический контекст и не заданы
        // свойства System.setProperty, использование неполного дефолтного (static)
        // контекста приведет к появлению окон CSP для ввода пароля для каждого(!)
        // найденного контейнера, и, чем меньше фильтров в свойствах System.setProperty
        // (а этих свойств может не быть вообще, если используется динамический
        // контекст), тем окон больше.
        //
        // Как убрать окна CSP для ввода пароля, если в HttpsURLConnection
        // уже был передан динамический контекст?
        //
        // Для контроля над дефолтным (static) контекстом добавлен параметр:
        //
        // System.setProperty("disable_default_context", "false");
        // который задан по умолчанию со значением false.
        //
        // Свойство disable_default_context определяет, будет ли загружен KeyStore
        // при создании дефолтного контекста реализациями типа HttpsURLConnection
        // или нет. По умолчанию оно false, т.е. загрузка KeyStore из дефолтного
        // контекста включена. KeyStore, если System.setProperty не заданы, пустой.
        // Чтобы подавить окна в дефолтном (static) контексте, загрузку KeyStore
        // в нем можно отключить:
        //
        // System.setProperty("disable_default_context", "true");
        // ведь уже есть динамический контекст для HttpsURLConnection.
        //
        // Свойство disable_default_context имеет значение, только если реализация
        // TLS соединения действительно обращается к дефолтному контексту (ей нужен/не
        // нужен KeyStore).
        //
        // См. {@link ru.CryptoPro.ssl.JavaTLSKeyStoreParameter} в cpSSL-javadoc.jar
        //------------------------------------------------------------------------------------------
        //
        // Например, свойство disable_default_context втключено в ф.
        // initJavaProviders() в MainActivity для TLS-примеров,
        // использующих HttpsURLConnection, поскольку в последний
        // передается динаммически созданный контекст и нужны в
        // дефолтном (static) нет.
        //
        val sslCtx: SSLContext

        // Вариант №1, рекомендуемый.
        //
        // В данном случае, при клиентской аутентификации, пароль не
        // передается, он будет запрошен в окне ввода пароля для переданного
        // алиаса ключа.
        if (containerAdapter!!.isUseClientAuth) {
            sslCtx = TLSContext.initAuthClientSSL(
                Provider.PROVIDER_NAME,  // провайдер, по умолчанию - JTLS
                "TLSv1.2",  // протокол, по умолчанию - GostTLS
                JCSP.PROVIDER_NAME,
                keyStoreType,
                containerAdapter!!.clientAlias,  // точный алиас ключа
                containerAdapter!!.trustStoreProvider,
                containerAdapter!!.trustStoreType,
                containerAdapter!!.trustStoreStream,
                java.lang.String.valueOf(containerAdapter!!.trustStorePassword),
                trustManagers // для Ok Http
            )
        } // if
        else {
            sslCtx = TLSContext.initClientSSL(
                Provider.PROVIDER_NAME,  // провайдер, по умолчанию - JTLS
                "TLSv1.2",  // протокол, по умолчанию - GostTLS
                containerAdapter!!.trustStoreProvider,
                containerAdapter!!.trustStoreType,
                containerAdapter!!.trustStoreStream,
                java.lang.String.valueOf(containerAdapter!!.trustStorePassword),
                trustManagers // для Ok Http
            )
        } // else

        /*

        // Вариант 2, прежний, стандартный.
        //
        // Как было описано выше, если этот контекст (динамический)
        // предполагается передать в HttpsURLConnection, то дополнительно
        // нужно задать свойство:
        // System.setProperty("disable_default_context", "true");
        //
        // Таким образом, будет отключена работа дефолтного (static)
        // контекста в составе HttpsURLConnection.
        //
        // Например, свойство disable_default_context втключено в ф.
        // initJavaProviders() в MainActivity для TLS-примеров,
        // использующих HttpsURLConnection, поскольку в последний
        // передается динаммически созданный контекст и нужны в
        // дефолтном (static) нет.

        KeyStore ts = KeyStore.getInstance(
            containerAdapter.getTrustStoreType(),
            containerAdapter.getTrustStoreProvider());

        ts.load(
            containerAdapter.getTrustStoreStream(),
            containerAdapter.getTrustStorePassword()
        );

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
            Provider.KEYMANGER_ALG,
            Provider.PROVIDER_NAME
        );

        if (containerAdapter.isUseClientAuth()) {

            KeyStore ks = KeyStore.getInstance(
                keyStoreType,
                JCSP.PROVIDER_NAME
            );

            // Явное указание контейнера.

            if (containerAdapter.getClientAlias() != null) {
                ks.load(new StoreInputStream(containerAdapter.getClientAlias()), null);
            } // if
            else {
                ks.load(null, null);
            } // else

            kmf.init(ks, containerAdapter.getClientPassword());

        } // if

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
            Provider.KEYMANGER_ALG,
            Provider.PROVIDER_NAME
        );

        tmf.init(ts);

        sslCtx = SSLContext.getInstance(
            Provider.ALGORITHM_12,
            Provider.PROVIDER_NAME
        );

        sslCtx.init(containerAdapter.isUseClientAuth()
            ? kmf.getKeyManagers() : null,
            tmf.getTrustManagers(),
            null
        );

        if (trustManagers != null) { // для Ok Http
            System.arraycopy(tmf.getTrustManagers(), 0, trustManagers, 0, 1);
        } // if

        */Logger.log("SSL context completed.")
        return sslCtx
    }

    companion object {
        /**
         * Вывод полученных данных.
         *
         * @param inputStream Входящий поток.
         * @throws Exception
         */
        @Throws(Exception::class)
        fun logData(inputStream: InputStream?) {
            var br: BufferedReader? = null
            if (inputStream != null) {
                try {
                    br = BufferedReader(
                        InputStreamReader(
                            inputStream, Constants.DEFAULT_ENCODING
                        )
                    )
                    var input: String?
                    Logger.log("*** Content begin ***")
                    while ((br.readLine().also { input = it }) != null) {
                        input?.let { Logger.log(it) }
                    } // while
                    Logger.log("*** Content end ***")
                } finally {
                    if (br != null) {
                        try {
                            br.close()
                        } catch (e: IOException) {
                            // ignore
                        }
                    }
                }
            }
        }
    }
}
