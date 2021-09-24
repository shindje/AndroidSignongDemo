package com.example.androidsignongdemo.client.example

import com.example.androidsignongdemo.client.example.base.FinalListener
import com.example.androidsignongdemo.client.example.base.SignData.Companion.getThreadResult
import com.example.androidsignongdemo.client.example.base.TLSData
import com.example.androidsignongdemo.client.example.interfaces.ThreadExecuted
import com.example.androidsignongdemo.util.ContainerAdapter
import com.example.androidsignongdemo.util.Logger
import okhttp3.ConnectionSpec
import okhttp3.OkHttpClient
import okhttp3.Request
import ru.cprocsp.NGate.tls.TlsManager.createSSLContext
import java.lang.Exception
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Класс OkHttpExample реализует пример обмена
 * по TLS 1.0 с помощью Ok Http v3.
 *
 * @author Copyright 2004-2020 Crypto-Pro. All rights reserved.
 * @.Version
 */
open class OkHttpExample
/**
 * Конструктор.
 *
 * @param adapter Настройки примера.
 */
protected constructor(adapter: ContainerAdapter?) : TLSData(adapter) {
    @Throws(Exception::class)
    override fun getResult(listener: FinalListener?) {
        val thread: OkHttpThread = OkHttpThread()
        thread.addFinalListener(listener)
        getThreadResult(thread)
    }

    /**
     * Класс SimpleTLSThread реализует подключение
     * самописного клиента по TLS в отдельном потоке.
     *
     */
    private inner class OkHttpThread : ThreadExecuted() {
        @Throws(Exception::class)
        override fun executeOne() {
            Logger.log("Init OkHttp Sample Example.")
            val trustManagers = arrayOfNulls<TrustManager>(1)
            Logger.log("Create SSL context.")
            val sslContext: SSLContext = createSSLContext(trustManagers)
            Logger.log("Create SSL socket factory.")
            val sslSocketFactory = sslContext.socketFactory
            val trustManager = trustManagers[0] as X509TrustManager?

            // Установка нужного SSLSocketFactory.
            Logger.log("Create Ok Http client.")
            val builder = OkHttpClient.Builder()
            builder.sslSocketFactory(sslSocketFactory, trustManager!!)

            // Задание необходимых параметров (сюиты, протокол).
            val spec: ConnectionSpec = ConnectionSpec.Builder(
                ConnectionSpec.MODERN_TLS
            )
                .tlsVersions("TLSv1.2")
                .cipherSuites(
                    "TLS_CIPHER_2012",
                    "TLS_CIPHER_2001"
                )
                .build()
            builder.connectionSpecs(listOf(spec))
            val client: OkHttpClient = builder.build()

            // Создание запроса к нужному адресу.
            Logger.log("Prepare request.")
            val uri: String = containerAdapter!!.getConnectionInfo()!!.toUrl()!!
            val request: Request = Request.Builder().url(uri).build()

            // Обращение к серверу и вывод полученного ответа.
            Logger.log("Send request.")
            val response = client.newCall(request).execute()
            Logger.log("Successful: " + response.isSuccessful)
            logData(response.body!!.byteStream())
            Logger.log("Connection has been established (OK).")
        }
    }
}
