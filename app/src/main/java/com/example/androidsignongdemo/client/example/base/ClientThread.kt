/**
 * Copyright 2004-2013 Crypto-Pro. All rights reserved.
 * Программный код, содержащийся в этом файле, предназначен
 * для целей обучения. Может быть скопирован или модифицирован
 * при условии сохранения абзацев с указанием авторства и прав.
 *
 * Данный код не может быть непосредственно использован
 * для защиты информации. Компания Крипто-Про не несет никакой
 * ответственности за функционирование этого кода.
 */
package com.example.androidsignongdemo.client.example.base

import android.os.Looper
import com.example.androidsignongdemo.client.example.interfaces.ThreadExecuted
import com.example.androidsignongdemo.util.Logger
import com.example.androidsignongdemo.util.ProgressDialogHolder

/**
 * Служебный класс ClientThread выполняет задачу
 * в отдельном потоке.
 *
 * 29/05/2013
 *
 */
class ClientThread(task: ThreadExecuted?, progressDialogHolder: ProgressDialogHolder?) :
    Thread() {
    /**
     * Выполняемая задача.
     */
    private var executedTask: ThreadExecuted? = null

    /**
     * Окно ожидания.
     */
    private var progressDialogHolder: ProgressDialogHolder? = null
    override fun interrupt() {

        // Чтобы прервать, надо у каждого примера
        // сделать close()!
        super.interrupt()
    }

    /**
     * Поточная функция. Запускает выполнение
     * задания. В случае ошибки пишет сообщение
     * в лог.
     *
     */
    override fun run() {
        /**
         * Зададим, т.к. может потребоваться отобразить
         * окна CSP.
         *
         * В новой версии в провайдере есть этот вызов,
         * тут он делается для совместимости со старым
         * Android CSP.
         */
        if (Looper.myLooper() == null) {
            Looper.prepare()
        }

        // Выполняем задачу.
        executedTask?.execute()

        // Закрываем окно ожидания.
        Logger.log("Client thread finished job.")
        progressDialogHolder?.dismiss()
    }

    /**
     * Конструктор.
     *
     * @param task Выполняемая задача.
     * @param progressDialogHolder Окно ожидания.
     */
    init {
        this.progressDialogHolder = progressDialogHolder
        executedTask = task
    }
}