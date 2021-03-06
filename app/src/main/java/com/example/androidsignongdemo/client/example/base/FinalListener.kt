/**
 * $RCSfileFinalListener.java,v $
 * version $Revision: 36379 $
 * created 14.03.2019 11:15 by afevma
 * last modified $Date: 2012-05-30 12:19:27 +0400 (Ср, 30 май 2012) $ by $Author: afevma $
 * (C) ООО Крипто-Про 2004-2019.
 *
 *
 * Программный код, содержащийся в этом файле, предназначен
 * для целей обучения. Может быть скопирован или модифицирован
 * при условии сохранения абзацев с указанием авторства и прав.
 *
 *
 * Данный код не может быть непосредственно использован
 * для защиты информации. Компания Крипто-Про не несет никакой
 * ответственности за функционирование этого кода.
 */
package com.example.androidsignongdemo.client.example.base

/**
 * Интерфейс для реализации действия по
 * завершении операции.
 *
 * @author Copyright 2004-2019 Crypto-Pro. All rights reserved.
 * @.Version
 */
interface FinalListener {
    /**
     * Обработчик.
     *
     */
    fun onComplete()
}