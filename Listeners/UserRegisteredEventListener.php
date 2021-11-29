<?php

namespace Modules\Auth\Listeners;

use Modules\Auth\Events\UserRegisteredEvent;

/**
 * @class UserRegisteredEventListener
 * @package Modules\Admin\Listeners\Auth
 */
class UserRegisteredEventListener
{

    /**
     * Create the event listener.
     *
     * @return void
     */
    public function __construct()
    {
        //
    }

    /**
     * Handle the event.
     *
     * @param UserRegisteredEvent $userRegisteredEvent
     * @return void
     */
    public function handle(UserRegisteredEvent $userRegisteredEvent)
    {

    }
}
