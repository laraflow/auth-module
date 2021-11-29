<?php

namespace Modules\Auth\Events;

use Illuminate\Queue\SerializesModels;
use Modules\Core\Models\User;

class UserRegisteredEvent
{
    use SerializesModels;

    /**
     * @var User $user
     */
    public $user;


    /**
     * Create a new event instance.
     *
     * @param User $user
     */
    public function __construct(User $user)
    {
        $this->user = $user;
    }
}
