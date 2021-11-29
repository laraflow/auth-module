<?php

namespace Modules\Auth\Database\Seeders;

use Exception;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Seeder;
use Modules\Core\Models\User;
use Modules\Core\Repositories\Eloquent\UserRepository;
use Modules\Core\Services\Common\FileUploadService;
use Modules\Core\Supports\Constant;
use Modules\Core\Supports\Utility;
use Modules\Rbac\Models\Role;
use Psy\Command\Command;
use Spatie\MediaLibrary\MediaCollections\Exceptions\FileDoesNotExist;
use Spatie\MediaLibrary\MediaCollections\Exceptions\FileIsTooBig;
use Throwable;

class UserRegisterSeeder extends Seeder
{
    /**
     * @var UserRepository
     */
    private $userRepository;
    /**
     * @var FileUploadService
     */
    private $fileUploadService;


    /**
     * UserSeeder constructor.
     * @param UserRepository $userRepository
     * @param FileUploadService $fileUploadService
     */
    public function __construct(UserRepository    $userRepository,
                                FileUploadService $fileUploadService)
    {
        $this->userRepository = $userRepository;
        $this->fileUploadService = $fileUploadService;
    }

    /**
     * Run the database seeds.
     *
     * @return void
     * @throws Exception|Throwable
     */
    public function run()
    {
        Model::unguard();
        //disable Observer
        $eventDispatcher = User::getEventDispatcher();
        User::unsetEventDispatcher();

        //Default User "Ami"

        try {
            $newUser = [
                'name' => 'Mohammad Hafijul Islam',
                'username' => 'hafijul233',
                'email' => 'hafijul233@gmail.com',
                'password' => Utility::hashPassword(('123456789' ?? Constant::PASSWORD)),
                'mobile' => '01710534092',
                'remarks' => 'Database Seeder',
                'enabled' => Constant::ENABLED_OPTION
            ];

            $newUser = $this->userRepository->create($newUser);
            if ($newUser instanceof User) {
                if (!$this->attachProfilePicture($newUser)) {
                    throw new Exception("User Photo Create Failed");
                }

                if (!$this->attachUserRoles($newUser)) {
                    throw new Exception("User Role Assignment Failed");
                }
            } else {
                throw new Exception("Failed to Create  User Model");
            }
        } catch (Exception $exception) {
            $this->userRepository->handleException($exception);
        }

        //Enable observer
        User::setEventDispatcher($eventDispatcher);
    }

    /**
     * Attach Profile Image to User Model
     *
     * @param User $user
     * @return bool
     * @throws FileDoesNotExist
     * @throws FileIsTooBig
     * @throws Exception
     */
    protected function attachProfilePicture(User $user): bool
    {
        //add profile image
        $profileImagePath = $this->fileUploadService->createAvatarImageFromText($user->name);
        if (is_string($profileImagePath)) {
            return $user->addMedia($profileImagePath)->toMediaCollection('avatars')->save();
        }
        return false;
    }

    /**
     * Attach Role to user Model
     *
     * @param User $user
     * @return bool
     */
    protected function attachUserRoles(User $user): bool
    {

        $adminRole = Role::findByName(Constant::SUPER_ADMIN_ROLE);
        $this->userRepository->setModel($user);
        return $this->userRepository->manageRoles([$adminRole->id]);
    }
}
