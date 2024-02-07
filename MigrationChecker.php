<?php
/**
 * This file is part of GrrSf application.
 *
 * @author jfsenechal <jfsenechal@gmail.com>
 * @date 10/09/19
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Grr\Migration;

use Doctrine\ORM\NonUniqueResultException;
use Grr\Core\Security\SecurityRole;
use Grr\GrrBundle\Authorization\Repository\AuthorizationRepository;
use Grr\GrrBundle\Entity\Area;
use Grr\GrrBundle\Entity\Room;
use Grr\GrrBundle\Entity\Security\Authorization;
use Grr\GrrBundle\Entity\Security\User;
use Grr\GrrBundle\Room\Repository\RoomRepository;
use Grr\GrrBundle\User\Repository\UserRepository;

class MigrationChecker
{
    public function __construct(
        private readonly UserRepository $userRepository,
        private readonly AuthorizationRepository $authorizationRepository,
        private readonly RoomRepository $roomRepository
    ) {
    }

    /**
     * Vérifie si un utilisateur est admin d'une aréa
     * et si celui-ci est mis en tant que administrateur ou pas d'une room
     * de cet area.
     *
     * @return Area[][]|Room[][]|Authorization[][]|User[][]|null[][]
     *
     * @throws NonUniqueResultException
     */
    public function checkAreaAndRoomAdministrator(): array
    {
        $result = [];
        $i = 0;
        $users = $this->userRepository->findAll();
        foreach ($users as $user) {
            $authorizations = $this->authorizationRepository->findByUserAndAreaNotNull($user, true);
            foreach ($authorizations as $authorization) {
                $area = $authorization->getArea();
                $rooms = $this->roomRepository->findByArea($area);
                foreach ($rooms as $room) {
                    $admin = $this->authorizationRepository->findOneByUserAndRoom($user, $room);
                    if ($admin instanceof Authorization || $user->hasRole(SecurityRole::ROLE_GRR_ADMINISTRATOR)) {
                        $result[$i]['authorization'] = $authorization;
                        $result[$i]['user'] = $user;
                        $result[$i]['area'] = $area;
                        $result[$i]['room'] = $room;
                        ++$i;
                    }
                }
            }
        }

        return $result;
    }

    /**
     * @throws NonUniqueResultException
     */
    public function deleteDoublon(): void
    {
        foreach ($this->checkAreaAndRoomAdministrator() as $data) {
            $authorization = $data['authorization'];
            $this->authorizationRepository->remove($authorization);
        }

        $this->authorizationRepository->flush();
    }
}
