<?php
/**
 * This file is part of GrrSf application.
 *
 * @author jfsenechal <jfsenechal@gmail.com>
 * @date 8/09/19
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Grr\Migration;

use Carbon\Carbon;
use Carbon\CarbonInterface;
use DateTime;
use Exception;
use Grr\Core\Security\SecurityRole;
use Grr\Core\Setting\SettingsRoom;
use Grr\GrrBundle\Entity\Area;
use Grr\GrrBundle\Entity\TypeEntry;
use Grr\GrrBundle\Entity\Room;
use Grr\GrrBundle\Entity\Security\User;
use Grr\GrrBundle\Repository\AreaRepository;
use Grr\GrrBundle\Repository\EntryRepository;
use Grr\GrrBundle\Repository\TypeEntryRepository;
use Grr\GrrBundle\Repository\RoomRepository;
use Grr\GrrBundle\Repository\Security\AuthorizationRepository;
use Grr\GrrBundle\Repository\Security\UserRepository;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class MigrationUtil
{
    /**
     * @var UserPasswordEncoderInterface
     */
    public $passwordEncoder;
    /**
     * @var AreaRepository
     */
    public $areaRepository;
    /**
     * @var RoomRepository
     */
    public $roomRepository;
    /**
     * @var UserRepository
     */
    public $userRepository;
    /**
     * @var TypeEntryRepository
     */
    private $typeEntryRepository;
    /**
     * @var AuthorizationRepository
     */
    private $authorizationRepository;
    /**
     * @var EntryRepository
     */
    public $entryRepository;
    /**
     * @var ParameterBagInterface
     */
    private $parameterBag;

    public function __construct(
        UserPasswordEncoderInterface $passwordEncoder,
        AreaRepository $areaRepository,
        RoomRepository $roomRepository,
        UserRepository $userRepository,
        TypeEntryRepository $typeEntryRepository,
        EntryRepository $entryRepository,
        AuthorizationRepository $authorizationRepository,
        ParameterBagInterface $parameterBag
    ) {
        $this->passwordEncoder = $passwordEncoder;
        $this->areaRepository = $areaRepository;
        $this->roomRepository = $roomRepository;
        $this->userRepository = $userRepository;
        $this->entryTypeRepository = $typeEntryRepository;
        $this->authorizationRepository = $authorizationRepository;
        $this->entryRepository = $entryRepository;
        $this->parameterBag = $parameterBag;
    }

    public function getCacheDirectory(): string
    {
        return $this->parameterBag->get(
                'kernel.cache_dir'
            ).DIRECTORY_SEPARATOR.'download'.DIRECTORY_SEPARATOR;
    }

    public function clearCache(): void
    {
        $filesystem = new Filesystem();
        $cacheDir = $this->getCacheDirectory();
        $filesystem->remove($cacheDir);
        $filesystem->mkdir($cacheDir);
    }

    public function transformBoolean(string $value): bool
    {
        $value = strtolower($value);

        return 'y' == $value or 'a' == $value;
    }

    /**
     * @return int[]
     */
    public function transformSelecteDays(string $display_days): array
    {
        $pattern = ['#y#', '#n#'];
        $replacements = [1, 0];
        $tab = str_split(strtolower($display_days), 1);

        return array_map(
            function ($a) use ($pattern, $replacements): int {
                return (int) preg_replace($pattern, $replacements, $a);
            },
            $tab
        );
    }

    /***
     * Transforme un string : 0011001 en array
     * @param string $datas
     * @return array
     * @throws \Exception
     */

    /**
     * @return int[]
     */
    public function transformRepOpt(int $id, string $datas): array
    {
        if (7 !== strlen($datas)) {
            throw new Exception('Répétition pas 7 jours Repeat id :'.$id);
        }

        $days = [];
        $tab = str_split(strtolower($datas), 1);
        foreach ($tab as $key => $data) {
            if (1 === (int) $data) {
                $days[] = $key;
            }
        }

        return $days;
    }

    /**
     * @return int|float
     */
    public function transformToMinutes(int $time)
    {
        if ($time <= 0) {
            return 0;
        }

        return $time / CarbonInterface::MINUTES_PER_HOUR;
    }

    public function transformToArea(array $areas, int $areaId): ?Area
    {
        if ($areaId < 1) {
            return null;
        }

        foreach ($areas as $data) {
            if ($data['id'] == $areaId) {
                $nameArea = $data['area_name'];
                $area = $this->areaRepository->findOneBy(['name' => $nameArea]);
                if (null !== $area) {
                    return $area;
                }
            }
        }

        return null;
    }

    public function transformToRoom(array $rooms, int $roomId): ?Room
    {
        if ($roomId < 1) {
            return null;
        }

        if (isset($rooms[$roomId])) {
            return $rooms[$roomId];
        }

        return null;
    }

    public function transformToUser(string $username): ?User
    {
        return $this->userRepository->findOneBy(['username' => $username]);
    }

    public function transformEtat(string $etat): bool
    {
        return 'actif' === $etat;
    }

    public function transformPassword($user, $password): ?string
    {
        if ('' === $password || null === $password) {
            return null;
        }

        return $this->passwordEncoder->encodePassword($user, 123456);
    }

    /**
     * @return string[]|null[]
     */
    public function transformRole(string $statut): array
    {
        switch ($statut) {
            case 'administrateur':
                $role = SecurityRole::ROLE_GRR_ADMINISTRATOR;
                break;
            case 'utilisateur':
                $role = SecurityRole::ROLE_GRR_ACTIVE_USER;
                break;
            case 'visiteur':
                $role = null; //par defaut dipose de @see SecurityRole::ROLE_GRR
                break;
            default:
                break;
        }

        return [$role];
    }

    public function checkUser($data): ?string
    {
        if ('' == $data['email']) {
            return 'Pas de mail pour '.$data['login'];
        }
        if (null !== $this->userRepository->findOneBy(['email' => $data['email']])) {
            return $data['login'].' : Il exsite déjà un utilisateur avec cette email: '.$data['email'];
        }

        return null;
    }

    public function checkAuthorizationRoom(UserInterface $user, Room $room): ?string
    {
        if (null !== $this->authorizationRepository->findOneBy(['user' => $user, 'room' => $room])) {
            return $user->getUsername().' à déjà un rôle pour la room: '.$room->getName();
        }

        return null;
    }

    public function convertToUf8(?string $text = null): ?string
    {
        if (null === $text) {
            return null;
        }
        $charset = mb_detect_encoding($text, null, true);

        //sf5
        //b('Lorem Ipsum')->isUtf8(); // true
        //u('спасибо')->ascii();

        if ('UTF-8' == $charset) {
            $txt = utf8_decode($text);

            return $text;

            return mb_convert_encoding($text, 'UTF-8');
        }

        return $text;
    }

    /**
     * @return string|string[]
     */
    public function tabColor(int $index)
    {
        $tab_couleur[1] = '#FFCCFF';
        $tab_couleur[2] = '#99CCCC';
        $tab_couleur[3] = '#FF9999';
        $tab_couleur[4] = '#FFFF99';
        $tab_couleur[5] = '#C0E0FF';
        $tab_couleur[6] = '#FFCC99';
        $tab_couleur[7] = '#FF6666';
        $tab_couleur[8] = '#66FFFF';
        $tab_couleur[9] = '#DDFFDD';
        $tab_couleur[10] = '#CCCCCC';
        $tab_couleur[11] = '#7EFF7E';
        $tab_couleur[12] = '#8000FF';
        $tab_couleur[13] = '#FFFF00';
        $tab_couleur[14] = '#FF00DE';
        $tab_couleur[15] = '#00FF00';
        $tab_couleur[16] = '#FF8000';
        $tab_couleur[17] = '#DEDEDE';
        $tab_couleur[18] = '#C000FF';
        $tab_couleur[19] = '#FF0000';
        $tab_couleur[20] = '#FFFFFF';
        $tab_couleur[21] = '#A0A000';
        $tab_couleur[22] = '#DAA520';
        $tab_couleur[23] = '#40E0D0';
        $tab_couleur[24] = '#FA8072';
        $tab_couleur[25] = '#4169E1';
        $tab_couleur[26] = '#6A5ACD';
        $tab_couleur[27] = '#AA5050';
        $tab_couleur[28] = '#FFBB20';

        if (0 !== $index) {
            return $tab_couleur[$index];
        }

        return $tab_couleur;
    }

    public function converToDateTime(string $start_time): DateTime
    {
        $date = Carbon::createFromTimestamp($start_time);

        return $date->toDateTime();
    }

    /**
     * @param string $start_time 2019-11-14 15:03:18
     */
    public function converToDateTimeFromString(string $dateString): DateTime
    {
        $format = 'Y-m-d H:i:s';
        $date = Carbon::createFromFormat($format, $dateString);

        return $date->toDateTime();
    }

    public function convertToTypeEntry(array $resolveTypes, string $letter): ?TypeEntry
    {
        if (isset($resolveTypes[$letter])) {
            return $resolveTypes[$letter];
        }

        return null;
    }

    public function tranformToAuthorization(int $who_can_see): int
    {
        switch ($who_can_see) {
            case 0:
                $auth = SettingsRoom::CAN_ADD_EVERY_BODY;
                break;
            case 1:
                $auth = SettingsRoom::CAN_ADD_EVERY_CONNECTED;
                break;
            case 2:
                $auth = SettingsRoom::CAN_ADD_EVERY_USER_ACTIVE;
                break;
            case 3:
                $auth = SettingsRoom::CAN_ADD_EVERY_ROOM_MANAGER;
                break;
            case 4:
                $auth = SettingsRoom::CAN_ADD_EVERY_AREA_ADMINISTRATOR;
                break;
            case 5:
                $auth = SettingsRoom::CAN_ADD_EVERY_GRR_ADMINISTRATOR_SITE;
                break;
            case 6:
                $auth = SettingsRoom::CAN_ADD_EVERY_GRR_ADMINISTRATOR;
                break;
            default:
                $auth = 0;
                break;
        }

        return $auth;
    }

    public function writeFile($fileName, $content): void
    {
        $fileHandler = fopen($this->getCacheDirectory().$fileName, 'w');
        fwrite($fileHandler, $content);
        fclose($fileHandler);
    }

    /**
     * @return mixed[]
     */
    public function decompress(SymfonyStyle $io, string $content, string $type): array
    {
        $data = json_decode($content, true, 512, JSON_THROW_ON_ERROR);

        if (!is_array($data)) {
            $io->error($type.' La réponse doit être un json: '.$content);

            return [];
        }

        if (isset($data['error'])) {
            $io->error('Une erreur est survenue: '.$data['error']);

            return [];
        }

        return $data;
    }
}
