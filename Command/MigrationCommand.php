<?php

namespace Grr\Migration\Command;

use DateTime;
use Doctrine\Common\DataFixtures\Purger\ORMPurger;
use Doctrine\ORM\EntityManagerInterface;
use Grr\GrrBundle\Entity\Area;
use Grr\GrrBundle\Entity\Entry;
use Grr\GrrBundle\Entity\Room;
use Grr\GrrBundle\Entity\Security\User;
use Grr\GrrBundle\Periodicity\PeriodicityDaysProvider;
use Grr\Migration\MigrationFactory;
use Grr\Migration\MigrationUtil;
use Grr\Migration\RequestData;
use RuntimeException;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\ProgressBar;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Question\Question;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'grr:migration',
    description: 'Add a short description for your command',
)]
class MigrationCommand extends Command
{
    private ?SymfonyStyle $io = null;

    private ?array $rooms = null;

    private ?array $areas = null;

    private ?OutputInterface $output = null;

    /**
     * Fait la correspondance entre l'ancien id et le nouveau id des rooms.
     */
    private array $resolveRooms = [];

    /**
     * Fait la correspondance entre l'ancien id et le nouveau id des types d'entrées.
     */
    private array $resolveTypeEntries = [];

    private array $repeats;

    private array $resolveRepeats = [];

    public function __construct(
        private readonly RequestData $requestData,
        private readonly EntityManagerInterface $entityManager,
        private readonly MigrationUtil $migrationUtil,
        private readonly MigrationFactory $migrationFactory,
        private readonly PeriodicityDaysProvider $periodicityDaysProvider
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->setDescription('Migrations des données depuis un ancien Grr')
            ->addArgument('url', InputArgument::REQUIRED, "L'Url http de l'ancien Grr")
            ->addArgument('user', InputArgument::REQUIRED, "Le nom d'utilisateur d'un compte LOCALE grr administrator")
            ->addArgument('password', InputArgument::OPTIONAL, "Le mot de passe de l'utilisateur")
            ->addOption('date', null, InputOption::VALUE_NONE, 'Date à partir de laquelle les données seront ajoutées');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $this->io = new SymfonyStyle($input, $output);
        $this->output = $output;

        $helper = $this->getHelper('question');
        $user = $input->getArgument('user');
        $password = $input->getArgument('password');
        $url = $input->getArgument('url');

        if (($parts = parse_url((string) $url)) && ! isset($parts['scheme'])) {
            $this->io->error(sprintf("L'url n'est pas valide: %s", $url));

            return 1;
        }

        if (! $password) {
            $question = new Question("Le mot de passe de {$user}: \n");
            $question->setHidden(true);
            $question->setMaxAttempts(5);
            $question->setValidator(
                static function ($password) : string {
                    if (\strlen((string) $password) < 2) {
                        throw new RuntimeException('Le mot de passe ne peut être vide');
                    }
                    return $password;
                }
            );
            $password = $helper->ask($input, $output, $question);
        }

        $date = null;
        $questionDate = new Question(
            "A partir de quelle date voulez vous importer les entrées, par exemple: 2017-11-25. Laissez vide pour importer tout: \n"
        );
        $questionDate->setValidator(
            static function ($date) {
                if (null === $date) {
                    return (int) $date;
                }
                if (! $date = DateTime::createFromFormat('Y-m-d', $date)) {
                    throw new RuntimeException("La date n'a pas un format valable: ");
                }
                return $date;
            }
        );

        $date = $helper->ask($input, $output, $questionDate);

        if ($date) {
            $this->io->success('Date choisie : '.$date->format('Y-m-d'));
        }

        $purger = new ORMPurger($this->entityManager);
        //$purger->setPurgeMode(ORMPurger::PURGE_MODE_TRUNCATE);
        $purger->purge();

        $this->migrationUtil->clearCache();

        $this->requestData->connect($url, $user, $password);

        $this->io->section(
            'Téléchargement des entries et periodicities dans le dossier: '.$this->migrationUtil->getCacheDirectory()
        );
        $this->io->newLine();

        $progressBar = new ProgressBar($output, 2);
        $progressBar->start();

        $result = json_decode($this->requestData->download('repeat.php'), true, 512, JSON_THROW_ON_ERROR);

        if (isset($result['error'])) {
            $this->io->error($result['error']);

            return 1;
        }

        $progressBar->advance();
        $params = [];
        if ($date) {
            $params = [
                'date' => $date->format('Y-m-d'),
            ];
        }

        $result = json_decode($this->requestData->download('entry.php', $params), true, 512, JSON_THROW_ON_ERROR);
        if (isset($result['error'])) {
            $this->io->error($result['error']);

            return 1;
        }

        $progressBar->advance();
        $progressBar->finish();

        $this->io->newLine();

        $fileHandler = file_get_contents($this->migrationUtil->getCacheDirectory().'repeat.json');
        $this->repeats = json_decode($fileHandler, true, 512, JSON_THROW_ON_ERROR);

        $this->io->section('Importation des Areas et rooms');
        $this->handleArea();
        $this->io->newLine();
        $this->io->section('Importation des types d\'entrée');
        $this->handleTypeEntry();
        $this->io->newLine();
        $this->io->section('Importation des utilisateurs');
        $this->handleUser();
        $this->io->writeln('');
        $this->io->section('Importation des area admin');
        $this->handleAreaAdmin();
        $this->io->newLine();
        $this->io->section('Importation des rooms admin');
        $this->handleRoomAdmin();
        $this->io->newLine();
        $this->io->section('Importation des entrées');
        $this->handleEntry();
        $this->io->newLine();
        $this->io->section('Importation des paramètres');
        // $this->handlSetting();

        //je sauvegarde les resolutions pour la commande grr:check
        $this->migrationUtil->writeFile('resolverepeat.json', serialize($this->resolveRepeats));
        $this->migrationUtil->writeFile('resolveroom.json', serialize($this->resolveRooms));

        $this->io->newLine();
        $this->io->success('Importation terminée :-) .');

        return 0;
    }

    protected function handleArea(): void
    {
        $this->areas = $this->migrationUtil->decompress($this->io, $this->requestData->getAreas(), 'area');
        $this->rooms = $this->migrationUtil->decompress($this->io, $this->requestData->getRooms(), 'room');
        $count = \count($this->areas) + \count($this->rooms);
        $progressBar = new ProgressBar($this->output, $count);

        foreach ($progressBar->iterate($this->areas) as $data) {
            $area = $this->migrationFactory->createArea($data);
            $this->entityManager->persist($area);
            $this->handleRoom($area, $data['id']);
        }

        $this->entityManager->flush();
    }

    protected function handleRoom(Area $area, int $areaId): void
    {
        foreach ($this->rooms as $data) {
            if ($data['area_id'] == $areaId) {
                $room = $this->migrationFactory->createRoom($area, $data);
                $this->entityManager->persist($room);
                $this->entityManager->flush();
                $this->resolveRooms[$data['id']] = $room;
            }
        }
    }

    protected function handleTypeEntry(): void
    {
        $types = $this->migrationUtil->decompress($this->io, $this->requestData->getTypesEntry(), 'entry_type');
        $progressBar = new ProgressBar($this->output);

        foreach ($progressBar->iterate($types) as $data) {
            $type = $this->migrationFactory->createTypeEntry($data);
            $this->entityManager->persist($type);
            $this->entityManager->flush();
            $this->resolveTypeEntries[$data['type_letter']] = $type;
        }
    }

    protected function handleUser(): void
    {
        $users = $this->migrationUtil->decompress($this->io, $this->requestData->getUsers(), 'user');

        $progressBar = new ProgressBar($this->output);

        foreach ($progressBar->iterate($users) as $data) {
            if ($error = $this->migrationUtil->checkUser($data)) {
                $this->io->note('Utilisateur non ajouté: '.$error);
            } else {
                $user = $this->migrationFactory->createUser($data);
                $user->setPassword($this->migrationUtil->transformPassword($user, $data['password']));
                $user->setArea($this->migrationUtil->transformToArea($this->areas, $data['default_area']));
                $user->setRoom(
                    $this->migrationUtil->transformToRoom($this->resolveRooms, $data['default_room'])
                );
                $this->entityManager->persist($user);
                $this->entityManager->flush();
            }
        }
    }

    protected function handleEntry(): void
    {
        $fileHandler = file_get_contents($this->migrationUtil->getCacheDirectory().'entry.json');
        $entries = json_decode($fileHandler, true, 512, JSON_THROW_ON_ERROR);

        $progressBar = new ProgressBar($this->output);

        foreach ($progressBar->iterate($entries) as $data) {
            if ('PMTIC G4 MG' != $data['name']) {
                //    continue;
            }

            $entry = $this->migrationFactory->createEntry($this->resolveTypeEntries, $data);
            $room = $this->migrationUtil->transformToRoom($this->resolveRooms, $data['room_id']);

            if ($room instanceof Room) {
                $entry->setRoom($room);
                $this->entityManager->persist($entry);
                $repeatId = (int) $data['repeat_id'];

                if ($data['entry_type'] >= 1) { // il s'agit d'une reservation a laquelle est associee une periodicite
                }

                if ($repeatId > 0) {
                    $this->handlerPeriodicity($entry, $repeatId);
                }

                $this->entityManager->flush();
                //  $this->io->note(memory_get_usage());
                $room = null;
                $entry = null;
            } else {
                $this->io->error('Room non trouvé pour '.$data['name']);

                return;
            }
        }

        $this->entityManager->flush();
    }

    private function handlerPeriodicity(Entry $entry, int $id): void
    {
        if (isset($this->resolveRepeats[$id])) {
            $periodicity = $this->resolveRepeats[$id];
        } else {
            $key = array_search($id, array_column($this->repeats, 'id'), true);
            $repeat = $this->repeats[$key];
            $periodicity = $this->migrationFactory->createPeriodicity($entry, $repeat);
            $this->entityManager->persist($periodicity);
        }

        $entry->setPeriodicity($periodicity);
        //  $this->entityManager->flush();
        $this->resolveRepeats[$id] = $periodicity;
    }

    private function handleAreaAdmin(): void
    {
        $users = $this->migrationUtil->decompress($this->io, $this->requestData->getAreaAdmin(), 'area admin');

        $progressBar = new ProgressBar($this->output);

        foreach ($progressBar->iterate($users) as $data) {
            $authorization = $this->migrationFactory->createAuthorization($data);
            $user = $this->migrationUtil->transformToUser($data['login']);
            if (! $user instanceof User) {
                $this->io->error('Utilisateur non trouvé pour l\'ajouter en tant que area admin:'.$data['username']);
                continue;
            }

            $authorization->setUser($user);
            $area = $this->migrationUtil->transformToArea($this->areas, $data['id_area']);
            if (! $area instanceof Area) {
                $this->io->error('Area non trouvé pour l\'ajouter en tant que area admin: '.$data['id_area']);
                continue;
            }

            $authorization->setArea($area);
            $authorization->setRoom(null);
            $authorization->setIsAreaAdministrator(true);
            $authorization->setIsResourceAdministrator(false);
            $this->entityManager->persist($authorization);
            $this->entityManager->flush();
        }
    }

    private function handleRoomAdmin(): void
    {
        $users = $this->migrationUtil->decompress($this->io, $this->requestData->getRoomAdmin(), 'room admin');

        $progressBar = new ProgressBar($this->output);

        foreach ($progressBar->iterate($users) as $data) {
            $authorization = $this->migrationFactory->createAuthorization($data);
            $user = $this->migrationUtil->transformToUser($data['login']);

            if (! $user instanceof User) {
                $this->io->note('Utilisateur non trouvé: '.$data['login']);
                continue;
            }

            $authorization->setUser($user);
            $room = $this->migrationUtil->transformToRoom($this->resolveRooms, $data['id_room']);

            if (! $room instanceof Room) {
                $this->io->note('Room non trouvé: '.$data['id_room']);
                continue;
            }

            if ($message = $this->migrationUtil->checkAuthorizationRoom($user, $room)) {
                $this->io->note($message);
                continue;
            }

            $authorization->setArea(null);
            $authorization->setRoom($room);
            $authorization->setIsAreaAdministrator(false);
            $authorization->setIsResourceAdministrator(true);
            $this->entityManager->persist($authorization);
            $this->entityManager->flush();
        }
    }

    private function handlSetting(): void
    {
    }
}
