<?php

namespace Grr\Migration\Command;

use Grr\Migration\MigrationChecker;
use Grr\Migration\MigrationUtil;
use Grr\GrrBundle\Repository\EntryRepository;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Question\ConfirmationQuestion;
use Symfony\Component\Console\Style\SymfonyStyle;

class CheckCommand extends Command
{
    /**
     * @var string
     */
    protected static $defaultName = 'grr:check';
    /**
     * @var MigrationChecker
     */
    private $migrationChecker;
    /**
     * @var SymfonyStyle
     */
    private $io;
    /**
     * @var OutputInterface
     */
    private $output;
    /**
     * @var EntryRepository
     */
    private $entryRepository;
    /**
     * @var MigrationUtil
     */
    private $migrationUtil;

    public function __construct(
        MigrationChecker $migrationChecker,
        EntryRepository $entryRepository,
        MigrationUtil $migrationUtil
    ) {
        parent::__construct();
        $this->migrationChecker = $migrationChecker;
        $this->entryRepository = $entryRepository;
        $this->migrationUtil = $migrationUtil;
    }

    protected function configure(): void
    {
        $this
            ->setDescription('Add a short description for your command')
            ->addArgument('what', InputArgument::OPTIONAL, 'Que voulez vous checker')
            ->addOption('option1', null, InputOption::VALUE_NONE, 'Option description');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $this->io = new SymfonyStyle($input, $output);
        $this->output = $output;
        $helper = $this->getHelper('question');
        $what = $input->getArgument('what');

        $authorizations = $this->migrationChecker->checkAreaAndRoomAdministrator();
        if (count($authorizations) > 0) {
            $io->warning('Ces authorizations sont en double');
            foreach ($authorizations as $authorization) {
                $user = null !== $authorization['user'] ? $authorization['user']->getEmail() : '';
                $area = null !== $authorization['area'] ? $authorization['area']->getName() : '';
                $room = null !== $authorization['room'] ? $authorization['room']->getName() : '';

                $io->note($user.' ==> '.$area.' ==> '.$room." \n ");
            }
            $questionDelete = new ConfirmationQuestion("Les supprimer ? [y,N] \n", false);
            $delete = $helper->ask($input, $output, $questionDelete);
            if ($delete) {
                $this->migrationChecker->deleteDoublon();
                $io->success('Doublons supprimés');
            }
        } else {
            $io->success('Aucune authorization en double');
        }

        $this->io->section('Check entry: '.$this->migrationUtil->getCacheDirectory());
        $this->io->newLine();

        $fileHandler = file_get_contents($this->migrationUtil->getCacheDirectory().'entry.json');
        $entries = json_decode($fileHandler, true, 512, JSON_THROW_ON_ERROR);

        $fileHandler = file_get_contents($this->migrationUtil->getCacheDirectory().'resolveroom.json');
        $rooms = unserialize($fileHandler, []);

        $fileHandler = file_get_contents($this->migrationUtil->getCacheDirectory().'resolverepeat.json');
        $periodicities = unserialize($fileHandler, []);
        $count = 0;
        foreach ($entries as $data) {
            $name = $data['name'];
            $startTime = $this->migrationUtil->converToDateTime($data['start_time']);
            $endTime = $this->migrationUtil->converToDateTime($data['end_time']);
            $room = $this->migrationUtil->transformToRoom($rooms, $data['room_id']);
            $repeatId = (int) $data['repeat_id'];

            $args = ['startTime' => $startTime, 'endTime' => $endTime, 'name' => $name, 'room' => $room];

            if ($repeatId > 0) {
                $periodicity = $periodicities[$repeatId];
                $args['periodicity'] = $periodicity;
            }

            $entry = $this->entryRepository->findOneBy(
                $args
            );

            if ($entry === null) {
                ++$count;
                $io->error($data['name'].' '.$startTime->format('d-m-Y'));
            } else {
                // $io->success($entry->getName().' ==> '.$name);
            }
        }
        if (0 == $count) {
            $io->success('Toutes les entrées ont bien été importées');
        }

        return 0;
    }
}
